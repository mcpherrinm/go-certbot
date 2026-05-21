// Package nginx implements an nginx authenticator + installer. Phase 5
// targets the common case: a system with an existing nginx configuration
// where each managed domain has a matching `server` block. The plugin
//
//   - finds server blocks by matching server_name directives
//   - inserts ssl_certificate / ssl_certificate_key / listen 443 ssl
//   - optionally drops in HTTP→HTTPS redirect (--redirect)
//   - tests the new config with `nginx -t` and reloads with `nginx -s reload`
//
// For the http-01 authenticator path, the plugin inserts a temporary
// `location /.well-known/acme-challenge/` block, writes the challenge file
// into a scratch dir served from that location, reloads nginx, and cleans
// up after the challenge.
//
// What's *not* yet implemented (versus Certbot's full plugin) is documented
// explicitly in CHANGES.md so users know what to expect:
//
//   - `include` resolution — we operate on the file the user points us at;
//     a future version will follow `include` directives.
//   - Auto-creation of a new server block when one doesn't exist.
//   - HSTS, OCSP stapling, must-staple insertion (Phase 7).
//   - The `enhance` verb (Phase 7).
package nginx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/http01"

	"github.com/letsencrypt/go-certbot/internal/checkpoint"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/nginx/parser"
)

// Plugin implements both the Authenticator and Installer interfaces.
type Plugin struct {
	cfg     *config.Config
	domains []string

	// State for http-01 challenge.
	mu             sync.Mutex
	challengeDir   string
	addedLocations []*serverLocation
}

// serverLocation tracks where we inserted a temporary location block so we
// can remove it later.
type serverLocation struct {
	confPath string
	server   *parser.Block
}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string        { return "nginx" }
func (p *Plugin) Description() string { return "Nginx Web Server plugin." }

// Prepare implements plugins.Authenticator. The plugin runs an http-01 flow:
// drop a temporary location block in each domain's server, write the file
// under a scratch webroot, reload nginx, hand the lego provider back.
func (p *Plugin) Prepare(ctx context.Context, cfg *config.Config, domains []string) (plugins.ChallengeKind, challenge.Provider, error) {
	p.cfg = cfg
	p.domains = domains

	configPath := nginxConfigPath(cfg)
	if _, err := os.Stat(configPath); err != nil {
		return 0, nil, fmt.Errorf("nginx: %s: %w", configPath, err)
	}

	dir, err := os.MkdirTemp(cfg.WorkDir, "nginx-http-01-")
	if err != nil {
		return 0, nil, fmt.Errorf("nginx: mkdir scratch: %w", err)
	}
	p.challengeDir = dir
	if err := os.MkdirAll(filepath.Join(dir, ".well-known", "acme-challenge"), 0o755); err != nil {
		return 0, nil, err
	}

	// Inject a temporary location block into every matched server.
	if err := p.injectChallengeLocations(configPath, dir); err != nil {
		return 0, nil, err
	}

	if err := testAndReload(ctx, cfg); err != nil {
		return 0, nil, fmt.Errorf("nginx: post-injection reload failed: %w", err)
	}
	return plugins.HTTP01, p, nil
}

// Cleanup removes the injected location blocks and the scratch dir.
func (p *Plugin) Cleanup(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.addedLocations) == 0 && p.challengeDir == "" {
		return nil
	}
	if err := p.removeChallengeLocations(); err != nil {
		fmt.Fprintf(os.Stderr, "nginx: cleanup remove: %v\n", err)
	}
	if p.challengeDir != "" {
		_ = os.RemoveAll(p.challengeDir)
		p.challengeDir = ""
	}
	if err := testAndReload(ctx, p.cfg); err != nil {
		fmt.Fprintf(os.Stderr, "nginx: cleanup reload: %v\n", err)
	}
	return nil
}

// Present implements challenge.Provider for HTTP-01. The temporary location
// block we injected proxies requests under /.well-known/acme-challenge/ to
// the challenge file under our scratch dir.
func (p *Plugin) Present(_ context.Context, _, token, keyAuth string) error {
	path := filepath.Join(p.challengeDir, http01.ChallengePath(token))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("nginx: mkdir challenge path: %w", err)
	}
	return os.WriteFile(path, []byte(keyAuth), 0o644)
}

// CleanUp removes the per-challenge file.
func (p *Plugin) CleanUp(_ context.Context, _, token, _ string) error {
	return os.Remove(filepath.Join(p.challengeDir, http01.ChallengePath(token)))
}

// Install implements plugins.Installer: inserts the issued cert into every
// matching server block. fullchainPath / privkeyPath point at the live/
// symlinks the storage layer just wrote. Follows `include` directives so the
// standard Debian/Ubuntu layout (vhosts under sites-enabled/*.conf) works.
func (p *Plugin) Install(ctx context.Context, cfg *config.Config, domains []string, fullchainPath, privkeyPath string) error {
	configPath := nginxConfigPath(cfg)
	files, err := loadAll(configPath)
	if err != nil {
		return err
	}
	hits := findMatchingServersAcrossFiles(files, domains)
	if len(hits) == 0 {
		return fmt.Errorf("nginx: no server block matched any of %v in %s (or its includes)", domains, configPath)
	}
	// Find the chain path to enable OCSP stapling correctly later. For
	// install we accept it implicitly: the fullchain IS the chain we want
	// nginx to use for ssl_trusted_certificate.
	for _, h := range hits {
		insertSSLDirectives(h.Server, fullchainPath, privkeyPath, cfg.HTTPSPort)
		if cfg.Redirect != nil && *cfg.Redirect {
			addRedirectIfHTTPOnly(h.Server)
		}
	}
	// If --redirect was set and we found only HTTPS-shaped servers (e.g.
	// only :443 exists), clone the matched server to a new HTTP-only
	// :80 sibling that 301s — matches Certbot's _enable_redirect.
	if cfg.Redirect != nil && *cfg.Redirect {
		ensureRedirectExists(files, hits)
	}
	// Checkpoint every file before writing so rollback can undo this.
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	if _, err := checkpoint.Save(cfg.WorkDir, "nginx-install", paths); err != nil {
		return fmt.Errorf("nginx: checkpoint: %w", err)
	}
	if err := writeAllFiles(files); err != nil {
		return err
	}
	return testAndReload(ctx, cfg)
}

// serverIsHTTPS reports whether the server block listens on :443 or has any
// listen directive with the `ssl` keyword.
func serverIsHTTPS(srv *parser.Block) bool {
	for _, n := range srv.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "listen" || len(d.Args) == 0 {
			continue
		}
		if containsArg(d.Args, "ssl") {
			return true
		}
		_, port, _ := splitListenAddr(d.Args[0])
		if port == "443" {
			return true
		}
	}
	return false
}

// ensureRedirectExists adds a sibling :80 server block that 301s to https
// when a matched server has no HTTP-only counterpart. Called only after
// install when --redirect is true.
func ensureRedirectExists(files []*parsedFile, hits []serverHit) {
	// For each unique ServerName in our hits, check whether any file has
	// an HTTP-only :80 server with that name. If not, append a redirect
	// server to the file the hit lives in.
	for _, h := range hits {
		if !serverIsHTTPS(h.Server) {
			continue // hit is HTTP; addRedirectIfHTTPOnly already handled it
		}
		names := serverNames(h.Server)
		if hasHTTPRedirectAlready(files, names) {
			continue
		}
		h.File.AST.Nodes = append(h.File.AST.Nodes, newRedirectServer(names))
	}
}

func serverNames(b *parser.Block) []string {
	for _, n := range b.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == "server_name" {
			return append([]string(nil), d.Args...)
		}
	}
	return nil
}

func hasHTTPRedirectAlready(files []*parsedFile, names []string) bool {
	for _, f := range files {
		for _, n := range f.AST.Nodes {
			b, ok := n.(*parser.Block)
			if !ok || b.Name != "server" {
				continue
			}
			hasHTTP := false
			for _, c := range b.Body {
				d, ok := c.(*parser.Directive)
				if !ok || d.Name != "listen" {
					continue
				}
				if !containsArg(d.Args, "ssl") {
					_, port, _ := splitListenAddr(d.Args[0])
					if port == "80" {
						hasHTTP = true
					}
				}
			}
			if !hasHTTP {
				continue
			}
			for _, want := range serverNames(b) {
				for _, n := range names {
					if want == n {
						return true
					}
				}
			}
		}
	}
	return false
}

func newRedirectServer(names []string) *parser.Block {
	return &parser.Block{
		Whitespace: "\n",
		Name:       "server",
		Body: []parser.Node{
			&parser.Directive{Whitespace: "\n    ", Name: "listen", Args: []string{"80"}, Semicolon: true},
			&parser.Directive{Whitespace: "\n    ", Name: "server_name", Args: names, Semicolon: true},
			&parser.Directive{Whitespace: "\n    ", Name: "return", Args: []string{"301", "https://$host$request_uri"}, Semicolon: true},
		},
		BeforeClose: "\n",
	}
}

// nginxConfigPath returns the file the user pointed us at. Honors
// --nginx-server-root / cfg.NginxServerRoot, otherwise picks the
// per-OS default.
func nginxConfigPath(cfg *config.Config) string {
	if cfg.NginxConfig != "" {
		return cfg.NginxConfig
	}
	if cfg.NginxServerRoot != "" {
		return filepath.Join(cfg.NginxServerRoot, "nginx.conf")
	}
	return "/etc/nginx/nginx.conf"
}

// findMatchingServers walks the AST and returns every `server` block whose
// server_name covers any of `domains`.
func findMatchingServers(cfg *parser.Config, domains []string) []*parser.Block {
	want := map[string]bool{}
	for _, d := range domains {
		want[d] = true
	}
	var out []*parser.Block
	var visit func(nodes []parser.Node)
	visit = func(nodes []parser.Node) {
		for _, n := range nodes {
			b, ok := n.(*parser.Block)
			if !ok {
				continue
			}
			if b.Name == "server" && serverMatchesAny(b, want) {
				out = append(out, b)
			}
			visit(b.Body)
		}
	}
	visit(cfg.Nodes)
	return out
}

// serverMatchesAny returns true if the server block's server_name covers any
// requested domain. Supports plain names and basic suffix wildcards like
// `*.example.com`.
func serverMatchesAny(srv *parser.Block, want map[string]bool) bool {
	for _, n := range srv.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "server_name" {
			continue
		}
		for _, raw := range d.Args {
			name := strings.Trim(raw, `"'`)
			if want[name] {
				return true
			}
			if strings.HasPrefix(name, "*.") {
				suffix := name[1:] // ".example.com"
				for w := range want {
					if strings.HasSuffix(w, suffix) {
						return true
					}
				}
			}
		}
	}
	return false
}

// insertSSLDirectives appends ssl_certificate, ssl_certificate_key, and
// `listen <port> ssl` to a server block (replacing existing values if
// present). Indentation is borrowed from the first inner directive so the
// edit blends in with the surrounding file.
func insertSSLDirectives(srv *parser.Block, fullchain, privkey string, httpsPort int) {
	indent := childIndent(srv)
	if httpsPort <= 0 {
		httpsPort = 443
	}
	setOrAppend(srv, indent, "ssl_certificate", fullchain)
	setOrAppend(srv, indent, "ssl_certificate_key", privkey)
	addListenSSL(srv, indent, httpsPort)
}

// childIndent returns the leading whitespace of the first directive child of
// a block, to use as the indent of newly-inserted siblings.
func childIndent(b *parser.Block) string {
	for _, n := range b.Body {
		switch nn := n.(type) {
		case *parser.Directive:
			return leadingIndent(nn.Whitespace)
		case *parser.Block:
			return leadingIndent(nn.Whitespace)
		case *parser.Comment:
			return leadingIndent(nn.Whitespace)
		}
	}
	return "    "
}

// leadingIndent extracts the indentation from a whitespace blob: the part
// after the last newline.
func leadingIndent(ws string) string {
	idx := strings.LastIndex(ws, "\n")
	if idx < 0 {
		return ws
	}
	return ws[idx+1:]
}

// setOrAppend either replaces an existing directive's Args or appends a new
// one with the given name + single arg.
func setOrAppend(b *parser.Block, indent, name, arg string) {
	for _, n := range b.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == name {
			d.Args = []string{arg}
			return
		}
	}
	b.Body = append(b.Body, &parser.Directive{
		Whitespace: "\n" + indent,
		Name:       name,
		Args:       []string{arg},
		Semicolon:  true,
	})
}

// addListenSSL ensures the server block has a `listen <port> ssl` directive.
// If a plain `listen` is already there on the same port, we add the `ssl`
// keyword; otherwise we append a new directive.
func addListenSSL(b *parser.Block, indent string, port int) {
	portStr := fmt.Sprintf("%d", port)
	for _, n := range b.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "listen" {
			continue
		}
		if len(d.Args) == 0 {
			continue
		}
		first := strings.Trim(d.Args[0], `"'`)
		host, p, ok := splitListenAddr(first)
		_ = host
		if !ok || p != portStr {
			continue
		}
		if !containsArg(d.Args, "ssl") {
			d.Args = append(d.Args, "ssl")
		}
		return
	}
	b.Body = append(b.Body, &parser.Directive{
		Whitespace: "\n" + indent,
		Name:       "listen",
		Args:       []string{portStr, "ssl"},
		Semicolon:  true,
	})
}

// splitListenAddr parses an nginx listen value into host/port.
// Accepts plain "80", "127.0.0.1:80", "[::]:80". Returns ok=false for
// unix:/... socket forms so callers skip those vhosts (we can't SSL-upgrade
// a unix listener).
func splitListenAddr(v string) (host, port string, ok bool) {
	if strings.HasPrefix(v, "unix:") {
		return "", "", false
	}
	if strings.HasPrefix(v, "[") {
		i := strings.Index(v, "]:")
		if i < 0 {
			return "", "", false
		}
		return v[:i+1], v[i+2:], true
	}
	if i := strings.LastIndex(v, ":"); i >= 0 {
		return v[:i], v[i+1:], true
	}
	return "", v, true
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if strings.EqualFold(strings.Trim(a, `"'`), want) {
			return true
		}
	}
	return false
}

// addRedirectIfHTTPOnly turns a plain-HTTP server into one that issues a 301
// to https. Only fires for servers that listen on :80 *and* don't already
// have a `return 301` line for https. Matches what Certbot's auto-redirect
// does in its simplest form; complex setups (multiple listen ports, named
// upstreams) are out of scope for Phase 5 — see CHANGES.md.
func addRedirectIfHTTPOnly(srv *parser.Block) {
	hasHTTP, hasHTTPS := false, false
	for _, n := range srv.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "listen" {
			continue
		}
		if len(d.Args) == 0 {
			continue
		}
		_, port, _ := splitListenAddr(strings.Trim(d.Args[0], `"'`))
		switch port {
		case "80":
			hasHTTP = true
		case "443":
			hasHTTPS = true
		}
		if containsArg(d.Args, "ssl") {
			hasHTTPS = true
		}
	}
	if !hasHTTP || hasHTTPS {
		return
	}
	for _, n := range srv.Body {
		d, ok := n.(*parser.Directive)
		if !ok {
			continue
		}
		if d.Name == "return" && len(d.Args) >= 2 && d.Args[0] == "301" &&
			strings.HasPrefix(strings.Trim(d.Args[1], `"'`), "https://") {
			return
		}
	}
	srv.Body = append(srv.Body, &parser.Directive{
		Whitespace: "\n" + childIndent(srv),
		Name:       "return",
		Args:       []string{"301", "https://$host$request_uri"},
		Semicolon:  true,
	})
}

// testAndReload runs `nginx -t` then `nginx -s reload`. If reload fails
// (typically because nginx isn't running yet), fall back to `nginx -c <conf>`
// to start it — matches Certbot's restart() behavior.
func testAndReload(ctx context.Context, cfg *config.Config) error {
	ctl := cfg.NginxCtl
	if ctl == "" {
		ctl = "nginx"
	}
	if out, err := exec.CommandContext(ctx, ctl, "-t").CombinedOutput(); err != nil {
		return fmt.Errorf("nginx: `%s -t` failed: %w\n%s", ctl, err, string(out))
	}
	if out, err := exec.CommandContext(ctx, ctl, "-s", "reload").CombinedOutput(); err == nil {
		_ = out
		return nil
	}
	// Reload failed — likely nginx isn't running. Try to start it.
	cmd := exec.CommandContext(ctx, ctl)
	if cfg.NginxConfig != "" {
		cmd = exec.CommandContext(ctx, ctl, "-c", cfg.NginxConfig)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx: reload failed and `%s` (start) also failed: %w\n%s", ctl, err, string(out))
	}
	return nil
}

// injectChallengeLocations follows include directives, inserts a temporary
// `location /.well-known/acme-challenge/` block into every server matching
// any requested domain across all files, and writes them back. State is
// tracked so Cleanup can undo each file. A checkpoint is taken so the
// rollback verb can also recover.
func (p *Plugin) injectChallengeLocations(configPath, webroot string) error {
	files, err := loadAll(configPath)
	if err != nil {
		return err
	}
	hits := findMatchingServersAcrossFiles(files, p.domains)
	if len(hits) == 0 {
		return fmt.Errorf("nginx: no server block in %s (or its includes) matches any of %v", configPath, p.domains)
	}
	for _, h := range hits {
		injectChallengeLocation(h.Server, webroot)
		p.mu.Lock()
		p.addedLocations = append(p.addedLocations, &serverLocation{confPath: h.File.Path, server: h.Server})
		p.mu.Unlock()
	}
	// Checkpoint before mutation so rollback recovers if reload fails.
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	if _, err := checkpoint.Save(p.cfg.WorkDir, "nginx-challenge", paths); err != nil {
		return fmt.Errorf("nginx: checkpoint: %w", err)
	}
	return writeAllFiles(files)
}

func (p *Plugin) removeChallengeLocations() error {
	// Strip the marker location across every file we touched.
	seen := map[string]bool{}
	for _, sl := range p.addedLocations {
		if seen[sl.confPath] {
			continue
		}
		seen[sl.confPath] = true
		srcBytes, err := os.ReadFile(sl.confPath)
		if err != nil {
			return err
		}
		root, err := parser.Parse(string(srcBytes))
		if err != nil {
			return err
		}
		stripChallengeLocations(root.Nodes)
		if err := os.WriteFile(sl.confPath, []byte(root.String()), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// injectChallengeLocation appends a sentinel location block to the server.
func injectChallengeLocation(srv *parser.Block, webroot string) {
	indent := childIndent(srv)
	loc := &parser.Block{
		Whitespace: "\n" + indent,
		Name:       "location",
		Args:       []string{"/.well-known/acme-challenge/"},
		Body: []parser.Node{
			&parser.Directive{Whitespace: "\n" + indent + "    ", Name: "root", Args: []string{webroot}, Semicolon: true},
			&parser.Directive{Whitespace: "\n" + indent + "    ", Name: "default_type", Args: []string{`"text/plain"`}, Semicolon: true},
			&parser.Comment{Whitespace: "\n" + indent + "    ", Value: "# go-certbot acme-challenge (auto-cleaned)"},
		},
		BeforeClose: "\n" + indent,
	}
	srv.Body = append(srv.Body, loc)
}

// stripChallengeLocations removes any location block we inserted, identified
// by the marker comment.
func stripChallengeLocations(nodes []parser.Node) {
	for _, n := range nodes {
		b, ok := n.(*parser.Block)
		if !ok {
			continue
		}
		if b.Name == "server" {
			filtered := b.Body[:0]
			for _, child := range b.Body {
				lb, isBlock := child.(*parser.Block)
				if isBlock && lb.Name == "location" && hasChallengeMarker(lb) {
					continue
				}
				filtered = append(filtered, child)
			}
			b.Body = filtered
		}
		stripChallengeLocations(b.Body)
	}
}

func hasChallengeMarker(b *parser.Block) bool {
	for _, n := range b.Body {
		if c, ok := n.(*parser.Comment); ok &&
			strings.Contains(c.Value, "go-certbot acme-challenge") {
			return true
		}
	}
	return false
}

// _ keeps the errors import alive for future use; not currently referenced.
var _ = errors.New
