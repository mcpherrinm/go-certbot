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
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/challenge"

	"github.com/letsencrypt/go-certbot/internal/checkpoint"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/extenv"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/nginx/parser"
)

// Plugin implements both the Authenticator and Installer interfaces.
type Plugin struct {
	cfg     *config.Config
	domains []string

	// State for http-01 challenge.
	mu                sync.Mutex
	challengeDir      string
	challengeConfPath string // <work_dir>/le_http_01_cert_challenge.conf
	addedLocations    []*serverLocation
	addedInclude      bool   // we added the include line to nginx.conf
	addedBucketSize   bool   // we added server_names_hash_bucket_size to nginx.conf
	httpBlockFile     string // absolute path of the conf file containing the http {} block we edited
	pendingChallenges []challengeEntry
}

type challengeEntry struct {
	domain  string
	token   string
	keyAuth string
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

// Present implements challenge.Provider for HTTP-01. Appends a server
// block to le_http_01_cert_challenge.conf that serves `return 200 keyauth`
// at the challenge path, then reloads nginx. Matches Certbot's
// http_01.py:_set_up_challenges.
func (p *Plugin) Present(ctx context.Context, domain, token, keyAuth string) error {
	p.mu.Lock()
	p.pendingChallenges = append(p.pendingChallenges, challengeEntry{domain, token, keyAuth})
	all := append([]challengeEntry(nil), p.pendingChallenges...)
	confPath := p.challengeConfPath
	p.mu.Unlock()
	if confPath == "" {
		return fmt.Errorf("nginx: Present called before Prepare set up the challenge conf")
	}
	port := p.cfg.HTTP01Port
	if port == 0 {
		port = 80
	}
	if err := writeChallengeConf(confPath, port, all); err != nil {
		return err
	}
	return testAndReload(ctx, p.cfg)
}

// CleanUp removes a per-challenge server block from
// le_http_01_cert_challenge.conf and reloads nginx. Cleanup of the
// rewrite-injected vhosts happens in the plugin's overall Cleanup hook.
func (p *Plugin) CleanUp(ctx context.Context, domain, token, _ string) error {
	p.mu.Lock()
	filtered := p.pendingChallenges[:0]
	for _, c := range p.pendingChallenges {
		if c.domain == domain && c.token == token {
			continue
		}
		filtered = append(filtered, c)
	}
	p.pendingChallenges = filtered
	all := append([]challengeEntry(nil), filtered...)
	confPath := p.challengeConfPath
	p.mu.Unlock()
	if confPath == "" {
		return nil
	}
	port := p.cfg.HTTP01Port
	if port == 0 {
		port = 80
	}
	if err := writeChallengeConf(confPath, port, all); err != nil {
		return err
	}
	return testAndReload(ctx, p.cfg)
}

// writeChallengeConf overwrites the dedicated challenge config with one
// `server { ... return 200 "keyauth"; }` block per challenge. Matches the
// shape Certbot writes in http_01.py.
func writeChallengeConf(path string, port int, entries []challengeEntry) error {
	var sb strings.Builder
	sb.WriteString("# Generated by go-certbot for ACME HTTP-01. DO NOT EDIT.\n")
	for _, e := range entries {
		// `nginxQuote` escapes any `"` in keyAuth so the directive
		// stays well-formed. keyAuth is base64url-ish text plus `.`
		// so quoting is mostly precautionary.
		fmt.Fprintf(&sb, "server {\n")
		fmt.Fprintf(&sb, "    listen %d;\n", port)
		fmt.Fprintf(&sb, "    listen [::]:%d;\n", port)
		// server_name uses the achall identifier; nginx routes by
		// best-match, then falls back to default_server.
		fmt.Fprintf(&sb, "    server_name %s;\n", nginxQuoteName(e.domain))
		fmt.Fprintf(&sb, "    location = /.well-known/acme-challenge/%s {\n", e.token)
		fmt.Fprintf(&sb, "        default_type \"text/plain\";\n")
		fmt.Fprintf(&sb, "        return 200 %s;\n", nginxQuote(e.keyAuth))
		fmt.Fprintf(&sb, "    }\n")
		fmt.Fprintf(&sb, "}\n")
	}
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

// nginxQuote wraps s in double quotes, escaping any embedded `"`.
func nginxQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// nginxQuoteName quotes a server_name token when needed. IP literals are
// fine bare; FQDNs without special chars are fine bare; anything containing
// `:` gets quoted so IPv6 SANs (with literal colons via `[]`) survive.
func nginxQuoteName(s string) string {
	if strings.ContainsAny(s, ` \t"'#;`) {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
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
	// Select THE best server per requested domain rather than the union
	// of all overlapping matches. Pre-fix install touched every vhost
	// whose server_name overlapped any domain — for a config with both
	// `server_name example.com` and `server_name *.example.com`,
	// installing a cert for `example.com` ended up mutating both. Match
	// certbot _choose_vhost_single (configurator.py:475-494).
	hits := selectBestServerPerDomain(files, domains)
	if len(hits) == 0 {
		// Fall back to default_server matches (the catch-all path).
		hits = findMatchingServersAcrossFiles(files, domains)
	}
	if len(hits) == 0 {
		return fmt.Errorf("nginx: no server block matched any of %v in %s (or its includes)", domains, configPath)
	}
	// Find the chain path to enable OCSP stapling correctly later. For
	// install we accept it implicitly: the fullchain IS the chain we want
	// nginx to use for ssl_trusted_certificate.
	for _, h := range hits {
		insertSSLDirectives(h.Server, fullchainPath, privkeyPath, cfg.HTTP01Port, cfg.HTTPSPort)
		if cfg.Redirect != nil && *cfg.Redirect {
			addRedirectIfHTTPOnly(h.Server, domains)
		}
	}
	// Install Certbot's modern TLS-config snippet and include it from each
	// modified server. Brings ssl_protocols / ssl_ciphers / session settings
	// up to ssl-config.mozilla.org standards regardless of nginx version.
	if err := installOptionsSSLNginxConf(cfg.ConfigDir, files, hits); err != nil {
		return err
	}
	// If --redirect was set and we found only HTTPS-shaped servers (e.g.
	// only :443 exists), clone the matched server to a new HTTP-only
	// :80 sibling that 301s — matches Certbot's _enable_redirect.
	if cfg.Redirect != nil && *cfg.Redirect {
		ensureRedirectExists(files, hits, domains)
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
	if err := testAndReload(ctx, cfg); err != nil {
		return err
	}
	checkpoint.MarkClean()
	return nil
}

// serverIsHTTPS reports whether the server block listens on :443, has any
// listen directive with the `ssl` keyword, OR has a top-level `ssl on;`
// directive. Mirrors certbot _is_ssl_on_directive + has_ssl_on_directive
// (parser.py:582-591, configurator.py:629-630). The standalone `ssl on;`
// form was deprecated in nginx 1.15 but legacy configs still use it; pre-
// fix go-certbot misclassified those servers as HTTP and skipped them.
func serverIsHTTPS(srv *parser.Block) bool {
	for _, n := range srv.Body {
		d, ok := n.(*parser.Directive)
		if !ok {
			continue
		}
		if d.Name == "ssl" && len(d.Args) == 1 &&
			strings.EqualFold(strings.Trim(d.Args[0], `"'`), "on") {
			return true
		}
		if d.Name != "listen" || len(d.Args) == 0 {
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

// ensureRedirectExists tries to add a per-domain redirect to an existing
// HTTP vhost for each matched HTTPS-only server. Matches Certbot's
// _enable_redirect: prefers `if ($host = X) { return 301 ... }` in an
// existing :80 vhost; logs and skips if no HTTP vhost serves the domain.
func ensureRedirectExists(files []*parsedFile, hits []serverHit, domains []string) {
	for _, h := range hits {
		if !serverIsHTTPS(h.Server) {
			continue // hit is HTTP; addRedirectIfHTTPOnly already handled it
		}
		names := serverNames(h.Server)
		// Find an HTTP vhost we can amend with an if-host block.
		httpVHosts := findHTTPVHosts(files, names)
		if len(httpVHosts) == 0 {
			// Match Certbot's "no matching insecure server blocks"
			// log line (configurator.py:1265-1278). We deliberately
			// do NOT clone a whole new redirect server — for an
			// HTTPS-only setup with no HTTP listener, the user has
			// already opted out of accepting :80 traffic, and
			// adding our own would surprise.
			continue
		}
		for _, srv := range httpVHosts {
			addRedirectIfHTTPOnly(srv, domains)
		}
	}
}

// findHTTPVHosts returns all server blocks that listen on :80 and whose
// server_name matches at least one of names.
func findHTTPVHosts(files []*parsedFile, names []string) []*parser.Block {
	var out []*parser.Block
	for _, f := range files {
		for _, n := range f.AST.Nodes {
			b, ok := n.(*parser.Block)
			if !ok || b.Name != "server" {
				continue
			}
			if !hasListenPort(b, "80") || serverIsHTTPS(b) {
				continue
			}
			for _, want := range serverNames(b) {
				for _, n := range names {
					if want == n {
						out = append(out, b)
					}
				}
			}
		}
	}
	return out
}

// serverNames returns every name across all server_name directives in the
// block. Mirrors certbot-nginx's parser._get_servernames which collects
// names from EVERY server_name directive (multiple are legal in nginx).
func serverNames(b *parser.Block) []string {
	var out []string
	for _, n := range b.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == "server_name" {
			out = append(out, d.Args...)
		}
	}
	return out
}

// isDefaultServer reports whether any of the block's listen directives has
// the `default_server` flag. Used as a catch-all match when no server_name
// matches the requested SAN.
func isDefaultServer(b *parser.Block) bool {
	for _, n := range b.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "listen" {
			continue
		}
		for _, a := range d.Args {
			if a == "default_server" || a == "default" {
				return true
			}
		}
	}
	return false
}

// isDefaultServerOnPort returns true iff the block has a `listen` directive
// that BOTH names `port` (or is bare/wildcard-on-port) AND carries
// `default_server`. Mirrors certbot _get_default_vhost's port-matching
// prefilter (configurator.py:436-460): when picking a fallback target for
// HTTPS install, we want a default_server on :443 rather than one on :80.
func isDefaultServerOnPort(b *parser.Block, port string) bool {
	if port == "" {
		return isDefaultServer(b)
	}
	for _, n := range b.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "listen" || len(d.Args) == 0 {
			continue
		}
		// Port match: either the first arg names this port, or
		// there's no port at all (nginx's implicit default 80).
		_, p, parsed := splitListenAddr(strings.Trim(d.Args[0], `"'`))
		matches := false
		switch {
		case parsed && p == port:
			matches = true
		case parsed && p == "" && port == "80":
			// bare hostname listen = default port 80.
			matches = true
		}
		if !matches {
			continue
		}
		for _, a := range d.Args {
			if a == "default_server" || a == "default" {
				return true
			}
		}
	}
	return false
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
// per-OS default. Matches certbot-nginx/constants.py:5-14: BSD/macOS use
// /usr/local/etc/nginx, NetBSD uses /usr/pkg/etc/nginx.
func nginxConfigPath(cfg *config.Config) string {
	if cfg.NginxServerRoot != "" {
		return filepath.Join(cfg.NginxServerRoot, "nginx.conf")
	}
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "dragonfly":
		return "/usr/local/etc/nginx/nginx.conf"
	case "netbsd":
		return "/usr/pkg/etc/nginx/nginx.conf"
	}
	return "/etc/nginx/nginx.conf"
}

// sleepAfterReload pauses for cfg.NginxSleepSeconds (default 1) so a
// subsequent challenge-verification doesn't race the nginx worker swap.
// Matches certbot-nginx's configurable post-reload sleep (constants.py:19,
// configurator.py:1318-1323).
func sleepAfterReload(cfg *config.Config) {
	d := time.Duration(cfg.NginxSleepSeconds) * time.Second
	if d <= 0 {
		d = time.Second
	}
	time.Sleep(d)
}

// regexpCompile is a tiny wrapper over regexp.Compile so the inner loop in
// serverMatchesAny stays readable; lego/regex compile errors are uncommon
// for valid nginx configs.
func regexpCompile(s string) (interface{ MatchString(string) bool }, error) {
	return regexp.Compile(s)
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
	// If no exact / wildcard / regex match was found, fall back to any
	// vhost that's flagged `default_server` on its listen line — that's
	// the catch-all nginx routes unmatched requests to. Mirrors
	// certbot-nginx's get_vhosts default-server fallback. Prefer
	// default_servers on port 80 (the HTTP-01 challenge port) then 443
	// (HTTPS) then any, so the fallback matches the request shape that
	// would have hit the named vhost. Certbot's _get_default_vhost does
	// the same port filter (configurator.py:436-460).
	if len(out) == 0 {
		var collect func(nodes []parser.Node, port string, into *[]*parser.Block)
		collect = func(nodes []parser.Node, port string, into *[]*parser.Block) {
			for _, n := range nodes {
				b, ok := n.(*parser.Block)
				if !ok {
					continue
				}
				if b.Name == "server" && isDefaultServerOnPort(b, port) {
					*into = append(*into, b)
				}
				collect(b.Body, port, into)
			}
		}
		var port80, port443, any []*parser.Block
		collect(cfg.Nodes, "80", &port80)
		collect(cfg.Nodes, "443", &port443)
		switch {
		case len(port80) > 0:
			out = port80
		case len(port443) > 0:
			out = port443
		default:
			collect(cfg.Nodes, "", &any)
			out = any
		}
	}
	return out
}

// selectBestServerPerDomain picks ONE server block per requested domain
// using certbot/nginx's name-selection priority: exact > longest
// start-wildcard (*.example.com) > longest end-wildcard (mail.*) >
// regex; with SSL preferred over non-SSL within a tie. Mirrors
// certbot configurator.py:_choose_vhost_single + _select_best_name_match
// (configurator.py:475-494).
//
// Pre-fix Install touched every server whose server_name overlapped any
// requested domain, including less-specific wildcards the user didn't
// intend to receive the cert. Returns the union of selected vhosts (a
// single vhost can be returned multiple times if best for multiple
// domains; deduped by pointer).
func selectBestServerPerDomain(files []*parsedFile, domains []string) []serverHit {
	type candidate struct {
		hit   serverHit
		score int
	}
	type bestEntry struct {
		hit   serverHit
		score int
	}
	// First pass: collect all server blocks across files.
	type sNode struct {
		hit serverHit
	}
	var allServers []sNode
	for _, f := range files {
		var visit func(nodes []parser.Node)
		visit = func(nodes []parser.Node) {
			for _, n := range nodes {
				b, ok := n.(*parser.Block)
				if !ok {
					continue
				}
				if b.Name == "server" {
					allServers = append(allServers, sNode{hit: serverHit{File: f, Server: b}})
				}
				visit(b.Body)
			}
		}
		visit(f.AST.Nodes)
	}
	// Per-domain best, then collect unique hits.
	best := map[string]bestEntry{} // domain → best hit
	for _, dom := range domains {
		lcDom := strings.ToLower(dom)
		for _, s := range allServers {
			score := serverNameScore(s.hit.Server, lcDom)
			if score == 0 {
				continue
			}
			// SSL preference: bump score if the server already
			// listens with ssl. Tie-break only.
			if serverIsHTTPS(s.hit.Server) {
				score++
			}
			cur, ok := best[lcDom]
			if !ok || score > cur.score {
				best[lcDom] = bestEntry{hit: s.hit, score: score}
			}
		}
	}
	// Dedupe results by *parser.Block pointer.
	seen := map[*parser.Block]bool{}
	var out []serverHit
	for _, dom := range domains {
		lcDom := strings.ToLower(dom)
		entry, ok := best[lcDom]
		if !ok {
			continue
		}
		if seen[entry.hit.Server] {
			continue
		}
		seen[entry.hit.Server] = true
		out = append(out, entry.hit)
	}
	_ = candidate{} // keep unused-var quiet during incremental work
	return out
}

// serverNameScore returns 0 if no match, or a positive integer scoring
// the match's specificity per certbot's selection rules. Larger == more
// specific.
//
// Score scheme (per Certbot's certbot/_internal/plugins/nginx/parser.py
// best-match logic):
//
//	1000 + len(name)  exact match (longer FQDN ranks higher)
//	 500 + len(name)  start wildcard (*.example.com) — leading-dot variant
//	 400 + len(name)  end wildcard (mail.*)
//	 100              regex match
//	   0              no match
//
// The constants leave space for a +1 SSL-tie-break bump at the caller.
func serverNameScore(srv *parser.Block, lcDom string) int {
	best := 0
	for _, n := range srv.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "server_name" {
			continue
		}
		for _, raw := range d.Args {
			name := strings.ToLower(strings.Trim(raw, `"'`))
			score := nameMatchScore(name, lcDom)
			if score > best {
				best = score
			}
		}
	}
	return best
}

// nameMatchScore is the per-name-token scorer.
func nameMatchScore(name, lcDom string) int {
	if name == "" {
		return 0
	}
	if name == lcDom {
		return 1000 + len(name)
	}
	if strings.HasPrefix(name, "*.") {
		suffix := name[1:]
		if strings.HasSuffix(lcDom, suffix) {
			return 500 + len(name)
		}
	}
	if strings.HasPrefix(name, ".") {
		bare := name[1:]
		if lcDom == bare || strings.HasSuffix(lcDom, name) {
			return 500 + len(name)
		}
	}
	if strings.HasSuffix(name, ".*") {
		prefix := name[:len(name)-1] // "mail."
		if strings.HasPrefix(lcDom, prefix) {
			return 400 + len(name)
		}
	}
	if strings.HasPrefix(name, "~") {
		pat := strings.TrimPrefix(name, "~")
		if strings.HasPrefix(pat, "*") {
			pat = "(?i)" + strings.TrimPrefix(pat, "*")
		}
		if re, err := regexpCompile(pat); err == nil {
			if re.MatchString(lcDom) {
				return 100
			}
		}
	}
	return 0
}

// serverMatchesAny returns true if the server block's server_name covers any
// requested domain. Mirrors certbot-nginx/parser.py:_exact_match /
// _wildcard_match for these forms:
//
//   - exact name:        example.com
//   - trailing wildcard: example.* (matches example.com, example.net, ...)
//   - leading wildcard:  *.example.com (matches anything.example.com)
//   - leading dot:       .example.com (matches both example.com and any.example.com)
//   - regex name:        ~^foo\.example\.com$
//   - catch-all:         _ (treated as matching iff the server is the default)
func serverMatchesAny(srv *parser.Block, want map[string]bool) bool {
	// Build a lowercase view of the wanted names — DNS names are
	// case-insensitive (RFC 4343) and Certbot's _exact_match /
	// _wildcard_match lowercases both sides (parser.py:525-565). Without
	// this, a vhost configured as `server_name Example.COM` wouldn't
	// match a request for `example.com`.
	lcWant := make(map[string]bool, len(want))
	for w := range want {
		lcWant[strings.ToLower(w)] = true
	}
	for _, n := range srv.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "server_name" {
			continue
		}
		for _, raw := range d.Args {
			name := strings.ToLower(strings.Trim(raw, `"'`))
			if name == "" {
				continue
			}
			// Exact name.
			if lcWant[name] {
				return true
			}
			// Regex (`~^...$` or `~*^...$` for case-insensitive).
			// Compile lazily; fall through on parse error.
			if strings.HasPrefix(name, "~") {
				pat := strings.TrimPrefix(name, "~")
				caseInsensitive := false
				if strings.HasPrefix(pat, "*") {
					pat = strings.TrimPrefix(pat, "*")
					caseInsensitive = true
				}
				if caseInsensitive {
					pat = "(?i)" + pat
				}
				re, err := regexpCompile(pat)
				if err == nil {
					for w := range lcWant {
						if re.MatchString(w) {
							return true
						}
					}
				}
				continue
			}
			// Leading wildcard or leading-dot: matches any subdomain
			// (and, for leading-dot, also the bare name).
			if strings.HasPrefix(name, "*.") {
				suffix := name[1:] // ".example.com"
				for w := range lcWant {
					if strings.HasSuffix(w, suffix) {
						return true
					}
				}
				continue
			}
			if strings.HasPrefix(name, ".") {
				bare := name[1:]
				for w := range lcWant {
					if w == bare || strings.HasSuffix(w, name) {
						return true
					}
				}
				continue
			}
			// Trailing wildcard: `mail.*` matches mail.example.com, mail.example.org, etc.
			if strings.HasSuffix(name, ".*") {
				prefix := name[:len(name)-1] // "mail."
				for w := range lcWant {
					if strings.HasPrefix(w, prefix) {
						return true
					}
				}
				continue
			}
			// `_` (or `__`) is the catch-all default_server marker; not
			// a literal name. Only matches if the surrounding server has
			// `default_server` on a listen line, but we conservatively
			// don't treat it as a match here.
		}
	}
	return false
}

// insertSSLDirectives appends ssl_certificate, ssl_certificate_key, and
// `listen <port> ssl` to a server block (replacing existing values if
// present). Indentation is borrowed from the first inner directive so the
// edit blends in with the surrounding file.
func insertSSLDirectives(srv *parser.Block, fullchain, privkey string, httpPort, httpsPort int) {
	indent := childIndent(srv)
	if httpsPort <= 0 {
		httpsPort = 443
	}
	if httpPort <= 0 {
		httpPort = 80
	}
	setOrAppend(srv, indent, "ssl_certificate", fullchain)
	setOrAppend(srv, indent, "ssl_certificate_key", privkey)
	addListenSSL(srv, indent, httpPort, httpsPort)
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

// addListenSSL ensures the server block has the right `listen ... ssl`
// directive(s). Mirrors certbot _make_server_ssl (configurator.py:709-784):
//
//  1. If the block already has any `listen` matching the HTTPS port (with or
//     without `ssl`), make sure each carries the `ssl` flag and stop —
//     respecting whatever host/port tuples the user already configured.
//  2. Otherwise, for every existing `listen` matching the HTTP01 port (e.g.
//     `listen 127.0.0.1:80;`), emit a parallel SSL listen preserving the
//     host (`listen 127.0.0.1:443 ssl;`).
//  3. If neither matched, fall back to bare defaults: `[::]:443 ssl` for
//     IPv6, `443 ssl` for IPv4, derived from whatever existing listens hint
//     at family preference (or both if no hint).
func addListenSSL(b *parser.Block, indent string, httpPort, httpsPort int) {
	httpStr := fmt.Sprintf("%d", httpPort)
	httpsStr := fmt.Sprintf("%d", httpsPort)
	// If the block has NO listen directives at all, nginx defaults to
	// port 80. After we add ssl listens that implicit default goes away
	// and the vhost loses its HTTP listener. Add an explicit `listen
	// 80;` (or HTTP01Port) FIRST to preserve the original behavior.
	// Mirrors certbot _make_server_ssl (configurator.py:735-737).
	hasListen := false
	for _, n := range b.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == "listen" {
			hasListen = true
			break
		}
	}
	if !hasListen {
		b.Body = append(b.Body, &parser.Directive{
			Whitespace: "\n" + indent,
			Name:       "listen",
			Args:       []string{httpStr},
			Semicolon:  true,
		})
	}
	// Pass 1: existing HTTPS-port listens — promote to ssl if needed and
	// trust whatever the user configured.
	foundHTTPS := false
	for _, n := range b.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "listen" || len(d.Args) == 0 {
			continue
		}
		first := strings.Trim(d.Args[0], `"'`)
		_, p, ok := splitListenAddr(first)
		if !ok || p != httpsStr {
			continue
		}
		foundHTTPS = true
		if !containsArg(d.Args, "ssl") {
			d.Args = append(d.Args, "ssl")
		}
	}
	if foundHTTPS {
		return
	}
	// Pass 2: derive SSL listens from HTTP-port listens, preserving host.
	var derived []string
	hasV4, hasV6 := false, false
	for _, n := range b.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "listen" || len(d.Args) == 0 {
			continue
		}
		first := strings.Trim(d.Args[0], `"'`)
		host, p, ok := splitListenAddr(first)
		if !ok || p != httpStr {
			continue
		}
		isV6 := strings.HasPrefix(host, "[")
		if isV6 {
			hasV6 = true
		} else {
			hasV4 = true
		}
		if host != "" {
			derived = append(derived, host+":"+httpsStr)
		} else {
			derived = append(derived, httpsStr)
		}
	}
	defaultFallback := len(derived) == 0
	if defaultFallback {
		// No HTTP listen either — fall back to the same default set
		// nginx itself would have used. Match Certbot's behavior of
		// adding both IPv4 and IPv6 default listens when no hint.
		if !hasV4 && !hasV6 {
			hasV4, hasV6 = true, true
		}
		if hasV6 {
			derived = append(derived, "[::]:"+httpsStr)
		}
		if hasV4 {
			derived = append(derived, httpsStr)
		}
	}
	for _, addr := range derived {
		args := []string{addr, "ssl"}
		// Certbot _make_server_ssl appends `ipv6only=on` to new IPv6
		// listens it emits (configurator.py:751-764). Without this,
		// the kernel's net.ipv6.bindv6only default decides whether
		// the IPv6 socket also accepts IPv4 connections, which can
		// produce unpredictable behavior across distros. Only safe
		// for the default-fallback path here — for listens derived
		// from existing HTTP IPv6 listens, the original likely
		// already has ipv6only=on (or deliberately doesn't), and
		// nginx errors if multiple vhosts set ipv6only=on for the
		// same socket. Adding it only on the default fallback
		// matches the "this is a freshly-issued vhost, no other
		// vhost will conflict" case Certbot's test exercises.
		if defaultFallback && strings.HasPrefix(addr, "[") {
			args = append(args, "ipv6only=on")
		}
		b.Body = append(b.Body, &parser.Directive{
			Whitespace: "\n" + indent,
			Name:       "listen",
			Args:       args,
			Semicolon:  true,
		})
	}
}

// splitListenAddr parses an nginx listen value into host/port.
// Accepts:
//
//	"80"               → host="", port="80"
//	"127.0.0.1:80"     → host="127.0.0.1", port="80"
//	"[::]:80"          → host="[::]", port="80"
//	"myhost"           → host="myhost", port=""  (bare hostname: nginx
//	                     defaults to port 80 — callers treat empty port
//	                     as DEFAULT_LISTEN_PORT, mirroring certbot
//	                     obj.Addr.fromstring's regex check `^\d+$` for
//	                     all-digits first part)
//
// Returns ok=false for unix:/... socket forms so callers skip those
// vhosts (we can't SSL-upgrade a unix listener).
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
	// No `:` — either all-digits (`80`) or a bare hostname.
	// Certbot's obj.Addr.fromstring checks `re.match(r'^\d+$', tup[0])`:
	// all-digits → port; otherwise → host (with empty port).
	if isAllDigits(v) {
		return "", v, true
	}
	return v, "", true
}

// isAllDigits returns true for strings consisting solely of ASCII digits
// (and at least one). Mirrors `re.match(r'^\d+$', s)` for ASCII input.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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
// to https — but does so per-domain via an `if ($host = ...)` guard so other
// vhosts/CDNs sharing the listener aren't accidentally redirected. Matches
// Certbot's _enable_redirect (configurator.py:898-953 + 1265-1278):
//
//	if ($host = example.com) {
//	    return 301 https://$host$request_uri;
//	} # managed by Certbot
//
// One `if` is added per ServerName/ServerAlias on the matched server.
// Idempotent: if an `if ($host = X)` block already exists for a name, we
// don't add another.
func addRedirectIfHTTPOnly(srv *parser.Block, domains []string) {
	if !hasListenPort(srv, "80") || serverIsHTTPS(srv) {
		return
	}
	// Names to redirect: each ServerName from the matched server, narrowed
	// to those the user actually asked for.
	wanted := map[string]bool{}
	for _, d := range domains {
		wanted[d] = true
	}
	covered := map[string]bool{}
	for _, name := range serverNames(srv) {
		if wanted[name] {
			covered[name] = true
		}
	}
	for name := range covered {
		if hasIfHostRedirect(srv, name) {
			continue
		}
		appendIfHostRedirect(srv, name)
	}
}

// hasListenPort reports whether srv has at least one listen line on `port`.
func hasListenPort(srv *parser.Block, port string) bool {
	for _, n := range srv.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "listen" || len(d.Args) == 0 {
			continue
		}
		if _, p, _ := splitListenAddr(strings.Trim(d.Args[0], `"'`)); p == port {
			return true
		}
	}
	return false
}

// hasIfHostRedirect returns true if srv already contains an `if ($host = X) {
// return 301 https://... }` block for name.
func hasIfHostRedirect(srv *parser.Block, name string) bool {
	for _, n := range srv.Body {
		blk, ok := n.(*parser.Block)
		if !ok || blk.Name != "if" {
			continue
		}
		// Args look like ($host, =, name) after parser splitting.
		if len(blk.Args) >= 3 && blk.Args[0] == "($host" && blk.Args[1] == "=" {
			arg := strings.Trim(blk.Args[2], `)"'`)
			if arg == name {
				return true
			}
		}
	}
	return false
}

// appendIfHostRedirect prepends an `if ($host = name) { return 301 ... }`
// block to the top of the server block. Certbot uses `insert_at_top=True`
// (configurator.py:856-862) so the redirect fires before any other
// rewrites the user has below it.
func appendIfHostRedirect(srv *parser.Block, name string) {
	indent := childIndent(srv)
	inner := &parser.Block{
		Whitespace: "\n" + indent,
		Name:       "if",
		Args:       []string{"($host", "=", name + ")"},
		Body: []parser.Node{
			&parser.Directive{
				Whitespace: "\n" + indent + "    ",
				Name:       "return",
				Args:       []string{"301", "https://$host$request_uri"},
				Semicolon:  true,
			},
		},
		BeforeClose: "\n" + indent,
	}
	srv.Body = append([]parser.Node{inner}, srv.Body...)
}

// testAndReload runs `nginx -t` then `nginx -s reload`. If reload fails
// (typically because nginx isn't running yet), fall back to `nginx -c <conf>`
// to start it — matches Certbot's restart() behavior.
func testAndReload(ctx context.Context, cfg *config.Config) error {
	ctl := cfg.NginxCtl
	if ctl == "" {
		ctl = "nginx"
	}
	testCmd := exec.CommandContext(ctx, ctl, "-t")
	testCmd.Env = extenv.Env()
	if out, err := testCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx: `%s -t` failed: %w\n%s", ctl, err, string(out))
	}
	reload := exec.CommandContext(ctx, ctl, "-s", "reload")
	reload.Env = extenv.Env()
	if out, err := reload.CombinedOutput(); err == nil {
		_ = out
		// Sleep 1s post-reload so subsequent challenge verification
		// doesn't race the worker swap. Matches Certbot's
		// nginx_restart sleep (configurator.py:1318-1323, addresses
		// certbot#7422).
		sleepAfterReload(cfg)
		return nil
	}
	// Reload failed — likely nginx isn't running. Try to start it,
	// pointing at the discovered nginx.conf so the right config tree gets
	// loaded.
	cmd := exec.CommandContext(ctx, ctl, "-c", nginxConfigPath(cfg))
	cmd.Env = extenv.Env()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx: reload failed and `%s` (start) also failed: %w\n%s", ctl, err, string(out))
	}
	time.Sleep(time.Second)
	return nil
}

// injectChallengeLocations follows include directives, applies Certbot's
// HTTP-01 layout:
//
//   - Adds a `rewrite ^(/.well-known/acme-challenge/.*) $1 break;` at the
//     top of every matched server so the ACME path bypasses other rewrites
//     and lands at our challenge handler.
//   - Adds `include <work_dir>/le_http_01_cert_challenge.conf;` to the
//     main nginx.conf inside the http {} block.
//   - Writes a fallback default_server into the challenge conf so
//     identifiers with no matching vhost still resolve.
//   - Bumps server_names_hash_bucket_size (Certbot also does this so
//     long FQDN-based server_name parsing doesn't trip the default).
//
// State is tracked so Cleanup undoes every edit. A checkpoint is taken
// so the rollback verb can also recover.
func (p *Plugin) injectChallengeLocations(configPath, webroot string) error {
	files, err := loadAll(configPath)
	if err != nil {
		return err
	}
	hits := findMatchingServersAcrossFiles(files, p.domains)
	if len(hits) == 0 {
		// No match — write a default_server fallback so identifiers
		// like IP-address SANs (RFC 8738) without a server_name can
		// still be validated. We append the rewrite-host marker to
		// the main file so cleanup knows what to undo.
		hits = []serverHit{{File: files[0], Server: nil}}
	}
	for _, h := range hits {
		if h.Server != nil {
			prependChallengeRewrite(h.Server)
			p.mu.Lock()
			p.addedLocations = append(p.addedLocations, &serverLocation{confPath: h.File.Path, server: h.Server})
			p.mu.Unlock()
		}
	}
	// Inject the include + server_names_hash_bucket_size at the top of
	// the http {} block — searching across ALL parsed files (not just
	// the root nginx.conf). Debian/Ubuntu layouts often place `http {}`
	// in /etc/nginx/conf.d/*.conf rather than the root; pre-fix this
	// silently no-op'd and http-01 challenges then failed because the
	// include never landed. Mirrors certbot e32f4fc5f.
	challengeConfPath := filepath.Join(p.cfg.ConfigDir, "le_http_01_cert_challenge.conf")
	if owner := findHTTPBlockFile(files); owner != nil {
		p.addedInclude = ensureHTTPInclude(owner.AST, challengeConfPath)
		p.addedBucketSize = ensureBucketSize(owner.AST)
		p.httpBlockFile = owner.Path
	}
	p.challengeConfPath = challengeConfPath

	// Seed the challenge conf with an empty default_server so reload
	// doesn't fail when no Present calls have happened yet. Subsequent
	// Present calls append additional server { return 200 ...; } blocks.
	port := p.cfg.HTTP01Port
	if port == 0 {
		port = 80
	}
	if err := writeInitialChallengeConf(challengeConfPath, port); err != nil {
		return err
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
	// Strip the rewrite from every server we touched.
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
		stripChallengeRewrites(root.Nodes)
		// Only strip include/bucket here if this is ALSO the http {} file.
		// Otherwise we strip them below from the dedicated http file.
		if sl.confPath == p.httpBlockFile {
			if p.addedInclude {
				stripHTTPInclude(root, p.challengeConfPath)
			}
			if p.addedBucketSize {
				stripBucketSize(root)
			}
		}
		if err := os.WriteFile(sl.confPath, []byte(root.String()), 0o644); err != nil {
			return err
		}
	}
	// If the http {} block lives in a file that wasn't touched as a
	// challenge-rewrite target (common Debian/Ubuntu layout where
	// http {} is in nginx.conf but vhosts live in sites-enabled/*.conf),
	// strip include/bucket directly from that file now.
	if p.httpBlockFile != "" && !seen[p.httpBlockFile] && (p.addedInclude || p.addedBucketSize) {
		srcBytes, err := os.ReadFile(p.httpBlockFile)
		if err != nil {
			return err
		}
		root, err := parser.Parse(string(srcBytes))
		if err != nil {
			return err
		}
		if p.addedInclude {
			stripHTTPInclude(root, p.challengeConfPath)
		}
		if p.addedBucketSize {
			stripBucketSize(root)
		}
		if err := os.WriteFile(p.httpBlockFile, []byte(root.String()), 0o644); err != nil {
			return err
		}
	}
	// Delete the challenge conf — best effort.
	if p.challengeConfPath != "" {
		_ = os.Remove(p.challengeConfPath)
		p.challengeConfPath = ""
	}
	return nil
}

// prependChallengeRewrite prepends a `rewrite ^(/.well-known/acme-challenge/
// .*) $1 break;` directive to a server block. The `# managed by Certbot`
// comment lets cleanup find and strip the line. Idempotent.
func prependChallengeRewrite(srv *parser.Block) {
	indent := childIndent(srv)
	// Check for existing marker.
	for _, n := range srv.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == "rewrite" &&
			len(d.Args) >= 1 && strings.Contains(d.Args[0], "well-known/acme-challenge") {
			return
		}
	}
	d := &parser.Directive{
		Whitespace:      "\n" + indent,
		Name:            "rewrite",
		Args:            []string{"^(/.well-known/acme-challenge/.*)", "$1", "break"},
		Semicolon:       true,
		TrailingComment: " # managed by Certbot",
	}
	srv.Body = append([]parser.Node{d}, srv.Body...)
}

// stripChallengeRewrites removes any `rewrite ... # managed by Certbot`
// directive from every server block in nodes.
func stripChallengeRewrites(nodes []parser.Node) {
	for _, n := range nodes {
		b, ok := n.(*parser.Block)
		if !ok {
			continue
		}
		if b.Name == "server" {
			filtered := b.Body[:0]
			for _, child := range b.Body {
				if d, ok := child.(*parser.Directive); ok && d.Name == "rewrite" &&
					len(d.Args) >= 1 && strings.Contains(d.Args[0], "well-known/acme-challenge") {
					continue
				}
				filtered = append(filtered, child)
			}
			b.Body = filtered
		}
		stripChallengeRewrites(b.Body)
	}
}

// ensureHTTPInclude adds `include <path>;` inside the first `http {}` block
// of root if not already present. Returns true if it added one (so cleanup
// knows to remove it).
func ensureHTTPInclude(root *parser.Config, path string) bool {
	httpBlk := findHTTPBlock(root.Nodes)
	if httpBlk == nil {
		return false
	}
	for _, n := range httpBlk.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == "include" &&
			len(d.Args) == 1 && strings.Trim(d.Args[0], `"'`) == path {
			return false
		}
	}
	indent := childIndent(httpBlk)
	d := &parser.Directive{
		Whitespace:      "\n" + indent,
		Name:            "include",
		Args:            []string{path},
		Semicolon:       true,
		TrailingComment: " # managed by Certbot",
	}
	httpBlk.Body = append([]parser.Node{d}, httpBlk.Body...)
	return true
}

func stripHTTPInclude(root *parser.Config, path string) {
	httpBlk := findHTTPBlock(root.Nodes)
	if httpBlk == nil {
		return
	}
	filtered := httpBlk.Body[:0]
	for _, n := range httpBlk.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == "include" &&
			len(d.Args) == 1 && strings.Trim(d.Args[0], `"'`) == path {
			continue
		}
		filtered = append(filtered, n)
	}
	httpBlk.Body = filtered
}

// ensureBucketSize adds `server_names_hash_bucket_size 128;` in http {}.
// Returns true if it added the directive. Matches Certbot's http_01.py:75-78.
func ensureBucketSize(root *parser.Config) bool {
	httpBlk := findHTTPBlock(root.Nodes)
	if httpBlk == nil {
		return false
	}
	for _, n := range httpBlk.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == "server_names_hash_bucket_size" {
			return false
		}
	}
	indent := childIndent(httpBlk)
	d := &parser.Directive{
		Whitespace:      "\n" + indent,
		Name:            "server_names_hash_bucket_size",
		Args:            []string{"128"},
		Semicolon:       true,
		TrailingComment: " # managed by Certbot",
	}
	httpBlk.Body = append([]parser.Node{d}, httpBlk.Body...)
	return true
}

func stripBucketSize(root *parser.Config) {
	httpBlk := findHTTPBlock(root.Nodes)
	if httpBlk == nil {
		return
	}
	filtered := httpBlk.Body[:0]
	for _, n := range httpBlk.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == "server_names_hash_bucket_size" {
			// Only strip ours (with the marker comment).
			if strings.Contains(d.TrailingComment, "managed by Certbot") {
				continue
			}
		}
		filtered = append(filtered, n)
	}
	httpBlk.Body = filtered
}

// findHTTPBlock walks the AST and returns the first `http {}` block, or nil.
func findHTTPBlock(nodes []parser.Node) *parser.Block {
	for _, n := range nodes {
		b, ok := n.(*parser.Block)
		if !ok {
			continue
		}
		if b.Name == "http" {
			return b
		}
		if inner := findHTTPBlock(b.Body); inner != nil {
			return inner
		}
	}
	return nil
}

// findHTTPBlockFile returns the parsed file whose AST contains an `http {}`
// block. Certbot's nginx parser walks the entire include tree to find the
// http block — Debian/Ubuntu's /etc/nginx layout places `http {}` in the
// root nginx.conf, but other distros (or operator-customized layouts) put
// it in a separately-included conf.d/ file. Returns nil if no http block
// exists anywhere in the include tree.
func findHTTPBlockFile(files []*parsedFile) *parsedFile {
	for _, f := range files {
		if findHTTPBlock(f.AST.Nodes) != nil {
			return f
		}
	}
	return nil
}

// writeInitialChallengeConf writes a no-op fallback server block so nginx
// reload succeeds before any Present calls. Each subsequent Present
// appendChallengeBlock-s a server {} into this file.
func writeInitialChallengeConf(path string, port int) error {
	header := "# Generated by go-certbot for ACME HTTP-01. DO NOT EDIT.\n"
	return os.WriteFile(path, []byte(header), 0o644)
}

// _ keeps the errors import alive for future use; not currently referenced.
var _ = errors.New
