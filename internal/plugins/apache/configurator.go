// Package apache implements an apache (httpd) authenticator + installer.
// Phase 6 targets the common case: a system whose vhosts live in a single
// file (or you pass --apache-config /path/to/file). Per-vhost behavior:
//
//   - find <VirtualHost> blocks whose ServerName / ServerAlias covers each
//     requested domain
//   - if a matching :443 vhost exists, write SSLCertificateFile /
//     SSLCertificateKeyFile / SSLEngine on into it
//   - else clone the matching :80 vhost as a new :443 vhost and append it
//   - apachectl -t / apachectl graceful (or systemctl reload, configurable
//     via --apache-ctl)
//
// For http-01 authentication, the plugin inserts a temporary
// `Alias /.well-known/acme-challenge/ <webroot>/.well-known/acme-challenge/`
// directive into each matched vhost, reloads, and cleans up after the
// challenge.
//
// Out of scope (documented in CHANGES.md):
//   - Include / IncludeOptional resolution
//   - Auto-creating a vhost when none matches
//   - HSTS / OCSP stapling / Must-Staple insertion + the `enhance` verb
package apache

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
	"github.com/letsencrypt/go-certbot/internal/plugins/apache/parser"
)

type Plugin struct {
	cfg     *config.Config
	domains []string

	mu             sync.Mutex
	challengeDir   string
	injectedConfig string // path we wrote to during Present
}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string        { return "apache" }
func (p *Plugin) Description() string { return "Apache Web Server plugin." }

func (p *Plugin) Prepare(ctx context.Context, cfg *config.Config, domains []string) (plugins.ChallengeKind, challenge.Provider, error) {
	p.cfg = cfg
	p.domains = domains

	configPath := apacheConfigPath(cfg)
	if _, err := os.Stat(configPath); err != nil {
		return 0, nil, fmt.Errorf("apache: %s: %w", configPath, err)
	}
	dir, err := os.MkdirTemp(cfg.WorkDir, "apache-http-01-")
	if err != nil {
		return 0, nil, fmt.Errorf("apache: mkdir scratch: %w", err)
	}
	p.challengeDir = dir
	if err := os.MkdirAll(filepath.Join(dir, ".well-known", "acme-challenge"), 0o755); err != nil {
		return 0, nil, err
	}

	if err := p.injectChallengeAliases(configPath, dir); err != nil {
		return 0, nil, err
	}
	if err := testAndReload(ctx, cfg); err != nil {
		return 0, nil, fmt.Errorf("apache: post-injection reload: %w", err)
	}
	return plugins.HTTP01, p, nil
}

func (p *Plugin) Cleanup(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.injectedConfig != "" {
		if err := p.removeChallengeAliases(p.injectedConfig); err != nil {
			fmt.Fprintf(os.Stderr, "apache: cleanup remove: %v\n", err)
		}
	}
	if p.challengeDir != "" {
		_ = os.RemoveAll(p.challengeDir)
		p.challengeDir = ""
	}
	if err := testAndReload(ctx, p.cfg); err != nil {
		fmt.Fprintf(os.Stderr, "apache: cleanup reload: %v\n", err)
	}
	return nil
}

func (p *Plugin) Present(_ context.Context, _, token, keyAuth string) error {
	path := filepath.Join(p.challengeDir, http01.ChallengePath(token))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("apache: mkdir challenge path: %w", err)
	}
	return os.WriteFile(path, []byte(keyAuth), 0o644)
}

func (p *Plugin) CleanUp(_ context.Context, _, token, _ string) error {
	return os.Remove(filepath.Join(p.challengeDir, http01.ChallengePath(token)))
}

// Install implements plugins.Installer. Walks Include / IncludeOptional so
// the default Debian/Ubuntu layout (vhosts in sites-enabled/*.conf) works.
// If a matching :443 vhost exists it's edited in place; otherwise the
// matching :80 vhost is cloned as a new :443 vhost written to a sibling
// <basename>-le-ssl.conf wrapped in <IfModule mod_ssl.c> so the install is
// safe when mod_ssl is disabled.
func (p *Plugin) Install(ctx context.Context, cfg *config.Config, domains []string, fullchainPath, privkeyPath string) error {
	configPath := apacheConfigPath(cfg)
	files, err := loadAll(configPath)
	if err != nil {
		return err
	}
	hits443 := findMatchingVHostsAcrossFiles(files, domains, "443")
	hits80 := findMatchingVHostsAcrossFiles(files, domains, "80")
	if len(hits443) == 0 && len(hits80) == 0 {
		return fmt.Errorf("apache: no <VirtualHost> matched any of %v in %s (or its includes)", domains, configPath)
	}

	// Install the Mozilla-intermediate SSL snippet once. The Include
	// directive is added to every SSL vhost so the recommended
	// SSLProtocol/SSLCipherSuite/SSLHonorCipherOrder triple takes effect.
	sslSnippet, err := installOptionsSSLApacheConf(cfg.ConfigDir)
	if err != nil {
		return err
	}

	// On Apache < 2.4.8 the chain must be in a separate
	// SSLCertificateChainFile; on 2.4.8+ the chain lives inside fullchain
	// and SSLCertificateChainFile is deprecated. Compute the chain path
	// from the fullchain path (Certbot's layout ships chain.pem alongside).
	chainPath := ""
	if !apacheVersion(ctx, cfg).ge(2, 4, 8) {
		// Replace fullchain.pem -> chain.pem in the live symlink path.
		chainPath = deriveChainPath(fullchainPath)
	}

	// Track new -le-ssl.conf files so we write them too. Each `dest`
	// records both source path (for clone-from semantics) and final
	// destination (vhost_root + sites-enabled symlink on Debian).
	type extraFile struct{ path, body string }
	var extras []extraFile

	if len(hits443) > 0 {
		for _, h := range hits443 {
			applySSLDirectives(h.Sec, fullchainPath, privkeyPath, chainPath, sslSnippet)
		}
	} else {
		// Clone each :80 vhost as a :443 vhost in a separate -le-ssl.conf
		// file. The clone lands in cfg.VHostRoot (= <basename>-le-ssl.conf
		// inside the per-OS vhost_root) rather than next to the source —
		// matches Certbot's _get_ssl_vhost_path. Skip if the destination
		// already exists with our managed-by marker; in that case we
		// update in place.
		for _, h := range hits80 {
			leSSLPath := sslVHostDestination(cfg, h.File.Path)
			if existing, err := os.ReadFile(leSSLPath); err == nil && strings.Contains(string(existing), managedByMarker) {
				cfg2, perr := parser.Parse(string(existing))
				if perr == nil {
					updateExistingSSLVHost(cfg2, fullchainPath, privkeyPath, chainPath, sslSnippet)
					extras = append(extras, extraFile{path: leSSLPath, body: cfg2.String()})
					continue
				}
			}
			clone := cloneAsSSLVHost(h.Sec, fullchainPath, privkeyPath, chainPath, sslSnippet)
			body := managedByMarker + "\n" + wrapInIfModuleSSL(clone)
			extras = append(extras, extraFile{path: leSSLPath, body: body})
		}
	}
	// Add HTTP-→HTTPS redirect to matching :80 vhosts if --redirect is set.
	if cfg.Redirect != nil && *cfg.Redirect {
		for _, h := range hits80 {
			addRewriteRedirect(h.Sec)
		}
	}

	// Checkpoint every file we're about to write so rollback can revert.
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	for _, e := range extras {
		paths = append(paths, e.path)
	}
	if _, err := checkpoint.Save(cfg.WorkDir, "apache-install", paths); err != nil {
		return fmt.Errorf("apache: checkpoint: %w", err)
	}
	if err := writeAllFiles(files); err != nil {
		return err
	}
	for _, e := range extras {
		if err := os.WriteFile(e.path, []byte(e.body), 0o644); err != nil {
			return fmt.Errorf("apache: write %s: %w", e.path, err)
		}
		// Debian-style layouts: also symlink the new vhost into
		// sites-enabled/ so Apache actually loads it. Matches
		// override_debian.enable_site (a2ensite). For non-Debian
		// layouts vhost_root == conf.d (already auto-included via
		// IncludeOptional in httpd.conf), so the symlink isn't
		// needed.
		if err := ensureDebianSiteEnabled(cfg, e.path); err != nil {
			return err
		}
	}
	// Make sure mod_ssl / mod_headers / mod_rewrite / mod_socache_shmcb
	// are loaded. socache_shmcb is required by SSLStaplingCache (added
	// during enhance --staple-ocsp); enabling it eagerly keeps configtest
	// green even if the user enhances later.
	if err := ensureModules(ctx, cfg, []string{"ssl", "headers", "rewrite", "socache_shmcb"}); err != nil {
		return err
	}
	if err := testAndReload(ctx, cfg); err != nil {
		return err
	}
	// Reload succeeded — mark the checkpoint clean so a later SIGINT
	// doesn't roll back our (already-deployed) change.
	checkpoint.MarkClean()
	return nil
}

// wrapInIfModuleSSL returns the section serialized inside an <IfModule
// mod_ssl.c> wrapper.
func wrapInIfModuleSSL(sec *parser.Section) string {
	wrapped := &parser.Config{
		Nodes: []parser.Node{
			&parser.Section{
				Name:        "IfModule",
				Args:        []string{"mod_ssl.c"},
				OpenNewline: "\n",
				Body:        []parser.Node{sec},
				CloseNewline: "\n",
			},
		},
	}
	return wrapped.String()
}

// addRewriteRedirect inserts a `RewriteEngine on` + `RewriteCond` + `RewriteRule`
// trio into a matching :80 vhost, redirecting HTTP requests to HTTPS. Matches
// Certbot's _set_https_redirection. Idempotent: skips if a redirect already
// exists.
func addRewriteRedirect(sec *parser.Section) {
	for _, n := range sec.Body {
		if d, ok := n.(*parser.Directive); ok && strings.EqualFold(d.Name, "RewriteRule") {
			for _, a := range d.Args {
				if strings.HasPrefix(strings.TrimSpace(a), `https://`) {
					return
				}
			}
		}
	}
	indent := childIndent(sec)
	sec.Body = append(sec.Body,
		&parser.Directive{Indent: indent, Name: "RewriteEngine", Args: []string{"on"}, Newline: "\n"},
		&parser.Directive{Indent: indent, Name: "RewriteRule", Args: []string{"^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[END,NE,R=permanent]"}, Newline: "\n"},
	)
}

// apacheConfigPath returns where to read/write, honoring explicit overrides
// then falling back to the per-OS default (Debian vs RHEL vs Alpine vs Gentoo
// — see detectOSOptions).
func apacheConfigPath(cfg *config.Config) string {
	if cfg.ApacheConfig != "" {
		return cfg.ApacheConfig
	}
	opts := detectOSOptions()
	if cfg.ApacheServerRoot != "" {
		return filepath.Join(cfg.ApacheServerRoot, filepath.Base(opts.ConfigPath))
	}
	return opts.ConfigPath
}

// deriveChainPath returns the chain.pem path next to fullchain.pem (the
// Certbot live/<name>/ layout). Returns "" if fullchainPath doesn't end
// in "fullchain.pem" so we don't emit a bogus SSLCertificateChainFile.
func deriveChainPath(fullchainPath string) string {
	base := filepath.Base(fullchainPath)
	if base != "fullchain.pem" {
		return ""
	}
	return filepath.Join(filepath.Dir(fullchainPath), "chain.pem")
}

// sslVHostDestination returns the path where the SSL clone of srcPath
// should land. Matches Certbot's _get_ssl_vhost_path: place the clone
// under the per-OS vhost_root with a `-le-ssl.conf` suffix on the
// basename. Falls back to placing the clone next to the source when no
// vhost_root is configured (matches the original Phase 6 behavior).
func sslVHostDestination(cfg *config.Config, srcPath string) string {
	dir := vhostRoot(cfg)
	base := filepath.Base(srcPath)
	// Strip the existing extension (Debian: foo.conf; RHEL: foo.conf)
	// and append `-le-ssl.conf`.
	name := strings.TrimSuffix(base, filepath.Ext(base)) + "-le-ssl.conf"
	if dir == "" {
		return filepath.Join(filepath.Dir(srcPath), name)
	}
	return filepath.Join(dir, name)
}

// ensureDebianSiteEnabled is the in-process analogue of `a2ensite`: for
// Debian layouts where vhostPath sits under sites-available/, symlink it
// into sites-enabled/<basename>. No-op for other layouts and for paths
// already enabled. Returns nil silently if the symlink target's parent
// directory doesn't exist (i.e. not Debian).
func ensureDebianSiteEnabled(cfg *config.Config, vhostPath string) error {
	dir := filepath.Dir(vhostPath)
	if filepath.Base(dir) != "sites-available" {
		return nil
	}
	parent := filepath.Dir(dir)
	sitesEnabled := filepath.Join(parent, "sites-enabled")
	if _, err := os.Stat(sitesEnabled); err != nil {
		return nil
	}
	link := filepath.Join(sitesEnabled, filepath.Base(vhostPath))
	if _, err := os.Lstat(link); err == nil {
		return nil // already enabled
	}
	// Use a relative symlink (../sites-available/foo.conf) so the link
	// survives the parent dir being moved.
	rel := filepath.Join("..", "sites-available", filepath.Base(vhostPath))
	if err := os.Symlink(rel, link); err != nil {
		return fmt.Errorf("apache: enable site %s: %w", link, err)
	}
	return nil
}

// vhostRoot returns the directory in which to write -le-ssl.conf clones.
// Honors --apache-server-root + per-OS VHostRoot; falls back to "" so the
// caller writes next to the source file.
func vhostRoot(cfg *config.Config) string {
	if cfg.ApacheServerRoot != "" {
		// User explicitly pointed at a server root; assume the standard
		// Debian layout under it. RHEL users with non-standard layouts
		// can pass --apache-config directly.
		return filepath.Join(cfg.ApacheServerRoot, "sites-available")
	}
	return detectOSOptions().VHostRoot
}

// apacheCtl returns the control binary, honoring --apache-ctl then falling
// back to the per-OS default ("apachectl" / "httpd" / "apache2ctl").
func apacheCtl(cfg *config.Config) string {
	if cfg.ApacheCtl != "" {
		return cfg.ApacheCtl
	}
	return detectOSOptions().Ctl
}

// apacheVersion runs `<ctl> -v` and parses the "Server version: Apache/2.4.X"
// line. Returns (2, 4, 0) when parsing fails so we conservatively assume the
// older codepath (split chain) and won't write directives unsupported on
// older Apache.
//
// Cached so multiple Install/Enhance calls in the same process don't fork
// apachectl repeatedly.
type apacheVer struct{ Major, Minor, Patch int }

var (
	apacheVerCache    apacheVer
	apacheVerCacheOK  bool
)

func apacheVersion(ctx context.Context, cfg *config.Config) apacheVer {
	if apacheVerCacheOK {
		return apacheVerCache
	}
	ctl := apacheCtl(cfg)
	out, err := exec.CommandContext(ctx, ctl, "-v").CombinedOutput()
	if err != nil {
		// Try the non-wrapper binary as a fallback (e.g. Fedora's
		// apachectl can't take -v in some configs; httpd directly works).
		out, err = exec.CommandContext(ctx, "httpd", "-v").CombinedOutput()
		if err != nil {
			apacheVerCacheOK = true
			apacheVerCache = apacheVer{2, 4, 0}
			return apacheVerCache
		}
	}
	v := parseApacheVersion(string(out))
	apacheVerCacheOK = true
	apacheVerCache = v
	return v
}

// parseApacheVersion extracts (major, minor, patch) from `apachectl -v` text:
//
//	Server version: Apache/2.4.58 (Unix)
//	Server built:   ...
//
// Returns the all-zeros version on parse failure.
func parseApacheVersion(s string) apacheVer {
	for _, line := range strings.Split(s, "\n") {
		_, after, ok := strings.Cut(line, "Apache/")
		if !ok {
			continue
		}
		parts := strings.SplitN(strings.Fields(after)[0], ".", 3)
		if len(parts) < 2 {
			continue
		}
		var v apacheVer
		fmt.Sscanf(parts[0], "%d", &v.Major)
		fmt.Sscanf(parts[1], "%d", &v.Minor)
		if len(parts) == 3 {
			fmt.Sscanf(parts[2], "%d", &v.Patch)
		}
		return v
	}
	return apacheVer{}
}

// ge returns true if v >= (M, m, p).
func (v apacheVer) ge(M, m, p int) bool {
	if v.Major != M {
		return v.Major > M
	}
	if v.Minor != m {
		return v.Minor > m
	}
	return v.Patch >= p
}

// findMatchingVHosts walks the AST and returns every <VirtualHost> whose
// ServerName or ServerAlias matches any of `domains` AND whose listen port
// (the bit after ':' in the section's first arg) is `wantPort`. If wantPort
// is empty, match regardless of port.
func findMatchingVHosts(cfg *parser.Config, domains []string, wantPort string) []*parser.Section {
	want := map[string]bool{}
	for _, d := range domains {
		want[d] = true
	}
	var out []*parser.Section
	var visit func(nodes []parser.Node)
	visit = func(nodes []parser.Node) {
		for _, n := range nodes {
			sec, ok := n.(*parser.Section)
			if !ok {
				continue
			}
			if strings.EqualFold(sec.Name, "VirtualHost") &&
				vhostOnPort(sec, wantPort) &&
				vhostMatchesAny(sec, want) {
				out = append(out, sec)
			}
			visit(sec.Body)
		}
	}
	visit(cfg.Nodes)
	return out
}

// vhostOnPort returns true if the vhost's first arg ends in :wantPort, or if
// wantPort is "". `*:443`, `_default_:443`, `1.2.3.4:443` all match "443".
func vhostOnPort(sec *parser.Section, wantPort string) bool {
	if wantPort == "" {
		return true
	}
	if len(sec.Args) == 0 {
		return false
	}
	v := strings.Trim(sec.Args[0], `"`)
	i := strings.LastIndex(v, ":")
	if i < 0 {
		return false
	}
	return v[i+1:] == wantPort
}

// vhostMatchesAny: does ServerName or ServerAlias cover any requested domain?
func vhostMatchesAny(sec *parser.Section, want map[string]bool) bool {
	for _, n := range sec.Body {
		d, ok := n.(*parser.Directive)
		if !ok {
			continue
		}
		switch strings.ToLower(d.Name) {
		case "servername", "serveralias":
			for _, raw := range d.Args {
				name := strings.Trim(raw, `"`)
				if want[name] {
					return true
				}
				if strings.HasPrefix(name, "*.") {
					suffix := name[1:]
					for w := range want {
						if strings.HasSuffix(w, suffix) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// applySSLDirectives writes (or updates) SSLEngine on, SSLCertificateFile,
// SSLCertificateKeyFile, and `Include options-ssl-apache.conf` inside an
// existing :443 vhost. The Include pulls in the Mozilla-intermediate
// SSLProtocol / SSLCipherSuite / SSLHonorCipherOrder triple from
// installOptionsSSLApacheConf so the vhost doesn't fall back to Apache
// defaults (= weak ciphers, no protocol pinning).
//
// On Apache < 2.4.8 (when chainPath != ""), SSLCertificateChainFile is also
// emitted because Apache 2.4.7 and earlier don't accept the chain as part of
// SSLCertificateFile. Callers pass chainPath = "" for newer Apache.
func applySSLDirectives(sec *parser.Section, fullchain, privkey, chainPath, sslSnippet string) {
	indent := childIndent(sec)
	setOrAppend(sec, indent, "SSLEngine", "on")
	setOrAppend(sec, indent, "SSLCertificateFile", fullchain)
	setOrAppend(sec, indent, "SSLCertificateKeyFile", privkey)
	if chainPath != "" {
		setOrAppend(sec, indent, "SSLCertificateChainFile", chainPath)
	} else {
		// On newer Apache the chain is inside fullchain; remove any
		// stale SSLCertificateChainFile we (or an older Certbot run)
		// may have left behind so the vhost doesn't reference a wrong
		// file after an upgrade.
		removeDirective(sec, "SSLCertificateChainFile")
	}
	if sslSnippet != "" {
		setOrAppend(sec, indent, "Include", sslSnippet)
	}
}

// removeDirective drops every `name` directive from a section's direct
// children. Matches Certbot's `_clean_vhost` behavior for stale chain refs.
func removeDirective(sec *parser.Section, name string) {
	out := sec.Body[:0]
	for _, n := range sec.Body {
		if d, ok := n.(*parser.Directive); ok && strings.EqualFold(d.Name, name) {
			continue
		}
		out = append(out, n)
	}
	sec.Body = out
}

// managedByMarker matches Certbot's exact marker text
// (certbot-apache/_internal/constants.py:83 — "DO NOT REMOVE - Managed by
// Certbot") so a mixed-tool deployment (Certbot then go-certbot, or
// vice-versa) detects the existing cloned vhost and updates in place
// instead of duplicating it.
const managedByMarker = "# DO NOT REMOVE - Managed by Certbot"

// updateExistingSSLVHost walks an already-cloned -le-ssl.conf parse tree and
// refreshes its SSLCertificateFile / SSLCertificateKeyFile to the current
// fullchain/privkey paths. Used on re-run to keep the path in sync without
// duplicating the vhost.
func updateExistingSSLVHost(cfg *parser.Config, fullchain, privkey, chainPath, sslSnippet string) {
	var visit func(nodes []parser.Node)
	visit = func(nodes []parser.Node) {
		for _, n := range nodes {
			if sec, ok := n.(*parser.Section); ok {
				if strings.EqualFold(sec.Name, "VirtualHost") {
					applySSLDirectives(sec, fullchain, privkey, chainPath, sslSnippet)
				}
				visit(sec.Body)
			}
		}
	}
	visit(cfg.Nodes)
}

// cloneAsSSLVHost duplicates a :80 vhost as a new :443 vhost with SSL
// directives appended. The clone keeps ServerName/ServerAlias/DocumentRoot/
// other arbitrary directives so the new vhost behaves the same.
func cloneAsSSLVHost(src *parser.Section, fullchain, privkey, chainPath, sslSnippet string) *parser.Section {
	dst := &parser.Section{
		OpenIndent:   src.OpenIndent,
		Name:         "VirtualHost",
		Args:         rewriteArgsTo443(src.Args),
		OpenNewline:  src.OpenNewline,
		CloseIndent:  src.CloseIndent,
		CloseNewline: src.CloseNewline,
	}
	for _, child := range src.Body {
		// Deep-copy directives only; skip anything we don't recognize as a
		// directive (e.g. inner sections) — preserving them verbatim is safer
		// than the alternative for the common vhost shape.
		dst.Body = append(dst.Body, copyNode(child))
	}
	indent := childIndent(dst)
	dst.Body = append(dst.Body, &parser.Directive{
		Indent: indent, Name: "SSLEngine", Args: []string{"on"}, Newline: "\n",
	})
	dst.Body = append(dst.Body, &parser.Directive{
		Indent: indent, Name: "SSLCertificateFile", Args: []string{fullchain}, Newline: "\n",
	})
	dst.Body = append(dst.Body, &parser.Directive{
		Indent: indent, Name: "SSLCertificateKeyFile", Args: []string{privkey}, Newline: "\n",
	})
	if chainPath != "" {
		dst.Body = append(dst.Body, &parser.Directive{
			Indent: indent, Name: "SSLCertificateChainFile", Args: []string{chainPath}, Newline: "\n",
		})
	}
	if sslSnippet != "" {
		dst.Body = append(dst.Body, &parser.Directive{
			Indent: indent, Name: "Include", Args: []string{sslSnippet}, Newline: "\n",
		})
	}
	return dst
}

// rewriteArgsTo443 turns each `:80` listener arg into `:443`. Handles `*`
// (no port), `_default_:80`, `1.2.3.4:80`, `[::1]:80` (IPv6 bracketed), and
// quoted variants. Args without a port (like `unix:/...` or bare `*`) are
// passed through.
func rewriteArgsTo443(in []string) []string {
	out := make([]string, len(in))
	for i, a := range in {
		out[i] = rewritePortIn(a, "80", "443")
	}
	return out
}

func rewritePortIn(v, oldPort, newPort string) string {
	quoted := false
	if strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		v = strings.Trim(v, `"`)
		quoted = true
	}
	rewrite := func(in string) string {
		// Find the trailing :<port> sequence; for bracketed IPv6 it's after `]:`.
		// idx points at the character right after the colon — so in[:idx]
		// includes the colon and we splice newPort in place of oldPort.
		idx := -1
		if strings.HasSuffix(in, "]:"+oldPort) {
			idx = len(in) - len(oldPort)
		} else if !strings.HasPrefix(in, "[") {
			if j := strings.LastIndex(in, ":"); j >= 0 && in[j+1:] == oldPort {
				idx = j + 1
			}
		}
		if idx < 0 {
			return in
		}
		return in[:idx] + newPort
	}
	v = rewrite(v)
	if quoted {
		v = `"` + v + `"`
	}
	return v
}

func copyNode(n parser.Node) parser.Node {
	switch v := n.(type) {
	case *parser.Directive:
		args := append([]string(nil), v.Args...)
		copy := *v
		copy.Args = args
		return &copy
	case *parser.Section:
		body := make([]parser.Node, len(v.Body))
		for i, c := range v.Body {
			body[i] = copyNode(c)
		}
		copy := *v
		copy.Args = append([]string(nil), v.Args...)
		copy.Body = body
		return &copy
	case *parser.CommentLine:
		copy := *v
		return &copy
	}
	return n
}

// setOrAppend replaces an existing directive's Args or appends a new one.
func setOrAppend(sec *parser.Section, indent, name string, args ...string) {
	for _, n := range sec.Body {
		if d, ok := n.(*parser.Directive); ok && strings.EqualFold(d.Name, name) {
			d.Args = append([]string(nil), args...)
			return
		}
	}
	sec.Body = append(sec.Body, &parser.Directive{
		Indent: indent, Name: name, Args: append([]string(nil), args...), Newline: "\n",
	})
}

func childIndent(sec *parser.Section) string {
	for _, n := range sec.Body {
		switch nn := n.(type) {
		case *parser.Directive:
			return nn.Indent
		case *parser.Section:
			return nn.OpenIndent
		}
	}
	return strings.Repeat(" ", 4)
}

// injectChallengeAliases parses the config and inserts a temporary
// `Alias /.well-known/acme-challenge/ <webroot>/.well-known/acme-challenge/`
// directive into every <VirtualHost *:80> that matches any requested domain.
// A marker comment is added so cleanup can find what we put in.
func (p *Plugin) injectChallengeAliases(configPath, webroot string) error {
	src, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	root, err := parser.Parse(string(src))
	if err != nil {
		return err
	}
	matched := findMatchingVHosts(root, p.domains, "80")
	if len(matched) == 0 {
		// Fall back to any matching vhost.
		matched = findMatchingVHosts(root, p.domains, "")
	}
	if len(matched) == 0 {
		return fmt.Errorf("apache: no <VirtualHost> in %s matches any of %v", configPath, p.domains)
	}
	target := filepath.Join(webroot, ".well-known", "acme-challenge") + string(filepath.Separator)
	for _, sec := range matched {
		indent := childIndent(sec)
		sec.Body = append(sec.Body,
			&parser.CommentLine{Verbatim: indent + "# go-certbot acme-challenge (auto-cleaned)", Newline: "\n"},
			&parser.Directive{Indent: indent, Name: "Alias", Args: []string{`/.well-known/acme-challenge/`, target}, Newline: "\n"},
			&parser.Section{
				OpenIndent: indent, Name: "Directory", Args: []string{`"` + webroot + `/.well-known/acme-challenge/"`},
				OpenNewline: "\n",
				Body: []parser.Node{
					&parser.Directive{Indent: indent + "    ", Name: "Require", Args: []string{"all", "granted"}, Newline: "\n"},
				},
				CloseIndent: indent, CloseNewline: "\n",
			},
		)
	}
	p.mu.Lock()
	p.injectedConfig = configPath
	p.mu.Unlock()
	return os.WriteFile(configPath, []byte(root.String()), 0o644)
}

// removeChallengeAliases strips everything we marked with the sentinel comment.
func (p *Plugin) removeChallengeAliases(configPath string) error {
	src, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	root, err := parser.Parse(string(src))
	if err != nil {
		return err
	}
	stripChallengeMarkers(root.Nodes)
	return os.WriteFile(configPath, []byte(root.String()), 0o644)
}

// stripChallengeMarkers walks the AST and removes the sentinel comment, the
// directly-following Alias, and the directly-following <Directory> section.
// We identify the run by the marker comment we inserted.
func stripChallengeMarkers(nodes []parser.Node) {
	for _, n := range nodes {
		sec, ok := n.(*parser.Section)
		if !ok {
			continue
		}
		filtered := sec.Body[:0]
		skipping := 0
		for _, child := range sec.Body {
			if skipping > 0 {
				skipping--
				continue
			}
			if c, ok := child.(*parser.CommentLine); ok &&
				strings.Contains(c.Verbatim, "go-certbot acme-challenge") {
				skipping = 2 // also drop the Alias and the <Directory> after.
				continue
			}
			filtered = append(filtered, child)
		}
		sec.Body = filtered
		stripChallengeMarkers(sec.Body)
	}
}

// testAndReload runs configtest then graceful via the per-OS control binary
// (apachectl on Debian, httpd on RHEL/Alpine, apache2ctl on Gentoo).
// Honors cfg.ApacheCtl if set.
func testAndReload(ctx context.Context, cfg *config.Config) error {
	ctl := apacheCtl(cfg)
	if out, err := exec.CommandContext(ctx, ctl, "configtest").CombinedOutput(); err != nil {
		return fmt.Errorf("apache: `%s configtest` failed: %w\n%s", ctl, err, string(out))
	}
	// `apachectl graceful` is Debian; `httpd -k graceful` is RHEL.
	// apachectl accepts `graceful` directly. httpd needs `-k graceful`.
	var reload *exec.Cmd
	if strings.Contains(filepath.Base(ctl), "httpd") {
		reload = exec.CommandContext(ctx, ctl, "-k", "graceful")
	} else {
		reload = exec.CommandContext(ctx, ctl, "graceful")
	}
	if out, err := reload.CombinedOutput(); err != nil {
		return fmt.Errorf("apache: `%s graceful` failed: %w\n%s", ctl, err, string(out))
	}
	return nil
}

// _ keeps `errors` referenced for future use.
var _ = errors.New
