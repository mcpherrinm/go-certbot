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

// Install implements plugins.Installer.
func (p *Plugin) Install(ctx context.Context, cfg *config.Config, domains []string, fullchainPath, privkeyPath string) error {
	configPath := apacheConfigPath(cfg)
	srcBytes, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("apache: %s: %w", configPath, err)
	}
	root, err := parser.Parse(string(srcBytes))
	if err != nil {
		return fmt.Errorf("apache: parse %s: %w", configPath, err)
	}

	matched443 := findMatchingVHosts(root, domains, "443")
	matched80 := findMatchingVHosts(root, domains, "80")

	if len(matched443) == 0 && len(matched80) == 0 {
		return fmt.Errorf("apache: no <VirtualHost> matched any of %v in %s", domains, configPath)
	}

	if len(matched443) > 0 {
		for _, sec := range matched443 {
			applySSLDirectives(sec, fullchainPath, privkeyPath)
		}
	} else {
		// Clone every matching :80 vhost as a new :443 vhost.
		for _, sec := range matched80 {
			clone := cloneAsSSLVHost(sec, fullchainPath, privkeyPath)
			root.Nodes = append(root.Nodes, clone)
		}
	}

	if err := os.WriteFile(configPath, []byte(root.String()), 0o644); err != nil {
		return fmt.Errorf("apache: write %s: %w", configPath, err)
	}
	return testAndReload(ctx, cfg)
}

// apacheConfigPath returns where to read/write.
func apacheConfigPath(cfg *config.Config) string {
	if cfg.ApacheConfig != "" {
		return cfg.ApacheConfig
	}
	if cfg.ApacheServerRoot != "" {
		return filepath.Join(cfg.ApacheServerRoot, "apache2.conf")
	}
	return "/etc/apache2/apache2.conf"
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
// SSLCertificateKeyFile inside an existing :443 vhost.
func applySSLDirectives(sec *parser.Section, fullchain, privkey string) {
	indent := childIndent(sec)
	setOrAppend(sec, indent, "SSLEngine", "on")
	setOrAppend(sec, indent, "SSLCertificateFile", fullchain)
	setOrAppend(sec, indent, "SSLCertificateKeyFile", privkey)
}

// cloneAsSSLVHost duplicates a :80 vhost as a new :443 vhost with SSL
// directives appended. The clone keeps ServerName/ServerAlias/DocumentRoot/
// other arbitrary directives so the new vhost behaves the same.
func cloneAsSSLVHost(src *parser.Section, fullchain, privkey string) *parser.Section {
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
	return dst
}

// rewriteArgsTo443 turns `*:80` → `*:443`, leaving other args alone.
func rewriteArgsTo443(in []string) []string {
	out := make([]string, len(in))
	for i, a := range in {
		v := a
		quoted := false
		if strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
			v = strings.Trim(v, `"`)
			quoted = true
		}
		if j := strings.LastIndex(v, ":"); j >= 0 && v[j+1:] == "80" {
			v = v[:j+1] + "443"
		}
		if quoted {
			v = `"` + v + `"`
		}
		out[i] = v
	}
	return out
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

// testAndReload runs `apachectl configtest` then `apachectl graceful`. Uses
// cfg.ApacheCtl if set.
func testAndReload(ctx context.Context, cfg *config.Config) error {
	ctl := cfg.ApacheCtl
	if ctl == "" {
		ctl = "apachectl"
	}
	if out, err := exec.CommandContext(ctx, ctl, "configtest").CombinedOutput(); err != nil {
		return fmt.Errorf("apache: `%s configtest` failed: %w\n%s", ctl, err, string(out))
	}
	if out, err := exec.CommandContext(ctx, ctl, "graceful").CombinedOutput(); err != nil {
		return fmt.Errorf("apache: `%s graceful` failed: %w\n%s", ctl, err, string(out))
	}
	return nil
}

// _ keeps `errors` referenced for future use.
var _ = errors.New
