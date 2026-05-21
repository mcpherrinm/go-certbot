package nginx

import (
	"context"
	"fmt"
	"os"

	"github.com/letsencrypt/go-certbot/internal/checkpoint"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/nginx/parser"
)

// Enhance applies HSTS / OCSP-stapling / upgrade-insecure-requests to every
// matching server block that already speaks HTTPS (listens on :443 or has
// `ssl`). Idempotent.
func (p *Plugin) Enhance(ctx context.Context, cfg *config.Config, domains []string, enhancements []string) error {
	configPath := nginxConfigPath(cfg)
	srcBytes, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("nginx: %s: %w", configPath, err)
	}
	root, err := parser.Parse(string(srcBytes))
	if err != nil {
		return fmt.Errorf("nginx: parse %s: %w", configPath, err)
	}

	servers := findMatchingServers(root, domains)
	httpsServers := servers[:0]
	for _, s := range servers {
		if serverIsHTTPS(s) {
			httpsServers = append(httpsServers, s)
		}
	}
	if len(httpsServers) == 0 {
		return fmt.Errorf("nginx: no HTTPS server block matched %v; install a cert first", domains)
	}

	for _, srv := range httpsServers {
		for _, e := range enhancements {
			switch e {
			case plugins.EnhanceHSTS:
				addHSTS(srv)
			case plugins.EnhanceUIR:
				// UIR is apache-only in Certbot. Accept the flag (so cli.ini
				// from a mixed setup keeps parsing) but no-op here, matching
				// Certbot's behavior when --uir is passed without --apache.
			case plugins.EnhanceStaple:
				addStaple(srv)
			case plugins.EnhanceRedirect:
				// nginx redirect: for each matched HTTPS server, find the
				// sibling HTTP server (by ServerName) and inject an
				// `if ($host = X) { return 301 ... }` block. Reuses the
				// Install-time helper.
				ensureRedirectExists([]*parsedFile{{AST: root}}, []serverHit{{Server: srv}}, domains)
			default:
				return fmt.Errorf("nginx: unknown enhancement %q", e)
			}
		}
	}
	if _, err := checkpoint.Save(cfg.WorkDir, "nginx-enhance", []string{configPath}); err != nil {
		return fmt.Errorf("nginx: checkpoint: %w", err)
	}
	if err := os.WriteFile(configPath, []byte(root.String()), 0o644); err != nil {
		return fmt.Errorf("nginx: write %s: %w", configPath, err)
	}
	if err := testAndReload(ctx, cfg); err != nil {
		return err
	}
	checkpoint.MarkClean()
	return nil
}

func addHSTS(srv *parser.Block) {
	// HSTS: max-age=31536000 (1y). Mirrors Certbot's default header.
	value := `"max-age=31536000" always`
	upsertAddHeader(srv, "Strict-Transport-Security", value)
}

func addUIR(srv *parser.Block) {
	value := `"upgrade-insecure-requests" always`
	upsertAddHeader(srv, "Content-Security-Policy", value)
}

// upsertAddHeader replaces an existing `add_header <name> ...` directive with
// the new value, or appends one if none exists.
func upsertAddHeader(srv *parser.Block, name, valueArgs string) {
	for _, n := range srv.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "add_header" || len(d.Args) < 1 {
			continue
		}
		if d.Args[0] == name {
			d.Args = append([]string{name}, splitArgs(valueArgs)...)
			return
		}
	}
	srv.Body = append(srv.Body, &parser.Directive{
		Whitespace: "\n" + childIndent(srv),
		Name:       "add_header",
		Args:       append([]string{name}, splitArgs(valueArgs)...),
		Semicolon:  true,
	})
}

// addStaple enables OCSP stapling. nginx requires ssl_trusted_certificate
// to point at the issuer chain when ssl_stapling_verify is on (without it,
// nginx refuses to staple). The chain path is derived from the per-server
// ssl_certificate directive: replace fullchain.pem → chain.pem.
func addStaple(srv *parser.Block) {
	upsertDirective(srv, "ssl_stapling", "on")
	upsertDirective(srv, "ssl_stapling_verify", "on")
	chainPath := deriveChainPath(srv)
	if chainPath != "" {
		upsertDirective(srv, "ssl_trusted_certificate", chainPath)
	}
}

// deriveChainPath finds the server's ssl_certificate directive and returns
// the matching chain path (with "fullchain" → "chain"). Returns "" if no
// ssl_certificate is set on this server.
func deriveChainPath(srv *parser.Block) string {
	for _, n := range srv.Body {
		d, ok := n.(*parser.Directive)
		if !ok || d.Name != "ssl_certificate" || len(d.Args) == 0 {
			continue
		}
		v := d.Args[0]
		// Strip outer quotes if present.
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		// fullchain.pem → chain.pem
		if i := lastIndexByte(v, '/'); i >= 0 {
			base := v[i+1:]
			if base == "fullchain.pem" {
				return v[:i+1] + "chain.pem"
			}
		} else if v == "fullchain.pem" {
			return "chain.pem"
		}
		return v
	}
	return ""
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// upsertDirective replaces the named directive's args or appends new.
func upsertDirective(srv *parser.Block, name string, args ...string) {
	for _, n := range srv.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == name {
			d.Args = append([]string(nil), args...)
			return
		}
	}
	srv.Body = append(srv.Body, &parser.Directive{
		Whitespace: "\n" + childIndent(srv),
		Name:       name,
		Args:       append([]string(nil), args...),
		Semicolon:  true,
	})
}

// splitArgs splits an nginx-args string by spaces, keeping quoted segments
// together.
func splitArgs(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			start := i
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				i++
			}
			if i < len(s) {
				i++
			}
			out = append(out, s[start:i])
			continue
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		out = append(out, s[start:i])
	}
	return out
}
