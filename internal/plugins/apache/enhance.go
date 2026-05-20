package apache

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/apache/parser"
)

// Enhance applies HSTS / OCSP-stapling / upgrade-insecure-requests to every
// matching :443 <VirtualHost>. Idempotent.
func (p *Plugin) Enhance(ctx context.Context, cfg *config.Config, domains []string, enhancements []string) error {
	configPath := apacheConfigPath(cfg)
	srcBytes, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("apache: %s: %w", configPath, err)
	}
	root, err := parser.Parse(string(srcBytes))
	if err != nil {
		return fmt.Errorf("apache: parse %s: %w", configPath, err)
	}

	matched := findMatchingVHosts(root, domains, "443")
	if len(matched) == 0 {
		return fmt.Errorf("apache: no <VirtualHost *:443> matched %v; install a cert first", domains)
	}

	for _, sec := range matched {
		for _, e := range enhancements {
			switch e {
			case plugins.EnhanceHSTS:
				addHSTS(sec)
			case plugins.EnhanceUIR:
				addUIR(sec)
			case plugins.EnhanceStaple:
				addStaple(sec)
			default:
				return fmt.Errorf("apache: unknown enhancement %q", e)
			}
		}
	}
	if err := os.WriteFile(configPath, []byte(root.String()), 0o644); err != nil {
		return fmt.Errorf("apache: write %s: %w", configPath, err)
	}
	return testAndReload(ctx, cfg)
}

// addHSTS adds `Header always set Strict-Transport-Security "max-age=31536000"`.
// Idempotent: replaces an existing line.
func addHSTS(sec *parser.Section) {
	upsertHeader(sec, "always", "set", "Strict-Transport-Security", `"max-age=31536000"`)
}

func addUIR(sec *parser.Section) {
	upsertHeader(sec, "always", "set", "Content-Security-Policy", `"upgrade-insecure-requests"`)
}

// upsertHeader replaces a matching `Header [always] set <name> ...` directive
// or appends a new one. The match is on (mode, op, name).
func upsertHeader(sec *parser.Section, mode, op, name string, value string) {
	for _, n := range sec.Body {
		d, ok := n.(*parser.Directive)
		if !ok || !strings.EqualFold(d.Name, "Header") {
			continue
		}
		if matchHeader(d.Args, mode, op, name) {
			d.Args = []string{mode, op, name, value}
			return
		}
	}
	indent := childIndent(sec)
	sec.Body = append(sec.Body, &parser.Directive{
		Indent:  indent,
		Name:    "Header",
		Args:    []string{mode, op, name, value},
		Newline: "\n",
	})
}

// matchHeader returns true if args look like `[mode] op name ...` matching
// the requested triple. mode is optional (e.g. "always") — if present in
// args it must equal the requested mode.
func matchHeader(args []string, mode, op, name string) bool {
	if len(args) < 2 {
		return false
	}
	i := 0
	if strings.EqualFold(args[i], mode) {
		i++
	} else if mode != "" {
		// We want `always` but args don't have it: not a match.
		return false
	}
	if i >= len(args) || !strings.EqualFold(args[i], op) {
		return false
	}
	i++
	if i >= len(args) {
		return false
	}
	return strings.EqualFold(args[i], name)
}

// addStaple inserts OCSP-stapling directives. Apache requires both the
// per-vhost SSLUseStapling on and a server-scope SSLStaplingCache somewhere
// — for the simple in-vhost case we'll add both inside the vhost (Apache
// permits it inside an IfModule wrapper but a single vhost-level entry is
// accepted and matches what mod_ssl examples show).
func addStaple(sec *parser.Section) {
	upsertDirective(sec, "SSLUseStapling", "on")
	upsertDirective(sec, "SSLStaplingCache", `"shmcb:/var/run/ocsp(128000)"`)
}

func upsertDirective(sec *parser.Section, name string, args ...string) {
	for _, n := range sec.Body {
		if d, ok := n.(*parser.Directive); ok && strings.EqualFold(d.Name, name) {
			d.Args = append([]string(nil), args...)
			return
		}
	}
	indent := childIndent(sec)
	sec.Body = append(sec.Body, &parser.Directive{
		Indent:  indent,
		Name:    name,
		Args:    append([]string(nil), args...),
		Newline: "\n",
	})
}
