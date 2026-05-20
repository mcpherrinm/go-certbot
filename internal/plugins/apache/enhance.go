package apache

import (
	"context"
	"fmt"
	"strings"

	"github.com/letsencrypt/go-certbot/internal/checkpoint"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/apache/parser"
)

// Enhance applies HSTS / OCSP-stapling / upgrade-insecure-requests to every
// matching :443 <VirtualHost>. Idempotent. Header directives are wrapped in
// <IfModule mod_headers.c> so configtest doesn't fail when mod_headers isn't
// loaded; SSLStaplingCache is written at the global scope (Apache requires
// it server-wide, not per-vhost).
func (p *Plugin) Enhance(ctx context.Context, cfg *config.Config, domains []string, enhancements []string) error {
	configPath := apacheConfigPath(cfg)
	files, err := loadAll(configPath)
	if err != nil {
		return err
	}
	hits := findMatchingVHostsAcrossFiles(files, domains, "443")
	if len(hits) == 0 {
		return fmt.Errorf("apache: no <VirtualHost *:443> matched %v; install a cert first", domains)
	}

	needStaple := false
	for _, h := range hits {
		for _, e := range enhancements {
			switch e {
			case plugins.EnhanceHSTS:
				addHSTS(h.Sec)
			case plugins.EnhanceUIR:
				addUIR(h.Sec)
			case plugins.EnhanceStaple:
				addPerVHostStaple(h.Sec)
				needStaple = true
			default:
				return fmt.Errorf("apache: unknown enhancement %q", e)
			}
		}
	}
	if needStaple {
		// Apache requires SSLStaplingCache at server scope. Insert it into
		// the root file at the top level (idempotent — skip if present).
		ensureGlobalStaplingCache(files[0])
	}
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	if _, err := checkpoint.Save(cfg.WorkDir, "apache-enhance", paths); err != nil {
		return fmt.Errorf("apache: checkpoint: %w", err)
	}
	if err := writeAllFiles(files); err != nil {
		return err
	}
	return testAndReload(ctx, cfg)
}

// addHSTS adds `Header always set Strict-Transport-Security "max-age=31536000"`
// wrapped in an `<IfModule mod_headers.c>` block. Idempotent.
func addHSTS(sec *parser.Section) {
	addHeaderInIfModule(sec, "Strict-Transport-Security", `"max-age=31536000"`)
}

func addUIR(sec *parser.Section) {
	addHeaderInIfModule(sec, "Content-Security-Policy", `"upgrade-insecure-requests"`)
}

// addHeaderInIfModule emits:
//
//	<IfModule mod_headers.c>
//	  Header always set <name> <value>
//	</IfModule>
//
// Idempotent: if the same wrapping already exists with the same header name,
// updates the value in place.
func addHeaderInIfModule(sec *parser.Section, name, value string) {
	if updateExistingHeader(sec, name, value) {
		return
	}
	indent := childIndent(sec)
	wrapper := &parser.Section{
		OpenIndent:  indent,
		Name:        "IfModule",
		Args:        []string{"mod_headers.c"},
		OpenNewline: "\n",
		Body: []parser.Node{
			&parser.Directive{
				Indent:  indent + "    ",
				Name:    "Header",
				Args:    []string{"always", "set", name, value},
				Newline: "\n",
			},
		},
		CloseIndent:  indent,
		CloseNewline: "\n",
	}
	sec.Body = append(sec.Body, wrapper)
}

// updateExistingHeader walks the vhost body looking for an existing
// IfModule-wrapped or bare Header directive matching the requested name and
// updates its value. Returns true if found.
func updateExistingHeader(sec *parser.Section, name, value string) bool {
	for _, n := range sec.Body {
		switch nn := n.(type) {
		case *parser.Directive:
			if strings.EqualFold(nn.Name, "Header") && matchHeader(nn.Args, "always", "set", name) {
				nn.Args = []string{"always", "set", name, value}
				return true
			}
		case *parser.Section:
			if strings.EqualFold(nn.Name, "IfModule") && len(nn.Args) > 0 && strings.Contains(nn.Args[0], "mod_headers") {
				for _, c := range nn.Body {
					if d, ok := c.(*parser.Directive); ok &&
						strings.EqualFold(d.Name, "Header") &&
						matchHeader(d.Args, "always", "set", name) {
						d.Args = []string{"always", "set", name, value}
						return true
					}
				}
			}
		}
	}
	return false
}

// matchHeader returns true if args look like `[mode] op name ...` matching
// the requested triple.
func matchHeader(args []string, mode, op, name string) bool {
	if len(args) < 2 {
		return false
	}
	i := 0
	if strings.EqualFold(args[i], mode) {
		i++
	} else if mode != "" {
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

// addPerVHostStaple sets per-vhost `SSLUseStapling on` only. SSLStaplingCache
// must live at the global scope.
func addPerVHostStaple(sec *parser.Section) {
	upsertDirective(sec, "SSLUseStapling", "on")
}

// ensureGlobalStaplingCache adds `SSLStaplingCache "shmcb:..."` at the top
// level of the root config file, wrapped in <IfModule mod_ssl.c>. Idempotent.
func ensureGlobalStaplingCache(root *parsedFile) {
	for _, n := range root.AST.Nodes {
		switch nn := n.(type) {
		case *parser.Directive:
			if strings.EqualFold(nn.Name, "SSLStaplingCache") {
				return
			}
		case *parser.Section:
			if strings.EqualFold(nn.Name, "IfModule") && len(nn.Args) > 0 && strings.Contains(nn.Args[0], "mod_ssl") {
				for _, c := range nn.Body {
					if d, ok := c.(*parser.Directive); ok && strings.EqualFold(d.Name, "SSLStaplingCache") {
						return
					}
				}
			}
		}
	}
	root.AST.Nodes = append(root.AST.Nodes, &parser.Section{
		Name:        "IfModule",
		Args:        []string{"mod_ssl.c"},
		OpenNewline: "\n",
		Body: []parser.Node{
			&parser.Directive{
				Indent:  "    ",
				Name:    "SSLStaplingCache",
				Args:    []string{`"shmcb:/var/run/apache2/stapling_cache(128000)"`},
				Newline: "\n",
			},
		},
		CloseNewline: "\n",
	})
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
