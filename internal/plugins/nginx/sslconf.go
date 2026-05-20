package nginx

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/letsencrypt/go-certbot/internal/plugins/nginx/parser"
)

// optionsSSLNginxConf is Certbot's modern nginx TLS-config snippet, embedded
// so go-certbot's binary is self-contained. Source:
// certbot/_internal/plugins/nginx/tls_configs/options-ssl-nginx.conf.
const optionsSSLNginxConf = `# This file contains important security parameters. If you modify this file
# manually, Certbot will be unable to automatically provide future security
# updates. Instead, Certbot will print and log an error message with a path to
# the up-to-date file that you will need to refer to when manually updating
# this file. Contents are based on https://ssl-config.mozilla.org

ssl_session_cache shared:le_nginx_SSL:10m;
ssl_session_timeout 1440m;
ssl_session_tickets off;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;

ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
`

// installOptionsSSLNginxConf writes <config_dir>/options-ssl-nginx.conf if
// it's missing or its content differs from the embedded snippet, and ensures
// each modified server block has an `include <config_dir>/options-ssl-nginx.conf;`
// directive. Idempotent.
func installOptionsSSLNginxConf(configDir string, files []*parsedFile, hits []serverHit) error {
	target := filepath.Join(configDir, "options-ssl-nginx.conf")
	existing, err := os.ReadFile(target)
	if err != nil || string(existing) != optionsSSLNginxConf {
		if err := os.WriteFile(target, []byte(optionsSSLNginxConf), 0o644); err != nil {
			return fmt.Errorf("nginx: write %s: %w", target, err)
		}
	}
	includeDirective := target
	for _, h := range hits {
		ensureInclude(h.Server, includeDirective)
	}
	return nil
}

// ensureInclude appends `include <path>;` to the server block if it isn't
// already present.
func ensureInclude(srv *parser.Block, path string) {
	for _, n := range srv.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == "include" && len(d.Args) > 0 {
			arg := d.Args[0]
			// Strip optional quotes.
			if len(arg) >= 2 && (arg[0] == '"' && arg[len(arg)-1] == '"') {
				arg = arg[1 : len(arg)-1]
			}
			if arg == path {
				return
			}
		}
	}
	srv.Body = append(srv.Body, &parser.Directive{
		Whitespace: "\n" + childIndent(srv),
		Name:       "include",
		Args:       []string{path},
		Semicolon:  true,
	})
}
