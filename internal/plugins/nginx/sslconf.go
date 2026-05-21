package nginx

import (
	"crypto/sha256"
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

// installOptionsSSLNginxConf writes <config_dir>/options-ssl-nginx.conf
// (and ssl-dhparams.pem) when missing or matching a known historical
// version, and ensures each modified server block has an `include` of
// both. Matches Certbot's `update_files` (configurator.py:148-180) which
// tracks 25 historical SHA-256s for safe upgrade — when on-disk content
// has been user-edited (no SHA match), Certbot warns and leaves it alone.
func installOptionsSSLNginxConf(configDir string, files []*parsedFile, hits []serverHit) error {
	// SSL snippet.
	sslPath := filepath.Join(configDir, "options-ssl-nginx.conf")
	if err := writeIfManaged(sslPath, []byte(optionsSSLNginxConf), historicalSSLConfHashes); err != nil {
		return err
	}
	// DH params (Certbot ships /etc/letsencrypt/ssl-dhparams.pem and adds
	// `ssl_dhparam` to every modified server block — configurator.py:225,
	// 780). The file is a fixed RFC 7919 ffdhe2048 group, so embedding +
	// rewriting verbatim is safe.
	dhPath := filepath.Join(configDir, "ssl-dhparams.pem")
	if err := writeIfManaged(dhPath, []byte(sslDHParams), historicalDHParamHashes); err != nil {
		return err
	}
	for _, h := range hits {
		ensureInclude(h.Server, sslPath)
		ensureSSLDhparam(h.Server, dhPath)
	}
	return nil
}

// writeIfManaged writes `data` to `path` if either the path is missing or
// the on-disk content hashes to one of `historical`. If the file is
// user-modified (no SHA match), leaves it alone.
func writeIfManaged(path string, data []byte, historical map[string]bool) error {
	existing, err := os.ReadFile(path)
	if err == nil {
		if string(existing) == string(data) {
			return nil
		}
		if !historical[sha256Hex(existing)] {
			fmt.Fprintf(os.Stderr, "nginx: %s has been modified by hand; leaving untouched\n", path)
			return nil
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("nginx: write %s: %w", path, err)
	}
	return nil
}

// sslDHParams is the RFC 7919 ffdhe2048 group Certbot ships.
const sslDHParams = `-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
`

var historicalSSLConfHashes = map[string]bool{
	sha256Hex([]byte(optionsSSLNginxConf)): true,
}

var historicalDHParamHashes = map[string]bool{
	sha256Hex([]byte(sslDHParams)): true,
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:])
}

// ensureSSLDhparam adds `ssl_dhparam <path>;` to a server block if missing.
func ensureSSLDhparam(srv *parser.Block, path string) {
	for _, n := range srv.Body {
		if d, ok := n.(*parser.Directive); ok && d.Name == "ssl_dhparam" {
			return
		}
	}
	indent := childIndent(srv)
	srv.Body = append(srv.Body, &parser.Directive{
		Whitespace: "\n" + indent,
		Name:       "ssl_dhparam",
		Args:       []string{path},
		Semicolon:  true,
	})
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
