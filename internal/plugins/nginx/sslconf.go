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
// when missing or matching a known historical version, and ensures each
// modified server block has an `include` of it. Matches Certbot's
// `update_files` (configurator.py:148-180) which tracks 25 historical
// SHA-256s for safe upgrade — when on-disk content has been user-edited
// (no SHA match), Certbot warns and leaves it alone.
//
// Note: Certbot 5.x dropped the ssl-dhparams.pem auto-write and the
// ssl_dhparam directive from options-ssl-nginx.conf, so we don't touch
// either here.
func installOptionsSSLNginxConf(configDir string, files []*parsedFile, hits []serverHit) error {
	sslPath := filepath.Join(configDir, "options-ssl-nginx.conf")
	if err := writeIfManaged(sslPath, []byte(optionsSSLNginxConf), historicalSSLConfHashes); err != nil {
		return err
	}
	for _, h := range hits {
		ensureInclude(h.Server, sslPath)
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

// historicalSSLConfHashes covers every options-ssl-nginx.conf Certbot has
// shipped, so an upgrade from Certbot to go-certbot doesn't see the
// file as "user-modified" and refuse to update. Sourced from Certbot's
// constants.ALL_SSL_OPTIONS_HASHES (certbot-nginx/_internal/constants.py).
var historicalSSLConfHashes = map[string]bool{
	"0f81093a1465e3d4eaa8b0c14e77b2a2e93568b0fc1351c2b87893a95f0de87c": true,
	"9a7b32c49001fed4cff8ad24353329472a50e86ade1ef9b2b9e43566a619612e": true,
	"a6d9f1c7d6b36749b52ba061fff1421f9a0a3d2cfdafbd63c05d06f65b990937": true,
	"7f95624dd95cf5afc708b9f967ee83a24b8025dc7c8d9df2b556bbc64256b3ff": true,
	"394732f2bbe3e5e637c3fb5c6e980a1f1b90b01e2e8d6b7cff41dde16e2a756d": true,
	"4b16fec2bcbcd8a2f3296d886f17f9953ffdcc0af54582452ca1e52f5f776f16": true,
	"c052ffff0ad683f43bffe105f7c606b339536163490930e2632a335c8d191cc4": true,
	"02329eb19930af73c54b3632b3165d84571383b8c8c73361df940cb3894dd426": true,
	"63e2bddebb174a05c9d8a7cf2adf72f7af04349ba59a1a925fe447f73b2f1abf": true,
	"2901debc7ecbc10917edd9084c05464c9c5930b463677571eaf8c94bffd11ae2": true,
	"30baca73ed9a5b0e9a69ea40e30482241d8b1a7343aa79b49dc5d7db0bf53b6c": true,
	"108c4555058a087496a3893aea5d9e1cee0f20a3085d44a52dc1a66522299ac3": true,
	"d5e021706ecdccc7090111b0ae9a29ef61523e927f020e410caf0a1fd7063981": true,
	"ef11e3fb17213e74d3e1816cde0ec37b8b95b4167cf21e7b8ff1eaa9c6f918ee": true,
	"af85f6193808a44789a1d293e6cffa249cad9a21135940800958b8e3c72dbc69": true,
	"a2a612fd21b02abaa32d9d11ac63d987d6e3054dbfa356de5800eea0d7ce17f3": true,
	"2d9648302e3588a172c318e46bff88ade46fc7a16d6afc85322776a04800d473": true,
	"5e21cc66989f26ec46116d979421e538131cf8ab33ffff3f682fbfe491b0ace8": true,
	"f5615544105c4eee44f02a604e3e9ae55b3d5bad247160bb18731a0ac531af02": true,
	"05a799c4db12f8e15e68219c98056824cbd5ae7b05863225318ae112f343880b": true,
	"dc81acfd9670f137d5abbccfe3438d9306d4b6a906439b0fbf6a6756272e7cc7": true,
	"0175f71721dd8e5315a6d0f3efef703ff54e867d1ab2a4e076791b89a0b3511a": true,
	"246b520bedc461fcbd35f4d3efdd75ebf171baccaba5c38f488009566de6d5b3": true,
	"dd72286f760c90550f34fbeeceb5a1f1351b09b812e65a18569a0f4a4d7f5847": true,
	// Plus the current content, so an in-place rewrite doesn't trigger the
	// "modified by hand" warning when nothing changed.
	sha256Hex([]byte(optionsSSLNginxConf)): true,
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:])
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
