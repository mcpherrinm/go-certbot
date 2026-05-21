package apache

import (
	"fmt"
	"os"
	"path/filepath"
)

// optionsSSLApacheConf is the embedded copy of Certbot's
// current-options-ssl-apache.conf (certbot-apache/_internal/tls_configs).
// This is byte-identical to the upstream snippet so a mixed-tool
// deployment can detect "this is Certbot's snippet" via SHA-256 and
// upgrade in place rather than overwrite a user-modified file.
const optionsSSLApacheConf = `# This file contains important security parameters. If you modify this file
# manually, Certbot will be unable to automatically provide future security
# updates. Instead, Certbot will print and log an error message with a path to
# the up-to-date file that you will need to refer to when manually updating
# this file. Contents are based on https://ssl-config.mozilla.org

SSLEngine on

# Intermediate configuration, tweak to your needs
SSLProtocol             all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLOpenSSLConfCmd       Curves X25519:prime256v1:secp384r1
SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder     off
SSLSessionTickets       off

SSLOptions +StrictRequire
`

// installOptionsSSLApacheConf writes the snippet into
// <config_dir>/options-ssl-apache.conf if missing or content-different. The
// path is then `Include`d from every cloned -le-ssl vhost so the vhost
// inherits the recommended SSLProtocol / SSLCipherSuite / SSLHonorCipherOrder
// triple.
func installOptionsSSLApacheConf(configDir string) (string, error) {
	path := filepath.Join(configDir, "options-ssl-apache.conf")
	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == optionsSSLApacheConf {
		return path, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("apache: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(optionsSSLApacheConf), 0o644); err != nil {
		return "", fmt.Errorf("apache: write %s: %w", path, err)
	}
	return path, nil
}
