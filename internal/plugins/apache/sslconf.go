package apache

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

// optionsSSLApacheConf is the embedded copy of Certbot's
// current options-ssl-apache.conf (certbot-apache/_internal/tls_configs).
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

// historicalApacheSSLConfHashes covers every options-ssl-apache.conf
// Certbot has shipped, sourced from
// certbot_apache._internal.constants.ALL_SSL_OPTIONS_HASHES. A migrating
// user's existing options-ssl-apache.conf is recognized as Certbot-managed
// (and safe to upgrade) even if it predates the current snippet.
var historicalApacheSSLConfHashes = map[string]bool{
	"2086bca02db48daf93468332543c60ac6acdb6f0b58c7bfdf578a5d47092f82a": true,
	"4844d36c9a0f587172d9fa10f4f1c9518e3bcfa1947379f155e16a70a728c21a": true,
	"5a922826719981c0a234b1fbcd495f3213e49d2519e845ea0748ba513044b65b": true,
	"4066b90268c03c9ba0201068eaa39abbc02acf9558bb45a788b630eb85dadf27": true,
	"f175e2e7c673bd88d0aff8220735f385f916142c44aa83b09f1df88dd4767a88": true,
	"cfdd7c18d2025836ea3307399f509cfb1ebf2612c87dd600a65da2a8e2f2797b": true,
	"80720bd171ccdc2e6b917ded340defae66919e4624962396b992b7218a561791": true,
	"c0c022ea6b8a51ecc8f1003d0a04af6c3f2bc1c3ce506b3c2dfc1f11ef931082": true,
	"717b0a89f5e4c39b09a42813ac6e747cfbdeb93439499e73f4f70a1fe1473f20": true,
	"0fcdc81280cd179a07ec4d29d3595068b9326b455c488de4b09f585d5dafc137": true,
	"86cc09ad5415cd6d5f09a947fe2501a9344328b1e8a8b458107ea903e80baa6c": true,
	"06675349e457eae856120cdebb564efe546f0b87399f2264baeb41e442c724c7": true,
	"5cc003edd93fb9cd03d40c7686495f8f058f485f75b5e764b789245a386e6daf": true,
	"007cd497a56a3bb8b6a2c1aeb4997789e7e38992f74e44cc5d13a625a738ac73": true,
	"34783b9e2210f5c4a23bced2dfd7ec289834716673354ed7c7abf69fe30192a3": true,
	"61466bc2f98a623c02be8a5ee916ead1655b0ce883bdc936692076ea499ff5ce": true,
	"3fd812e3e87fe5c645d3682a511b2a06c8286f19594f28e280f17cd6af1301b5": true,
	"27155797e160fe43b6951354a0a0ca4d829e9e605b3b41fc223c20bf2f6cb3c6": true,
	"3a6881d0a7e5740b039ec550c916105259f53b577a3d38d0ed11bd675bfeab88": true,
	"0f3d9c62d4274aca0406925dc4ee0919599c397e7463bce792a915b60060d004": true,
	"95f7367d4905a1cd0932a35ce476b4a639e2108dbd1eedf924a5ea9e51fecaf7": true,
}

// installOptionsSSLApacheConf writes the snippet into
// <config_dir>/options-ssl-apache.conf if missing, byte-identical, or
// matching a known historical SHA-256. User-modified files are left alone
// with a warning, mirroring Certbot's common.install_version_controlled_file
// (configurator.py:2509-2523).
func installOptionsSSLApacheConf(configDir string) (string, error) {
	path := filepath.Join(configDir, "options-ssl-apache.conf")
	existing, err := os.ReadFile(path)
	if err == nil {
		if string(existing) == optionsSSLApacheConf {
			return path, nil
		}
		h := sha256.Sum256(existing)
		hex := fmt.Sprintf("%x", h[:])
		if !historicalApacheSSLConfHashes[hex] {
			fmt.Fprintf(os.Stderr,
				"apache: %s has been modified by hand; leaving untouched. New TLS settings are at %s.dist\n",
				path, path)
			distPath := path + ".dist"
			if werr := os.WriteFile(distPath, []byte(optionsSSLApacheConf), 0o644); werr != nil {
				return "", fmt.Errorf("apache: write %s: %w", distPath, werr)
			}
			return path, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("apache: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(optionsSSLApacheConf), 0o644); err != nil {
		return "", fmt.Errorf("apache: write %s: %w", path, err)
	}
	return path, nil
}
