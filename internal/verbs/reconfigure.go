package verbs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/hooks"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

// Reconfigure updates a renewal/<certname>.conf in place, applying any
// user-set flags (everything tracked via SetByUser) to the [renewalparams]
// section, then saving. Validates the merged config (plugin selection +
// hook commands) before committing.
func Reconfigure(_ context.Context, cfg *config.Config, reg *plugins.Registry) error {
	name, err := chooseCertName(cfg, "reconfigure")
	if err != nil {
		return err
	}
	cfg.CertName = name
	// Certbot rejects reconfigure of these (main.py:1773-1778) because
	// changing them effectively requires a fresh issuance and breaks the
	// drop-in promise of "renew uses the recorded settings".
	for _, banned := range []string{"server", "account", "domain"} {
		if cfg.SetByUser(banned) {
			return fmt.Errorf("reconfigure: changing --%s is not supported (use a fresh certonly run); see https://eff-certbot.readthedocs.io for migration", banned)
		}
	}
	path := filepath.Join(cfg.RenewalConfigsDir(), cfg.CertName+".conf")
	f, err := renewalconf.Load(path)
	if err != nil {
		return err
	}

	// Map of CLI flag → renewal-conf key (and how to encode the value).
	type setter struct {
		flag, key string
		encode    func(*config.Config) string
	}
	all := []setter{
		{"key-type", "key_type", func(c *config.Config) string { return c.KeyType }},
		{"rsa-key-size", "rsa_key_size", func(c *config.Config) string { return strconv.Itoa(c.RSAKeySize) }},
		{"elliptic-curve", "elliptic_curve", func(c *config.Config) string { return c.EllipticCurve }},
		{"must-staple", "must_staple", func(c *config.Config) string { return boolStr(c.MustStaple) }},
		{"reuse-key", "reuse_key", func(c *config.Config) string { return boolStr(c.ReuseKey) }},
		{"preferred-chain", "preferred_chain", func(c *config.Config) string { return c.PreferredChain }},
		{"preferred-profile", "preferred_profile", func(c *config.Config) string { return c.PreferredProfile }},
		{"required-profile", "required_profile", func(c *config.Config) string { return c.RequiredProfile }},
		{"http-01-port", "http01_port", func(c *config.Config) string { return strconv.Itoa(c.HTTP01Port) }},
		{"http-01-address", "http01_address", func(c *config.Config) string { return c.HTTP01Address }},
		{"pre-hook", "pre_hook", func(c *config.Config) string { return c.PreHook }},
		{"post-hook", "post_hook", func(c *config.Config) string { return c.PostHook }},
		// Persist deploy-hook under the historic `renew_hook` key so older
		// Certbot can pick it up (storage.py:512-516).
		{"deploy-hook", "renew_hook", func(c *config.Config) string { return c.DeployHook }},
		{"webroot-path", "webroot_path", func(c *config.Config) string { return strings.Join(c.WebrootPath, ",") + "," }},
	}
	changed := 0
	for _, s := range all {
		if !cfg.SetByUser(s.flag) {
			continue
		}
		v := s.encode(cfg)
		if v == "" {
			// User explicitly cleared the value (e.g. `--deploy-hook ""`);
			// remove the key from the conf rather than leaving an empty stub.
			f.DeleteParam(s.key)
		} else {
			f.SetParam(s.key, v)
		}
		changed++
	}
	if changed == 0 {
		fmt.Println("reconfigure: nothing to update (no overriding flags provided)")
		return nil
	}
	// Dry-run-style validation before persisting: write to a temp file,
	// re-parse, merge, and check the hook commands + plugin names that
	// would be used on the next renewal. This catches typos in
	// --pre-hook / unknown installer names / etc. before they break
	// `certbot renew` later.
	tmp := path + ".reconfigure-test"
	if err := f.Save(tmp); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := validateReconfiguredConf(tmp, cfg, reg); err != nil {
		return fmt.Errorf("reconfigure: validation failed (config not written): %w", err)
	}
	if err := f.Save(path); err != nil {
		return err
	}
	// Certbot's success message (main.py:1688).
	fmt.Println("Successfully updated configuration.")
	fmt.Println("Changes will apply when the certificate renews.")
	return nil
}

// validateReconfiguredConf re-reads the temp conf and checks that:
//   - hook commands are present in PATH (matches `Validate`).
//   - any named authenticator/installer is a registered plugin.
//
// Mirrors Certbot's reconfigure dry-run intent without actually contacting
// the ACME server (which would also require live network + an account).
func validateReconfiguredConf(path string, cfg *config.Config, reg *plugins.Registry) error {
	f, err := renewalconf.Load(path)
	if err != nil {
		return err
	}
	if !cfg.DisableHookValidation {
		for _, k := range []string{"pre_hook", "post_hook", "renew_hook", "deploy_hook"} {
			if v := f.RenewalParams[k]; v != "" {
				if err := hooks.Validate(v, k); err != nil {
					return err
				}
			}
		}
	}
	if a := f.RenewalParams["authenticator"]; a != "" {
		if _, err := reg.Authenticator(a); err != nil {
			return err
		}
	}
	if i := f.RenewalParams["installer"]; i != "" && i != "None" {
		if _, err := reg.Installer(i); err != nil {
			return err
		}
	}
	return nil
}

func boolStr(b bool) string {
	if b {
		return "True"
	}
	return "False"
}
