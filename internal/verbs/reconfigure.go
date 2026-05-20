package verbs

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

// Reconfigure updates a renewal/<certname>.conf in place, applying any
// user-set flags (everything tracked via SetByUser) to the [renewalparams]
// section, then saving. No issuance happens.
func Reconfigure(_ context.Context, cfg *config.Config, _ *plugins.Registry) error {
	if cfg.CertName == "" {
		return errors.New("reconfigure: --cert-name is required")
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
		{"server", "server", func(c *config.Config) string { return c.Server }},
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
		{"deploy-hook", "deploy_hook", func(c *config.Config) string { return c.DeployHook }},
		{"webroot-path", "webroot_path", func(c *config.Config) string { return strings.Join(c.WebrootPath, ",") + "," }},
	}
	changed := 0
	for _, s := range all {
		if cfg.SetByUser(s.flag) {
			f.SetParam(s.key, s.encode(cfg))
			changed++
		}
	}
	if changed == 0 {
		fmt.Println("reconfigure: nothing to update (no overriding flags provided)")
		return nil
	}
	if err := f.Save(path); err != nil {
		return err
	}
	fmt.Printf("reconfigure: updated %d field(s) in %s\n", changed, path)
	return nil
}

func boolStr(b bool) string {
	if b {
		return "True"
	}
	return "False"
}
