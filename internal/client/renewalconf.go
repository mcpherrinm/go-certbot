package client

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/storage"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

// writeRenewalConf produces a renewal/<certname>.conf compatible with
// certbot._internal.renewal so the resulting lineage can be renewed by either
// tool.
func writeRenewalConf(cfg *config.Config, certName string, domains []string, lineage *storage.Lineage) error {
	f := renewalconf.New()
	// Top-level paths point at the live/ symlinks.
	f.SetTop("cert", lineage.Live.Cert)
	f.SetTop("privkey", lineage.Live.Privkey)
	f.SetTop("chain", lineage.Live.Chain)
	f.SetTop("fullchain", lineage.Live.Fullchain)

	// Required renewalparams. Field names match Certbot's renewal type tables
	// (certbot/_internal/renewal.py:48-58).
	f.SetParam("account", "")
	f.SetParam("authenticator", chooseAuth(cfg))
	if cfg.Installer != "" {
		f.SetParam("installer", cfg.Installer)
	} else {
		f.SetParam("installer", "None")
	}
	f.SetParam("server", cfg.EffectiveServer())
	f.SetParam("key_type", cfg.KeyType)
	if cfg.KeyType == "rsa" {
		f.SetParam("rsa_key_size", strconv.Itoa(cfg.RSAKeySize))
	} else {
		f.SetParam("elliptic_curve", cfg.EllipticCurve)
	}
	f.SetParam("must_staple", boolStr(cfg.MustStaple))
	f.SetParam("reuse_key", boolStr(cfg.ReuseKey))
	f.SetParam("autorenew", "True")
	if cfg.PreferredChain != "" {
		f.SetParam("preferred_chain", cfg.PreferredChain)
	}
	if cfg.PreHook != "" {
		f.SetParam("pre_hook", cfg.PreHook)
	}
	if cfg.PostHook != "" {
		f.SetParam("post_hook", cfg.PostHook)
	}
	if cfg.DeployHook != "" {
		f.SetParam("deploy_hook", cfg.DeployHook)
	}
	if cfg.HTTP01Port != 0 {
		f.SetParam("http01_port", strconv.Itoa(cfg.HTTP01Port))
	}
	if cfg.HTTP01Address != "" {
		f.SetParam("http01_address", cfg.HTTP01Address)
	}
	// `domains = a,b,c,` — configobj treats trailing-comma values as lists.
	f.SetParam("domains", strings.Join(domains, ",")+",")

	path := filepath.Join(cfg.RenewalConfigsDir(), certName+".conf")
	return f.Save(path)
}

func chooseAuth(cfg *config.Config) string {
	if cfg.Authenticator != "" {
		return cfg.Authenticator
	}
	switch {
	case cfg.Standalone:
		return "standalone"
	case cfg.Webroot:
		return "webroot"
	case cfg.Manual:
		return "manual"
	case cfg.Apache:
		return "apache"
	case cfg.Nginx:
		return "nginx"
	}
	return ""
}

func boolStr(b bool) string {
	if b {
		return "True"
	}
	return "False"
}
