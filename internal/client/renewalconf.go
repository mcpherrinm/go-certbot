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
// tool. Format and key names match certbot._internal.storage:make_renewal_configobj.
func writeRenewalConf(cfg *config.Config, certName, accountID string, domains []string, lineage *storage.Lineage) error {
	f := renewalconf.New()

	// Top-level keys exactly as Certbot's make_renewal_configobj writes them
	// (storage.py:209-225). archive_dir and version are required by Certbot's
	// RenewableCert.__init__ to locate archive files when configdir moves.
	f.SetTop("version", version)
	f.SetTop("archive_dir", storage.ArchiveDir(cfg.ConfigDir, certName))
	f.SetTop("cert", lineage.Live.Cert)
	f.SetTop("privkey", lineage.Live.Privkey)
	f.SetTop("chain", lineage.Live.Chain)
	f.SetTop("fullchain", lineage.Live.Fullchain)

	// [renewalparams]. Field names match Certbot's renewal type tables
	// (certbot/_internal/renewal.py:48-58).
	f.SetParam("account", accountID)
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
	if cfg.PreferredProfile != "" {
		f.SetParam("preferred_profile", cfg.PreferredProfile)
	}
	if cfg.RequiredProfile != "" {
		f.SetParam("required_profile", cfg.RequiredProfile)
	}
	if cfg.PreHook != "" {
		f.SetParam("pre_hook", cfg.PreHook)
	}
	if cfg.PostHook != "" {
		f.SetParam("post_hook", cfg.PostHook)
	}
	// Certbot stores deploy_hook on disk under the key `renew_hook` (the
	// historic name) and renames it back to `deploy_hook` on load
	// (storage.py:216-223, :512-516). Mirror that so older Certbot versions
	// don't silently drop the hook on read.
	if cfg.DeployHook != "" {
		f.SetParam("renew_hook", cfg.DeployHook)
	}
	if cfg.HTTP01Port != 0 {
		f.SetParam("http01_port", strconv.Itoa(cfg.HTTP01Port))
	}
	if cfg.HTTP01Address != "" {
		f.SetParam("http01_address", cfg.HTTP01Address)
	}
	if cfg.UserAgent != "" {
		f.SetParam("user_agent", cfg.UserAgent)
	}
	if cfg.AllowSubsetOfNames {
		f.SetParam("allow_subset_of_names", "True")
	}
	if len(cfg.PreferredChallenges) > 0 {
		f.SetParam("pref_challs", strings.Join(cfg.PreferredChallenges, ",")+",")
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
