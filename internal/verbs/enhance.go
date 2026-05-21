package verbs

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

// Enhance applies security enhancements (HSTS, OCSP stapling,
// upgrade-insecure-requests) to a managed cert's vhost(s).
//
// --cert-name selects the lineage; we read its domains from the renewal conf
// unless -d is supplied. --installer (or --nginx / --apache) picks the
// plugin; falls back to whatever installer the renewal conf recorded.
func Enhance(ctx context.Context, cfg *config.Config, reg *plugins.Registry) error {
	if !cfg.HSTS && !cfg.UIR && !cfg.Staple {
		return errors.New("enhance: select at least one of --hsts / --uir / --staple")
	}

	domains := cfg.Domains
	installerName := cfg.Installer
	if cfg.Nginx {
		installerName = "nginx"
	}
	if cfg.Apache {
		installerName = "apache"
	}
	if cfg.CertName == "" && len(domains) == 0 {
		name, err := chooseCertName(cfg, "enhance")
		if err != nil {
			return err
		}
		cfg.CertName = name
	}
	if cfg.CertName != "" {
		conf, err := renewalconf.Load(filepath.Join(cfg.RenewalConfigsDir(), cfg.CertName+".conf"))
		if err != nil {
			return err
		}
		if len(domains) == 0 {
			if list, ok := conf.List("domains"); ok {
				domains = list
			}
		}
		if installerName == "" {
			installerName = conf.RenewalParams["installer"]
		}
	}
	if len(domains) == 0 {
		return errors.New("enhance: -d/--domain or a --cert-name with recorded domains is required")
	}
	if installerName == "" || installerName == "None" {
		return errors.New("enhance: --installer (or --nginx / --apache) is required")
	}
	inst, err := reg.Installer(installerName)
	if err != nil {
		return err
	}
	enhancer, ok := inst.(plugins.Enhancer)
	if !ok {
		return fmt.Errorf("enhance: installer %q does not support enhancements", installerName)
	}
	var asks []string
	if cfg.HSTS {
		asks = append(asks, plugins.EnhanceHSTS)
	}
	if cfg.UIR {
		asks = append(asks, plugins.EnhanceUIR)
	}
	if cfg.Staple {
		asks = append(asks, plugins.EnhanceStaple)
	}
	if err := enhancer.Enhance(ctx, cfg, domains, asks); err != nil {
		return err
	}
	fmt.Printf("Applied %v to %v via %s.\n", asks, domains, installerName)
	return nil
}

// helper to keep this file using config.Config + plugins.Registry symbols
// in case of unused-import drift.
var _ = config.SourceDefault
