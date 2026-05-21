package verbs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

// Install installs an existing certificate into a web server without running
// an ACME order. Requires:
//
//   - --cert-name: install the lineage's live/ symlinks; OR
//   - --cert-path + --key-path: install arbitrary paths.
//
// Plus an installer plugin (--nginx / --apache / --installer).
func Install(ctx context.Context, cfg *config.Config, reg *plugins.Registry) error {
	installerName := cfg.Installer
	if cfg.Nginx {
		installerName = "nginx"
	}
	if cfg.Apache {
		installerName = "apache"
	}

	var fullchainPath, privkeyPath string
	domains := cfg.Domains

	// Prompt for cert-name if neither --cert-name nor --cert-path was set
	// and we're interactive. Matches main.py:_install_cert's
	// _get_certbot_config_filename interactive path.
	if cfg.CertName == "" && cfg.CertPath == "" {
		name, err := chooseCertName(cfg, "install")
		if err != nil {
			return err
		}
		cfg.CertName = name
	}

	switch {
	case cfg.CertPath != "" && cfg.KeyPath != "":
		fullchainPath = cfg.CertPath
		privkeyPath = cfg.KeyPath
	case cfg.CertName != "":
		conf, err := renewalconf.Load(filepath.Join(cfg.RenewalConfigsDir(), cfg.CertName+".conf"))
		if err != nil {
			return err
		}
		fullchainPath = conf.Top["fullchain"]
		privkeyPath = conf.Top["privkey"]
		if fullchainPath == "" || privkeyPath == "" {
			return fmt.Errorf("install: renewal conf %s.conf missing fullchain/privkey", cfg.CertName)
		}
		if len(domains) == 0 {
			if list, ok := conf.List("domains"); ok {
				domains = list
			}
		}
		if installerName == "" {
			installerName = conf.RenewalParams["installer"]
		}
	default:
		return errors.New("install: pass --cert-name OR (--cert-path + --key-path)")
	}

	if installerName == "" || installerName == "None" {
		return errors.New("install: --installer (or --nginx / --apache) is required")
	}
	if len(domains) == 0 {
		return errors.New("install: --domain is required when not using --cert-name")
	}
	// Pre-flight check: certbot main._check_certificate_and_key (main.py:1166)
	// resolves both paths and fails early if either file is missing — gives
	// users a clear error before nginx/apache attempts to parse a non-existent
	// PEM. Mirror the wording verbatim so scripts grepping for the certbot
	// error keep working.
	if _, err := os.Stat(fullchainPath); err != nil {
		return fmt.Errorf("Error while reading certificate from path %s", fullchainPath)
	}
	if _, err := os.Stat(privkeyPath); err != nil {
		return fmt.Errorf("Error while reading private key from path %s", privkeyPath)
	}
	inst, err := reg.Installer(installerName)
	if err != nil {
		return err
	}
	if err := inst.Install(ctx, cfg, domains, fullchainPath, privkeyPath); err != nil {
		return err
	}
	fmt.Printf("Installed %s via %s for %v.\n", fullchainPath, installerName, domains)
	return nil
}
