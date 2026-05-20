package verbs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/letsencrypt/go-certbot/internal/account"
	"github.com/letsencrypt/go-certbot/internal/client"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

// revocationReasons maps the human-readable values Certbot accepts to RFC 5280
// codes. Matches certbot._internal.constants.REVOCATION_REASONS.
var revocationReasons = map[string]uint{
	"unspecified":          0,
	"keycompromise":        1,
	"affiliationchanged":   3,
	"superseded":           4,
	"cessationofoperation": 5,
}

// Revoke revokes a certificate via ACME and (optionally) deletes its lineage.
//
// One of --cert-name or --cert-path must be specified. With --cert-name we
// look up the lineage's fullchain; with --cert-path the user supplies the PEM
// directly.
func Revoke(ctx context.Context, cfg *config.Config, reg *plugins.Registry) error {
	if cfg.CertName == "" && cfg.CertPath == "" {
		return errors.New("revoke: --cert-name or --cert-path is required")
	}
	certPath := cfg.CertPath
	if certPath == "" {
		conf, err := renewalconf.Load(filepath.Join(cfg.RenewalConfigsDir(), cfg.CertName+".conf"))
		if err != nil {
			return err
		}
		certPath = conf.Top["fullchain"]
		if certPath == "" {
			return fmt.Errorf("revoke: renewal conf for %q has no fullchain path", cfg.CertName)
		}
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("revoke: read %s: %w", certPath, err)
	}
	reason, err := lookupReason(cfg.Reason)
	if err != nil {
		return err
	}

	accountsDir, err := cfg.AccountsDir()
	if err != nil {
		return err
	}
	store := &account.FileStorage{
		AccountsDir:       accountsDir,
		StrictPermissions: cfg.StrictPermissions,
	}
	acc, err := loadOrCreateAccount(cfg, store)
	if err != nil {
		return err
	}
	if acc.Registration.URI == "" {
		return errors.New("revoke: no registered account; nothing to revoke as")
	}
	c, err := client.New(cfg, acc)
	if err != nil {
		return err
	}
	if err := c.RevokeWithReason(ctx, certBytes, reason); err != nil {
		return err
	}
	fmt.Printf("Revoked certificate at %s\n", certPath)

	if cfg.CertName != "" && cfg.DeleteAfterRevoke {
		// Reuse Delete logic to also remove on-disk state.
		return Delete(ctx, cfg, reg)
	}
	return nil
}

func lookupReason(name string) (uint, error) {
	if name == "" {
		return 0, nil
	}
	v, ok := revocationReasons[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		valid := make([]string, 0, len(revocationReasons))
		for k := range revocationReasons {
			valid = append(valid, k)
		}
		return 0, fmt.Errorf("revoke: unknown --reason %q (valid: %s)",
			name, strings.Join(valid, ", "))
	}
	return v, nil
}
