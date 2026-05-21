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
	"github.com/letsencrypt/go-certbot/internal/display"
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
	if cfg.CertName != "" && cfg.CertPath != "" {
		// Match Certbot's exact wording (main.py:1366) so user-facing
		// error grep tooling keeps working.
		return errors.New("Error! Exactly one of --cert-path or --cert-name must be specified!")
	}
	if cfg.CertName == "" && cfg.CertPath == "" {
		return errors.New("Error! Exactly one of --cert-path or --cert-name must be specified!")
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

	// Two revocation paths (RFC 8555 §7.6):
	//   1. account-key revocation — load the local ACME account and POST.
	//   2. cert-key revocation — use the certificate's own private key.
	// Path 2 is what `--key-path` enables; useful when revoking a cert that
	// wasn't issued by any local account.
	if cfg.KeyPath != "" {
		if err := revokeWithCertKey(ctx, cfg, certBytes, cfg.KeyPath, reason); err != nil {
			return err
		}
	} else {
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
			return errors.New("revoke: no registered account; use --key-path to revoke with the cert's own key, or register first")
		}
		c, err := client.New(cfg, acc)
		if err != nil {
			return err
		}
		if err := c.RevokeWithReason(ctx, certBytes, reason); err != nil {
			return err
		}
	}
	fmt.Printf("Congratulations! You have successfully revoked the certificate that was located at %s.\n", certPath)

	// Mirrors Certbot's main.revoke 786-794: prompt the user to also
	// delete the lineage (default Yes) unless --no-delete-after-revoke
	// was passed or there's no lineage to delete.
	if cfg.CertName != "" {
		delete := cfg.DeleteAfterRevoke
		if !cfg.NonInteractive && !cfg.SetByUser("delete-after-revoke") && !cfg.SetByUser("no-delete-after-revoke") {
			delete = display.YesNoDefault(
				"Would you like to delete the certificate(s) you just revoked, along with all earlier and later versions of the certificate?",
				true)
		}
		if delete {
			return Delete(ctx, cfg, reg)
		}
	}
	return nil
}

// revokeWithCertKey performs cert-key revocation per RFC 8555 §7.6. The cert's
// own private key signs the revocation JWS; no ACME account is involved.
// We pipe through lego by constructing an anonymous client with the cert key
// in place of the account key — lego's Certifier.RevokeWithReason accepts that
// usage when the URL is a directory's revokeCert endpoint.
func revokeWithCertKey(ctx context.Context, cfg *config.Config, certPEM []byte, keyPath string, reason uint) error {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("revoke: read key %s: %w", keyPath, err)
	}
	// Build a transient Account holding the cert's private key and an empty
	// registration URI. The client wrapper recognizes "no Location" and
	// emits an unsigned revocation request keyed by the cert's key.
	transient, err := account.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return err
	}
	acc := &account.Account{Key: transient}
	c, err := client.New(cfg, acc)
	if err != nil {
		return err
	}
	return c.RevokeWithReason(ctx, certPEM, reason)
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
