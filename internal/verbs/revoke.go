package verbs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/letsencrypt/go-certbot/internal/account"
	"github.com/letsencrypt/go-certbot/internal/client"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/display"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

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
		// Pin server + account to the issuing CA. Without this, revoking a
		// cert that was issued by a non-default CA fails with "unrecognized
		// account". Matches Certbot main.py:1355-1378 (reconstitute fills
		// server/account from the lineage before _determine_account).
		if v := conf.RenewalParams["server"]; v != "" && !cfg.SetByUser("server") {
			cfg.Server = v
		}
		if v := conf.RenewalParams["account"]; v != "" && !cfg.SetByUser("account") {
			cfg.Account = v
		}
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("revoke: read %s: %w", certPath, err)
	}
	reason := uint(cfg.Reason)

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
	// was passed.
	if cfg.CertName != "" {
		var doDelete bool
		switch {
		case cfg.SetByUser("delete-after-revoke"):
			doDelete = cfg.DeleteAfterRevoke
		case cfg.SetByUser("no-delete-after-revoke"):
			doDelete = false
		case cfg.NonInteractive:
			// Certbot errors out in non-interactive mode if neither flag
			// was passed (main.py:788-791 uses force_interactive=True).
			return errors.New("revoke: --delete-after-revoke or --no-delete-after-revoke must be set in non-interactive mode")
		default:
			doDelete = display.YesNoDefault(
				"Would you like to delete the certificate(s) you just revoked, along with all earlier and later versions of the certificate?",
				true)
		}
		if doDelete {
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
