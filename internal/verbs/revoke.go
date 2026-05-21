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
	} else if cfg.CertName == "" {
		// --cert-path was given without --cert-name. Walk renewal confs
		// to find a lineage that owns this cert path so the post-revoke
		// delete prompt (when not suppressed) targets the right
		// lineage. Mirrors certbot cert_manager.cert_path_to_lineage
		// (main.py:799-801). Silently skip on lookup failure — the
		// revoke itself still proceeds against the cert bytes.
		if name := certPathToLineage(cfg, certPath); name != "" {
			cfg.CertName = name
			// Also pin server + account from the resolved lineage.
			if conf, err := renewalconf.Load(filepath.Join(cfg.RenewalConfigsDir(), name+".conf")); err == nil {
				if v := conf.RenewalParams["server"]; v != "" && !cfg.SetByUser("server") {
					cfg.Server = v
				}
				if v := conf.RenewalParams["account"]; v != "" && !cfg.SetByUser("account") {
					cfg.Account = v
				}
			}
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
	// was passed. In non-interactive mode the prompt's default is
	// returned, so the default behavior is to DELETE — matches
	// certbot integration test_revoke_simple which expects
	// `revoke --cert-path X --delete-after-revoke` AND
	// `revoke --cert-path X` (no flag) to both delete by default.
	if cfg.CertName != "" {
		var doDelete bool
		switch {
		case cfg.SetByUser("delete-after-revoke"):
			doDelete = cfg.DeleteAfterRevoke
		case cfg.SetByUser("no-delete-after-revoke"):
			doDelete = false
		case cfg.NonInteractive:
			// certbot's display_util.yesno returns the default (True)
			// in non-interactive mode; mirror by defaulting to delete.
			doDelete = true
		default:
			doDelete = display.YesNoDefault(
				"Would you like to delete the certificate(s) you just revoked, along with all earlier and later versions of the certificate?",
				true)
		}
		if doDelete {
			if hasOverlappingArchiveDir(cfg, cfg.CertName) {
				fmt.Fprintf(os.Stderr,
					"Not deleting revoked certificates due to overlapping archive dirs. "+
						"More than one certificate is using %s\n",
					archiveDirFor(cfg, cfg.CertName))
				return nil
			}
			return Delete(ctx, cfg, reg)
		}
	}
	return nil
}

// certPathToLineage returns the lineage name (renewal-conf basename without
// the `.conf` suffix) whose `cert` or `fullchain` top-level key matches
// targetPath. Empty when nothing matches. Mirrors certbot
// cert_manager.cert_path_to_lineage which scans renewal confs by file path.
func certPathToLineage(cfg *config.Config, targetPath string) string {
	abs, err := filepath.Abs(targetPath)
	if err != nil {
		abs = targetPath
	}
	entries, err := os.ReadDir(cfg.RenewalConfigsDir())
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".conf")
		conf, err := renewalconf.Load(filepath.Join(cfg.RenewalConfigsDir(), e.Name()))
		if err != nil {
			continue
		}
		for _, key := range []string{"cert", "fullchain"} {
			if p := conf.Top[key]; p != "" {
				if pa, err := filepath.Abs(p); err == nil && pa == abs {
					return name
				}
				if p == targetPath {
					return name
				}
			}
		}
	}
	return ""
}

// hasOverlappingArchiveDir returns true iff any renewal conf OTHER than
// certName points at the same archive_dir. Mirrors certbot's pre-delete
// safety check in main.revoke (main.py:802-815): without this, revoking a
// cert whose renewal conf was hand-copied or shares archive_dir with
// another lineage would delete files still referenced by the sibling.
func hasOverlappingArchiveDir(cfg *config.Config, certName string) bool {
	if certName == "" {
		return false
	}
	target := archiveDirFor(cfg, certName)
	if target == "" {
		return false
	}
	entries, err := os.ReadDir(cfg.RenewalConfigsDir())
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		otherName := strings.TrimSuffix(e.Name(), ".conf")
		if otherName == certName {
			continue
		}
		if archiveDirFor(cfg, otherName) == target {
			return true
		}
	}
	return false
}

// archiveDirFor reads renewal/<certName>.conf and returns the archive_dir
// top-level key. Returns "" on any error so callers fail-open (treat as
// no overlap detected).
func archiveDirFor(cfg *config.Config, certName string) string {
	conf, err := renewalconf.Load(filepath.Join(cfg.RenewalConfigsDir(), certName+".conf"))
	if err != nil {
		return ""
	}
	return conf.Top["archive_dir"]
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
