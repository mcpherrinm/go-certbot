// Package verbs implements Certbot's subcommand handlers. Phase 1 only
// implements certonly; other verbs return a "not implemented in this phase"
// error so the CLI surface stays consistent.
package verbs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/letsencrypt/go-certbot/internal/account"
	"github.com/letsencrypt/go-certbot/internal/client"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
)

// Certonly obtains a new certificate (no installation).
func Certonly(ctx context.Context, cfg *config.Config, reg *plugins.Registry) error {
	if len(cfg.Domains) == 0 && cfg.CSR == "" {
		return errors.New("certonly: at least one -d/--domain is required")
	}
	if cfg.CSR != "" {
		return errors.New("certonly: --csr issuance is not yet implemented (Phase 1)")
	}
	if cfg.Apache || cfg.Nginx {
		return errors.New("certonly: --apache and --nginx installers are not yet implemented (Phase 1)")
	}
	if cfg.Webroot || cfg.Manual {
		return errors.New("certonly: --webroot and --manual are not yet implemented (Phase 1); use --standalone")
	}
	if !cfg.Standalone && cfg.Authenticator == "" {
		return errors.New("certonly: --standalone (or --authenticator standalone) is required in Phase 1")
	}
	if cfg.Authenticator != "" && cfg.Authenticator != "standalone" {
		return fmt.Errorf("certonly: authenticator %q is not yet implemented (Phase 1)", cfg.Authenticator)
	}

	certName := cfg.CertName
	if certName == "" {
		certName = cfg.Domains[0]
	}

	// Load or create an account.
	accountsDir, err := cfg.AccountsDir()
	if err != nil {
		return err
	}
	storage := &account.FileStorage{
		AccountsDir:       accountsDir,
		StrictPermissions: cfg.StrictPermissions,
	}
	acc, err := loadOrCreateAccount(cfg, storage)
	if err != nil {
		return err
	}

	c, err := client.New(cfg, acc)
	if err != nil {
		return err
	}
	if err := c.EnsureRegistered(ctx, storage); err != nil {
		return err
	}

	auth, err := reg.Authenticator("standalone")
	if err != nil {
		return err
	}

	slog.Info("requesting certificate",
		"domains", cfg.Domains,
		"cert_name", certName,
		"server", cfg.EffectiveServer())

	lineage, err := c.Obtain(ctx, auth, cfg.Domains, certName)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully obtained certificate for %v\n", cfg.Domains)
	fmt.Printf("  cert:      %s\n", lineage.Live.Cert)
	fmt.Printf("  privkey:   %s\n", lineage.Live.Privkey)
	fmt.Printf("  chain:     %s\n", lineage.Live.Chain)
	fmt.Printf("  fullchain: %s\n", lineage.Live.Fullchain)
	return nil
}

func loadOrCreateAccount(cfg *config.Config, storage *account.FileStorage) (*account.Account, error) {
	if cfg.Account != "" {
		return storage.Load(cfg.Account)
	}
	existing, err := storage.FindAll()
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		return existing[0], nil
	}
	key, err := account.NewKey(cfg.KeyType, cfg.RSAKeySize)
	if err != nil {
		return nil, err
	}
	pub, err := account.PublicKey(key)
	if err != nil {
		return nil, err
	}
	id, err := account.ComputeID(pub)
	if err != nil {
		return nil, err
	}
	acc := &account.Account{ID: id, Key: key}
	return acc, nil
}
