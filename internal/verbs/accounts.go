package verbs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/letsencrypt/go-certbot/internal/account"
	"github.com/letsencrypt/go-certbot/internal/client"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
)

// Register creates and registers a fresh ACME account. Errors if --email is
// missing (use --register-unsafely-without-email to bypass) or --agree-tos
// is missing. EAB is honored if --eab-kid and --eab-hmac-key are set.
func Register(ctx context.Context, cfg *config.Config, _ *plugins.Registry) error {
	if !cfg.TOS {
		return errors.New("register: --agree-tos is required")
	}
	if cfg.Email == "" && !cfg.RegisterUnsafelyWithoutEmail {
		return errors.New("register: --email is required (or --register-unsafely-without-email)")
	}

	accountsDir, err := cfg.AccountsDir()
	if err != nil {
		return err
	}
	store := &account.FileStorage{
		AccountsDir:       accountsDir,
		StrictPermissions: cfg.StrictPermissions,
	}
	// Reject if an account already exists for this server unless --account
	// matches what's there.
	existing, err := store.FindAll()
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		// Match Certbot's behavior: register doesn't overwrite. Tell the user.
		fmt.Printf("Account already registered at %s (id=%s)\n",
			existing[0].Registration.URI, existing[0].ID)
		return nil
	}
	key, err := account.NewKey(cfg.KeyType, cfg.RSAKeySize)
	if err != nil {
		return err
	}
	pub, err := account.PublicKey(key)
	if err != nil {
		return err
	}
	id, err := account.ComputeID(pub)
	if err != nil {
		return err
	}
	acc := &account.Account{ID: id, Key: key}

	c, err := client.New(cfg, acc)
	if err != nil {
		return err
	}
	if err := c.EnsureRegistered(ctx, store); err != nil {
		return err
	}
	fmt.Printf("Registered account at %s (id=%s)\n", acc.Registration.URI, acc.ID)
	return nil
}

// ShowAccount prints the current account's details.
func ShowAccount(_ context.Context, cfg *config.Config, _ *plugins.Registry) error {
	store, acc, err := loadAccountOrFail(cfg)
	if err != nil {
		return err
	}
	_ = store
	fmt.Printf("Account id: %s\n", acc.ID)
	fmt.Printf("Account URL: %s\n", acc.Registration.URI)
	contacts := acc.Contact
	if len(contacts) > 0 {
		fmt.Printf("Email contact: %s\n", strings.Join(contacts, ", "))
	} else {
		fmt.Println("Email contact: (none)")
	}
	if acc.Meta.CreationHost != "" {
		fmt.Printf("Created on: %s at %s\n", acc.Meta.CreationHost, acc.Meta.CreationDT.Format("2006-01-02"))
	}
	return nil
}

// UpdateAccount updates the contact email for the current account.
func UpdateAccount(ctx context.Context, cfg *config.Config, _ *plugins.Registry) error {
	if cfg.Email == "" && !cfg.RegisterUnsafelyWithoutEmail {
		return errors.New("update_account: --email is required (or --register-unsafely-without-email to clear)")
	}
	store, acc, err := loadAccountOrFail(cfg)
	if err != nil {
		return err
	}
	c, err := client.New(cfg, acc)
	if err != nil {
		return err
	}
	if err := c.UpdateAccount(ctx, cfg.Email); err != nil {
		return err
	}
	// Update on-disk contact.
	if cfg.Email != "" {
		acc.Contact = []string{"mailto:" + cfg.Email}
	} else {
		acc.Contact = nil
	}
	if err := store.Save(acc); err != nil {
		return err
	}
	fmt.Println("Account updated.")
	return nil
}

// Unregister deactivates the current account at the ACME server and removes
// the on-disk account directory.
func Unregister(ctx context.Context, cfg *config.Config, _ *plugins.Registry) error {
	store, acc, err := loadAccountOrFail(cfg)
	if err != nil {
		return err
	}
	c, err := client.New(cfg, acc)
	if err != nil {
		return err
	}
	if err := c.DeactivateAccount(ctx); err != nil {
		return err
	}
	// Remove the account dir locally. Other accounts (if any) survive.
	if err := os.RemoveAll(store.AccountsDir + string(os.PathSeparator) + acc.ID); err != nil {
		return fmt.Errorf("unregister: remove %s: %w", acc.ID, err)
	}
	fmt.Printf("Unregistered account %s\n", acc.ID)
	return nil
}

// loadAccountOrFail finds the (only) account; errors if there isn't exactly one
// to act on.
func loadAccountOrFail(cfg *config.Config) (*account.FileStorage, *account.Account, error) {
	dir, err := cfg.AccountsDir()
	if err != nil {
		return nil, nil, err
	}
	store := &account.FileStorage{
		AccountsDir:       dir,
		StrictPermissions: cfg.StrictPermissions,
	}
	if cfg.Account != "" {
		acc, err := store.Load(cfg.Account)
		return store, acc, err
	}
	all, err := store.FindAll()
	if err != nil {
		return nil, nil, err
	}
	switch len(all) {
	case 0:
		return store, nil, fmt.Errorf("no accounts registered at %s", dir)
	case 1:
		return store, all[0], nil
	}
	return store, nil, fmt.Errorf("multiple accounts registered at %s; pass --account=<id>", dir)
}
