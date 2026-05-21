package verbs

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/letsencrypt/go-certbot/internal/account"
	"github.com/letsencrypt/go-certbot/internal/client"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/display"
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
		if cfg.NonInteractive {
			return errors.New("register: --email is required (or --register-unsafely-without-email)")
		}
		// Certbot's display_ops.get_email (display/ops.py:35) accepts an
		// empty line as "skip"; we mirror by switching into
		// register-unsafely-without-email mode if the user hits enter.
		cfg.Email = display.Email("Enter email address or hit Enter to skip:")
		if cfg.Email == "" {
			cfg.RegisterUnsafelyWithoutEmail = true
		}
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
		// Match Certbot main.register: error out rather than silently
		// succeed when an account already exists.
		return fmt.Errorf("register: there is an existing account; use update_account or unregister first (existing URL: %s)",
			existing[0].Registration.URI)
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
	fmt.Println("Account registered.")
	return nil
}

// ShowAccount prints the current account's details. Format matches
// certbot main.show_account: a header line then indented fields.
func ShowAccount(_ context.Context, cfg *config.Config, _ *plugins.Registry) error {
	store, acc, err := loadAccountOrFail(cfg)
	if err != nil {
		return err
	}
	_ = store
	fmt.Printf("Account details for server %s:\n", cfg.EffectiveServer())
	fmt.Printf("  Account URL: %s\n", acc.Registration.URI)
	thumb, _ := accountThumbprint(acc)
	if thumb != "" {
		fmt.Printf("  Account Thumbprint: %s\n", thumb)
	}
	// Strip the "mailto:" URI prefix before display.
	stripped := make([]string, 0, len(acc.Contact))
	for _, c := range acc.Contact {
		stripped = append(stripped, strings.TrimPrefix(c, "mailto:"))
	}
	label := "Email contact"
	if len(stripped) > 1 {
		label = "Email contacts"
	}
	if len(stripped) > 0 {
		fmt.Printf("  %s: %s\n", label, strings.Join(stripped, ", "))
	} else {
		fmt.Printf("  %s: (none)\n", label)
	}
	return nil
}

// accountThumbprint returns the JWK thumbprint of the account key matching
// certbot's show_account output. Certbot uses Python's `base64.b64encode`
// (STANDARD base64, not RFC 7638's base64url) on the raw SHA-256 of the
// canonical JSON form (main.py:1013). RFC 7638 says base64url, but certbot
// historically doesn't follow that — we mirror certbot so byte-for-byte
// show_account output stays identical across the two tools.
func accountThumbprint(acc *account.Account) (string, error) {
	canon, err := account.JWKThumbprintCanonical(acc.Key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// UpdateAccount updates the contact email for the current account.
// Prompts interactively for --email when missing (unless --non-interactive).
func UpdateAccount(ctx context.Context, cfg *config.Config, _ *plugins.Registry) error {
	if cfg.Email == "" && !cfg.RegisterUnsafelyWithoutEmail {
		if cfg.NonInteractive {
			return errors.New("update_account: --email is required (or --register-unsafely-without-email to clear)")
		}
		cfg.Email = display.Email("Enter the new contact email:")
		if cfg.Email == "" {
			return errors.New("update_account: --email is required")
		}
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
	// Update on-disk contact. Certbot splits comma-separated emails into
	// one mailto: each (main.py:960).
	if cfg.Email != "" {
		acc.Contact = nil
		for _, e := range strings.Split(cfg.Email, ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				acc.Contact = append(acc.Contact, "mailto:"+e)
			}
		}
	} else {
		acc.Contact = nil
	}
	if err := store.UpdateRegistration(acc); err != nil {
		return err
	}
	if cfg.Email != "" {
		fmt.Printf("Your e-mail address was updated to %s.\n", cfg.Email)
	} else {
		fmt.Println("Any contact information associated with this account has been removed.")
	}
	return nil
}

// Unregister deactivates the current account at the ACME server and removes
// the on-disk account directory. Prompts unless --non-interactive.
func Unregister(ctx context.Context, cfg *config.Config, _ *plugins.Registry) error {
	store, acc, err := loadAccountOrFail(cfg)
	if err != nil {
		return err
	}
	if !cfg.NonInteractive {
		fmt.Fprintf(os.Stderr,
			"You are about to deactivate account %s at %s. After this, the\n"+
				"account key can no longer be used for new orders and the account is\n"+
				"effectively destroyed.\n",
			acc.ID, cfg.EffectiveServer())
		// Certbot defaults Yes on this prompt (main.py:872-892).
		if !display.YesNoDefault("Are you sure you would like to deactivate this account?", true) {
			fmt.Println("unregister: aborted by user.")
			return nil
		}
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
	// Best-effort: rmdir the empty server parent dir so a re-registered
	// account against a different server doesn't see a stale empty tree.
	// Matches account.py:_delete_links_and_find_target_dir 280-294.
	_ = os.Remove(store.AccountsDir)
	fmt.Printf("Account deactivated.\n")
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
