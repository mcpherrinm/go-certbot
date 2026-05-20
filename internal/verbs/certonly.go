// Package verbs implements Certbot's subcommand handlers.
package verbs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/letsencrypt/go-certbot/internal/account"
	"github.com/letsencrypt/go-certbot/internal/client"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/eff"
	"github.com/letsencrypt/go-certbot/internal/hooks"
	"github.com/letsencrypt/go-certbot/internal/plugins"
)

// Certonly obtains a new certificate (no installation).
func Certonly(ctx context.Context, cfg *config.Config, reg *plugins.Registry) error {
	if len(cfg.Domains) == 0 && cfg.CSR == "" {
		return errors.New("certonly: at least one -d/--domain is required")
	}
	if cfg.CSR != "" {
		return errors.New("certonly: --csr issuance is not yet implemented")
	}
	if cfg.Apache || cfg.Nginx {
		return errors.New("certonly: --apache and --nginx installers are not yet implemented")
	}

	authName, err := resolveAuthenticatorName(cfg)
	if err != nil {
		return err
	}

	if !cfg.DisableHookValidation {
		for _, h := range []struct{ cmd, label string }{
			{cfg.PreHook, "pre"},
			{cfg.PostHook, "post"},
			{cfg.DeployHook, "deploy"},
		} {
			if err := hooks.Validate(h.cmd, h.label); err != nil {
				return err
			}
		}
	}

	certName := cfg.CertName
	if certName == "" {
		certName = cfg.Domains[0]
	}

	// pre_hook runs before challenge work; post_hook always runs after.
	if err := hooks.Run(ctx, cfg.PreHook, nil); err != nil {
		return err
	}
	if err := hooks.RunDir(ctx, cfg.HookDir("pre"), nil); err != nil {
		return err
	}
	defer func() {
		_ = hooks.Run(ctx, cfg.PostHook, nil)
		_ = hooks.RunDir(ctx, cfg.HookDir("post"), nil)
	}()

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

	auth, err := reg.Authenticator(authName)
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

	// deploy_hook runs only on success, with RENEWED_LINEAGE / RENEWED_DOMAINS.
	env := hooks.DeployEnv(filepath.Dir(lineage.Live.Cert), cfg.Domains)
	if err := hooks.Run(ctx, cfg.DeployHook, env); err != nil {
		slog.Warn("deploy_hook failed", "err", err)
	}
	if err := hooks.RunDir(ctx, cfg.HookDir("deploy"), env); err != nil {
		slog.Warn("deploy-hook directory failed", "err", err)
	}

	// EFF subscription (only for fresh accounts, only if user opted in).
	if cfg.EFFEmailExplicit && cfg.Email != "" && !cfg.DryRun {
		if err := eff.Subscribe(ctx, cfg.Email); err != nil {
			slog.Warn("EFF subscribe failed", "err", err)
		}
	}
	return nil
}

// resolveAuthenticatorName chooses the authenticator plugin name from the
// flag soup. Mirrors Certbot's plugin_selection.choose_configurator_plugins
// for the certonly path.
func resolveAuthenticatorName(cfg *config.Config) (string, error) {
	if cfg.Authenticator != "" {
		return cfg.Authenticator, nil
	}
	count := 0
	picked := ""
	for name, on := range map[string]bool{
		"standalone": cfg.Standalone,
		"webroot":    cfg.Webroot,
		"manual":     cfg.Manual,
	} {
		if on {
			count++
			picked = name
		}
	}
	for name, on := range cfg.DNSSelected {
		if on {
			count++
			picked = "dns-" + name
		}
	}
	if count > 1 {
		return "", errors.New("certonly: more than one authenticator selected; pick one of --standalone/--webroot/--manual/--dns-*")
	}
	if count == 0 {
		return "", errors.New("certonly: an authenticator is required (--standalone / --webroot / --manual / --dns-* / --authenticator)")
	}
	return picked, nil
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
