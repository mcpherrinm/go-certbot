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

// Run obtains a cert and installs it. The default verb. Picks an authenticator
// + installer plugin pair from flags (e.g. --nginx sets both to nginx), runs
// the issuance, then installs.
func Run(ctx context.Context, cfg *config.Config, reg *plugins.Registry) error {
	if len(cfg.Domains) == 0 && len(cfg.IPAddresses) == 0 {
		return errors.New("run: at least one -d/--domain is required")
	}
	// IP-address-only certs can't be installed by nginx/apache — neither
	// plugin's installer flow knows how to match an IP SAN to a vhost. Match
	// certbot main.run (main.py:1438-1440) and reject upfront with the same
	// wording so users get a clear error instead of a confusing later one.
	if len(cfg.Domains) == 0 && len(cfg.IPAddresses) > 0 {
		return errors.New("run: installation of IP address certificates is not currently supported. Use the `certonly` command instead.")
	}

	authName, instName, err := resolveRunPlugins(cfg)
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

	if err := hooks.Run(ctx, cfg.PreHook, nil); err != nil {
		return err
	}
	if err := hooks.RunDirIf(ctx, cfg.DirectoryHooks, cfg.HookDir("pre"), nil, cfg.PreHook); err != nil {
		return err
	}
	var renewedDomains []string
	defer func() {
		// post-hook gets RENEWED_DOMAINS / FAILED_DOMAINS env. For run /
		// certonly the FAILED list is always empty per Certbot
		// hooks.py:post_hook 145.
		env := hooks.PostEnv(renewedDomains, nil)
		_ = hooks.Run(ctx, cfg.PostHook, env)
		_ = hooks.RunDirIf(ctx, cfg.DirectoryHooks, cfg.HookDir("post"), env, cfg.PostHook)
	}()

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
	c, err := client.New(cfg, acc)
	if err != nil {
		return err
	}
	if err := c.EnsureRegistered(ctx, store); err != nil {
		return err
	}

	auth, err := reg.Authenticator(authName)
	if err != nil {
		return err
	}
	slog.Info("requesting certificate", "domains", cfg.Domains, "cert_name", certName,
		"authenticator", authName, "installer", instName, "server", cfg.EffectiveServer())
	lineage, err := c.Obtain(ctx, auth, cfg.Domains, certName)
	if err != nil {
		return err
	}
	renewedDomains = append([]string(nil), cfg.Domains...)

	// Install.
	if instName != "" && instName != "null" {
		inst, err := reg.Installer(instName)
		if err != nil {
			return err
		}
		if err := inst.Install(ctx, cfg, cfg.Domains, lineage.Live.Fullchain, lineage.Live.Privkey); err != nil {
			return err
		}
		fmt.Printf("Installed certificate for %v with %s.\n", cfg.Domains, instName)
	}

	env := hooks.DeployEnv(filepath.Dir(lineage.Live.Cert), cfg.Domains)
	if err := hooks.Run(ctx, cfg.DeployHook, env); err != nil {
		slog.Warn("deploy_hook failed", "err", err)
	}
	if err := hooks.RunDirIf(ctx, cfg.DirectoryHooks, cfg.HookDir("deploy"), env, cfg.DeployHook); err != nil {
		slog.Warn("deploy-hook directory failed", "err", err)
	}

	if !cfg.DryRun && eff.Decide(cfg) {
		_ = eff.Subscribe(ctx, cfg.Email)
	}
	return nil
}

// resolveRunPlugins picks (authenticator, installer) names. Order:
//   - explicit --authenticator / --installer wins
//   - --configurator (a plugin that's both) sets both
//   - --nginx / --apache sets both to the same name
//   - otherwise an error: `run` requires an installer
func resolveRunPlugins(cfg *config.Config) (string, string, error) {
	if cfg.Configurator != "" {
		return cfg.Configurator, cfg.Configurator, nil
	}
	auth := cfg.Authenticator
	inst := cfg.Installer
	if cfg.Nginx {
		if auth == "" {
			auth = "nginx"
		}
		if inst == "" {
			inst = "nginx"
		}
	}
	if cfg.Apache {
		if auth == "" {
			auth = "apache"
		}
		if inst == "" {
			inst = "apache"
		}
	}
	if auth == "" {
		return "", "", errors.New("run: choose an authenticator (--nginx / --apache / --standalone+--installer / --authenticator <name>)")
	}
	if inst == "" {
		return "", "", fmt.Errorf("run: authenticator %q selected without an installer; use --installer or `certonly`", auth)
	}
	return auth, inst, nil
}
