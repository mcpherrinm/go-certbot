package verbs

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"

	"github.com/letsencrypt/go-certbot/internal/checkpoint"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
)

// Rollback reverts the most recent N config-file changes go-certbot made.
// Defaults to 1 if --checkpoints is unset. Reloads the web server after, if
// possible.
func Rollback(ctx context.Context, cfg *config.Config, _ *plugins.Registry) error {
	n := cfg.RollbackCheckpoints
	if n <= 0 {
		n = 1
	}
	changed, err := checkpoint.Restore(cfg.WorkDir, n)
	if err != nil {
		return err
	}
	if len(changed) == 0 {
		fmt.Println("rollback: nothing changed.")
		return nil
	}
	fmt.Printf("Restored %d file(s):\n", len(changed))
	for _, p := range changed {
		fmt.Println("  " + p)
	}

	// Try to reload the relevant web server. We don't always know which one
	// was modified, so try nginx then apache; failures are best-effort.
	reloadIfAvailable(ctx, cfg)
	return nil
}

// reloadIfAvailable tries `nginx -s reload` and `apachectl graceful`. We only
// reload servers whose control binary is on PATH; failures are logged and
// not fatal.
func reloadIfAvailable(ctx context.Context, cfg *config.Config) {
	nginxCtl := cfg.NginxCtl
	if nginxCtl == "" {
		nginxCtl = "nginx"
	}
	if _, err := exec.LookPath(nginxCtl); err == nil {
		if err := exec.CommandContext(ctx, nginxCtl, "-t").Run(); err == nil {
			if err := exec.CommandContext(ctx, nginxCtl, "-s", "reload").Run(); err != nil {
				slog.Warn("nginx reload after rollback failed", "err", err)
			}
		}
	}
	apacheCtl := cfg.ApacheCtl
	if apacheCtl == "" {
		apacheCtl = "apachectl"
	}
	if _, err := exec.LookPath(apacheCtl); err == nil {
		if err := exec.CommandContext(ctx, apacheCtl, "configtest").Run(); err == nil {
			if err := exec.CommandContext(ctx, apacheCtl, "graceful").Run(); err != nil {
				slog.Warn("apachectl graceful after rollback failed", "err", err)
			}
		}
	}
}
