package apache

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/extenv"
)

// ensureModules makes sure each requested apache module is loaded. On Debian
// it shells out to `a2enmod`; on RHEL/Alpine (where modules are normally
// already loaded via `LoadModule` in /etc/httpd/conf.modules.d) we just
// check with `apachectl -M` and warn if missing.
//
// `apachectl configtest` would fail with "Invalid command 'SSLEngine'" or
// "Invalid command 'Header'" on a fresh apache install when mod_ssl /
// mod_headers / mod_rewrite aren't enabled. Match Certbot's
// prepare_https_modules behavior.
func ensureModules(ctx context.Context, cfg *config.Config, want []string) error {
	ctl := apacheCtl(cfg)
	loaded, err := loadedModules(ctx, ctl)
	if err != nil {
		// `apachectl -M` failing usually means apache isn't installed yet;
		// don't escalate — the configtest after our write will catch it
		// with a clearer error.
		slog.Warn("apache: cannot list loaded modules; skipping a2enmod", "err", err)
		return nil
	}
	var missing []string
	for _, m := range want {
		key := strings.TrimSuffix(m, "_module")
		full := key + "_module"
		if !loaded[full] {
			missing = append(missing, key)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	opts := detectOSOptions()
	if opts.A2EnMod == "" {
		// Non-Debian: we can't safely run a2enmod. Surface a warning so the
		// configtest failure that follows is easier to debug.
		slog.Warn("apache: required modules not loaded — load them in /etc/httpd/conf.modules.d/ or pass --apache-config to a layout with them",
			"missing", missing)
		return nil
	}
	args := append([]string{}, missing...)
	a2cmd := exec.CommandContext(ctx, opts.A2EnMod, args...)
	a2cmd.Env = extenv.Env()
	out, err := a2cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apache: `%s %v` failed: %w\n%s", opts.A2EnMod, args, err, string(out))
	}
	slog.Info("apache: enabled modules", "modules", missing)
	return nil
}

// loadedModules parses `apachectl -M` (or `httpd -M`) output into a set
// like {"ssl_module": true, "headers_module": true}.
func loadedModules(ctx context.Context, ctl string) (map[string]bool, error) {
	listCmd := exec.CommandContext(ctx, ctl, "-M")
	listCmd.Env = extenv.Env()
	out, err := listCmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	loaded := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		// Lines look like "  ssl_module (shared)" or "  ssl_module (static)".
		name := f[0]
		if strings.HasSuffix(name, "_module") {
			loaded[name] = true
		}
	}
	return loaded, nil
}
