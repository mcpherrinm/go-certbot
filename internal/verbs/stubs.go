package verbs

import (
	"context"
	"fmt"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
)

// notImplemented returns an error explaining which later phase will implement
// a given verb. Used by all non-certonly verbs in Phase 1.
func notImplemented(verb, phase string) error {
	return fmt.Errorf("%s: not implemented in Phase 1; planned for %s", verb, phase)
}

func Run(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("run", "Phase 1 final (requires installer)")
}

func Renew(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("renew", "Phase 2")
}

func Certificates(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("certificates", "Phase 3")
}

func Delete(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("delete", "Phase 3")
}

func Revoke(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("revoke", "Phase 3")
}

func Register(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("register", "Phase 3")
}

func Unregister(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("unregister", "Phase 3")
}

func UpdateAccount(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("update_account", "Phase 3")
}

func ShowAccount(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("show_account", "Phase 3")
}

func Install(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("install", "Phase 5 (nginx) / Phase 6 (apache)")
}

func Enhance(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("enhance", "Phase 5 (nginx) / Phase 6 (apache)")
}

func Rollback(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("rollback", "Phase 5 (nginx) / Phase 6 (apache)")
}

func Plugins(_ context.Context, _ *config.Config, reg *plugins.Registry) error {
	fmt.Println("Built-in authenticators:")
	for _, a := range reg.Authenticators() {
		fmt.Printf("  %s — %s\n", a.Name(), a.Description())
	}
	fmt.Println("Built-in installers:")
	if len(reg.Installers()) == 0 {
		fmt.Println("  (none — nginx/apache land in Phase 5/6)")
	}
	for _, i := range reg.Installers() {
		fmt.Printf("  %s — %s\n", i.Name(), i.Description())
	}
	return nil
}

func Reconfigure(_ context.Context, _ *config.Config, _ *plugins.Registry) error {
	return notImplemented("reconfigure", "Phase 2")
}
