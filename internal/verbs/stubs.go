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

// Plugins prints the registered authenticator and installer plugins. Mirrors
// certbot/_internal/main.plugins_cmd output (the human-readable side; the
// `--init`/`--prepare` flags are no-ops since plugins lazy-init on use).
func Plugins(_ context.Context, _ *config.Config, reg *plugins.Registry) error {
	fmt.Println("Authenticators:")
	for _, a := range reg.Authenticators() {
		fmt.Printf("  %s\n    %s\n", a.Name(), a.Description())
	}
	fmt.Println()
	fmt.Println("Installers:")
	for _, i := range reg.Installers() {
		fmt.Printf("  %s\n    %s\n", i.Name(), i.Description())
	}
	return nil
}

