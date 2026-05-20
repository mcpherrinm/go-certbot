// Package plugins defines the authenticator/installer interfaces and the
// compiled-in registry. Mirrors certbot.interfaces.Authenticator/Installer in
// shape, minus the abstractions tied to Python plugin discovery — plugins here
// are registered at compile time.
package plugins

import (
	"context"

	"github.com/go-acme/lego/v5/challenge"

	"github.com/letsencrypt/go-certbot/internal/config"
)

// Authenticator solves an ACME challenge for the given domains.
//
// PrepareHTTP01 returns a lego challenge.Provider that should be installed via
// client.Challenge.SetHTTP01Provider before calling Obtain. Authenticators
// that don't support http-01 return ErrUnsupportedChallenge.
//
// Cleanup is called after Obtain returns (success or failure). It must not
// fail loudly — best-effort.
type Authenticator interface {
	Name() string
	Description() string
	// PrepareHTTP01 returns a lego http-01 provider. Domains are passed for
	// plugins (like webroot) that need them up front.
	PrepareHTTP01(ctx context.Context, cfg *config.Config, domains []string) (challenge.Provider, error)
	// Cleanup releases any resources held by the authenticator (e.g. stop
	// listeners). Idempotent.
	Cleanup(ctx context.Context) error
}

// Installer takes a freshly issued cert and installs it into a web server.
// Phase 1 ships a null installer; nginx and apache come later.
type Installer interface {
	Name() string
	Description() string
	Install(ctx context.Context, cfg *config.Config, domains []string, fullchainPath, privkeyPath string) error
}
