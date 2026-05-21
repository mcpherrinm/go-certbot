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

// ChallengeKind identifies which ACME challenge a plugin solves.
type ChallengeKind int

const (
	HTTP01 ChallengeKind = iota
	DNS01
)

func (c ChallengeKind) String() string {
	switch c {
	case HTTP01:
		return "http-01"
	case DNS01:
		return "dns-01"
	}
	return "unknown"
}

// Authenticator solves an ACME challenge for the given domains.
//
// Prepare returns the kind of challenge the plugin solves along with a lego
// challenge.Provider. The client uses the kind to call SetHTTP01Provider or
// SetDNS01Provider on the lego client.
//
// Cleanup is called after Obtain returns (success or failure). It must not
// fail loudly — best-effort.
type Authenticator interface {
	Name() string
	Description() string
	Prepare(ctx context.Context, cfg *config.Config, domains []string) (ChallengeKind, challenge.Provider, error)
	Cleanup(ctx context.Context) error
}

// Installer takes a freshly issued cert and installs it into a web server.
type Installer interface {
	Name() string
	Description() string
	Install(ctx context.Context, cfg *config.Config, domains []string, fullchainPath, privkeyPath string) error
}

// Enhancement names supported by Enhance.
const (
	EnhanceHSTS     = "hsts"     // Strict-Transport-Security
	EnhanceUIR      = "uir"      // Content-Security-Policy: upgrade-insecure-requests
	EnhanceStaple   = "staple"   // OCSP stapling
	EnhanceRedirect = "redirect" // HTTP→HTTPS redirect
)

// Enhancer is implemented by installers that can apply security enhancements
// (HSTS, OCSP stapling, upgrade-insecure-requests) to existing managed
// vhosts. nginx and apache implement this; null does not.
type Enhancer interface {
	Enhance(ctx context.Context, cfg *config.Config, domains []string, enhancements []string) error
}
