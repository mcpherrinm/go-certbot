// Package standalone wraps lego's http01.ProviderServer as a Certbot-style
// authenticator. Honors --http-01-port and --http-01-address.
package standalone

import (
	"context"
	"fmt"
	"strconv"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/http01"

	"github.com/letsencrypt/go-certbot/internal/config"
)

type Authenticator struct {
	server *http01.ProviderServer
}

func New() *Authenticator {
	return &Authenticator{}
}

func (a *Authenticator) Name() string { return "standalone" }
func (a *Authenticator) Description() string {
	return "Runs an HTTP server locally which serves the necessary validation files."
}

// PrepareHTTP01 starts an in-process HTTP server bound to the configured
// address and port that responds to /.well-known/acme-challenge/ requests.
func (a *Authenticator) PrepareHTTP01(_ context.Context, cfg *config.Config, _ []string) (challenge.Provider, error) {
	port := cfg.HTTP01Port
	if port <= 0 {
		port = 80
	}
	addr := cfg.HTTP01Address // "" = all interfaces (lego default)
	a.server = http01.NewProviderServer(addr, strconv.Itoa(port))
	if a.server == nil {
		return nil, fmt.Errorf("standalone: failed to create http-01 provider on %s:%d", addr, port)
	}
	return a.server, nil
}

// Cleanup is a no-op: lego stops the ProviderServer in its CleanUp.
func (a *Authenticator) Cleanup(_ context.Context) error { return nil }
