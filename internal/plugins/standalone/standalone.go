// Package standalone wraps lego's http01.ProviderServer as a Certbot-style
// authenticator. Honors --http-01-port and --http-01-address.
package standalone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/http01"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
)

type Authenticator struct {
	server *http01.ProviderServer
}

func New() *Authenticator { return &Authenticator{} }

func (a *Authenticator) Name() string { return "standalone" }
func (a *Authenticator) Description() string {
	return "Runs an HTTP server locally which serves the necessary validation files."
}

// Prepare starts an in-process HTTP server bound to the configured address
// and port that responds to /.well-known/acme-challenge/ requests. On
// startup we eagerly bind once to surface EACCES (running unprivileged on
// :80) or EADDRINUSE (another service is bound) with helpful messages
// matching Certbot's standalone._handle_perform_error (standalone.py:189-206).
func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	port := cfg.HTTP01Port
	if port <= 0 {
		port = 80
	}
	addr := cfg.HTTP01Address
	if err := preflightBind(addr, port); err != nil {
		return 0, nil, err
	}
	a.server = http01.NewProviderServer(addr, strconv.Itoa(port))
	if a.server == nil {
		return 0, nil, fmt.Errorf("standalone: failed to create http-01 provider on %s:%d", addr, port)
	}
	return plugins.HTTP01, a.server, nil
}

// preflightBind opens then closes a TCP listener on the address+port we'll
// hand to lego. Lets us emit standalone-style error messages on bind
// failure rather than the opaque errors lego surfaces later.
func preflightBind(addr string, port int) error {
	host := addr
	if host == "" {
		host = "0.0.0.0"
	}
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		if isPermission(err) {
			return fmt.Errorf("standalone: cannot bind %s:%d — permission denied. Standalone often needs root for port 80; pass --http-01-port or run with sudo.", host, port)
		}
		if isAddrInUse(err) {
			return fmt.Errorf("standalone: cannot bind %s:%d — address already in use. Stop the running web server (or pass --apache/--nginx to use it) and retry.", host, port)
		}
		return fmt.Errorf("standalone: bind %s:%d: %w", host, port, err)
	}
	_ = l.Close()
	return nil
}

func isPermission(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}

// Cleanup is a no-op: lego stops the ProviderServer in its CleanUp.
func (a *Authenticator) Cleanup(_ context.Context) error { return nil }
