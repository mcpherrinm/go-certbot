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
	"github.com/letsencrypt/go-certbot/internal/display"
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
	for {
		err := preflightBind(addr, port)
		if err == nil {
			break
		}
		if isAddrInUse(err) && !cfg.NonInteractive {
			// Certbot's standalone prompts the user to retry on
			// EADDRINUSE (standalone.py:196-204). Default No so a
			// non-attended terminal doesn't loop forever.
			if display.YesNoDefault("Please stop the server using "+
				portLabel(addr, port)+
				" before pressing Enter, or choose Cancel. Retry?", false) {
				continue
			}
		}
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
		// Match Certbot's ASCII-only error wording so scripts grepping
		// stderr for these phrases keep working (standalone.py:189-201).
		if isPermission(err) {
			return fmt.Errorf("standalone: could not bind TCP port %d because you don't have the appropriate permissions (for example, you aren't running this program as root).", port)
		}
		if isAddrInUse(err) {
			return fmt.Errorf("standalone: could not bind TCP port %d because it is already in use by another process on this system (such as a web server). Please stop the program in question and then try again.", port)
		}
		return fmt.Errorf("standalone: bind %s:%d: %w", host, port, err)
	}
	_ = l.Close()
	return nil
}

func portLabel(addr string, port int) string {
	if addr == "" {
		return fmt.Sprintf("port %d", port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

func isPermission(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}

// Cleanup is a no-op: lego stops the ProviderServer in its CleanUp.
func (a *Authenticator) Cleanup(_ context.Context) error { return nil }
