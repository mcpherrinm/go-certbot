// Package manual implements Certbot's --manual plugin. Users supply
// --manual-auth-hook and --manual-cleanup-hook scripts that publish/remove the
// http-01 file or dns-01 TXT record. The plugin is the bridge that lets a
// third-party DNS provider keep working with go-certbot — write a hook script
// that calls your favorite tool.
//
// Environment passed to hooks (matches certbot/_internal/plugins/manual.py:188):
//
//	CERTBOT_DOMAIN        the domain being authenticated
//	CERTBOT_VALIDATION    keyAuth (http-01) / sha256-of-keyAuth (dns-01)
//	CERTBOT_TOKEN         the http-01 challenge token (http-01 only; unset for dns-01)
//	CERTBOT_AUTH_OUTPUT   stdout of the auth script, passed to cleanup
package manual

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/go-acme/lego/v5/challenge"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/hooks"
)

// Authenticator backs --manual.
type Authenticator struct {
	authHook    string
	cleanupHook string

	mu          sync.Mutex
	authOutputs map[string]string // domain → stdout of auth hook, for cleanup env
}

func New() *Authenticator { return &Authenticator{authOutputs: map[string]string{}} }

func (a *Authenticator) Name() string        { return "manual" }
func (a *Authenticator) Description() string { return "Manual configuration or running of shell scripts to fulfill ACME challenges." }

// PrepareHTTP01 returns the plugin acting as a lego http-01 challenge.Provider.
// The same plugin also services dns-01 via a separate code path (not yet wired
// because Phase 2 doesn't introduce DNS challenges into go-certbot; lego's
// dns-01 path is reached automatically when the only configured provider is
// us — Phase 4 will revisit when DNS plugins ship).
func (a *Authenticator) PrepareHTTP01(_ context.Context, cfg *config.Config, _ []string) (challenge.Provider, error) {
	if cfg.ManualAuthHook == "" {
		return nil, errors.New("manual: --manual-auth-hook is required (interactive mode is not yet implemented in Phase 2)")
	}
	a.authHook = cfg.ManualAuthHook
	a.cleanupHook = cfg.ManualCleanupHook
	return a, nil
}

func (a *Authenticator) Cleanup(_ context.Context) error { return nil }

// Present runs the auth hook for the given domain. The hook is expected to
// publish the challenge response somewhere reachable by the CA (e.g. drop the
// http-01 file in a webroot, or update a DNS TXT record).
func (a *Authenticator) Present(ctx context.Context, domain, token, keyAuth string) error {
	env := []string{
		"CERTBOT_DOMAIN=" + domain,
		"CERTBOT_VALIDATION=" + keyAuth,
	}
	if token != "" {
		env = append(env, "CERTBOT_TOKEN="+token)
	}
	out, err := hooks.RunCapture(ctx, a.authHook, env)
	if err != nil {
		return fmt.Errorf("manual: auth hook for %s: %w", domain, err)
	}
	a.mu.Lock()
	a.authOutputs[domain] = out
	a.mu.Unlock()
	return nil
}

// CleanUp runs the cleanup hook for the given domain.
func (a *Authenticator) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	if a.cleanupHook == "" {
		return nil
	}
	a.mu.Lock()
	authOutput := a.authOutputs[domain]
	delete(a.authOutputs, domain)
	a.mu.Unlock()

	env := []string{
		"CERTBOT_DOMAIN=" + domain,
		"CERTBOT_VALIDATION=" + keyAuth,
		"CERTBOT_AUTH_OUTPUT=" + authOutput,
	}
	if token != "" {
		env = append(env, "CERTBOT_TOKEN="+token)
	}
	if err := hooks.Run(ctx, a.cleanupHook, env); err != nil {
		// Match Certbot: cleanup failures are logged but don't abort.
		fmt.Fprintf(os.Stderr, "manual: cleanup hook for %s failed: %v\n", domain, err)
	}
	return nil
}
