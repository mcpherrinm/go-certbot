// Package manual implements Certbot's --manual plugin. Users supply
// --manual-auth-hook and --manual-cleanup-hook scripts that publish/remove the
// http-01 file or dns-01 TXT record. The plugin is the bridge that lets a
// third-party DNS provider keep working with go-certbot — write a hook script
// that calls your favorite tool.
//
// Environment passed to hooks (matches certbot/_internal/plugins/manual.py:188):
//
//	CERTBOT_DOMAIN              the domain being authenticated
//	CERTBOT_VALIDATION          keyAuth (http-01) / sha256-of-keyAuth (dns-01)
//	CERTBOT_TOKEN               http-01 challenge token (http-01 only)
//	CERTBOT_AUTH_OUTPUT         stdout of the auth script, passed to cleanup
//	CERTBOT_ALL_DOMAINS         space-separated list of all domains in the order
//	CERTBOT_REMAINING_CHALLENGES count of remaining challenges (for batched cleanup)
//	CERTBOT_IDENTIFIER          alias for CERTBOT_DOMAIN (used by ACME v2)
//	CERTBOT_ALL_IDENTIFIERS     alias for CERTBOT_ALL_DOMAINS
package manual

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-acme/lego/v5/challenge"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/hooks"
	"github.com/letsencrypt/go-certbot/internal/plugins"
)

// Authenticator backs --manual.
type Authenticator struct {
	authHook    string
	cleanupHook string
	allDomains  []string
	remaining   atomic.Int64

	mu          sync.Mutex
	authOutputs map[string]string // domain → stdout of auth hook, for cleanup env
}

func New() *Authenticator { return &Authenticator{authOutputs: map[string]string{}} }

func (a *Authenticator) Name() string { return "manual" }
func (a *Authenticator) Description() string {
	return "Manual configuration or running of shell scripts to fulfill ACME challenges."
}

// Prepare returns the plugin acting as a lego challenge.Provider for whichever
// challenge type the user picked. Defaults to http-01 unless
// --preferred-challenges=dns-01 is set, matching Certbot's behavior for
// --manual. The domain list is captured so Present/CleanUp can emit
// CERTBOT_ALL_DOMAINS / CERTBOT_REMAINING_CHALLENGES.
func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, domains []string) (plugins.ChallengeKind, challenge.Provider, error) {
	if cfg.ManualAuthHook == "" {
		return 0, nil, errors.New("manual: --manual-auth-hook is required (interactive mode is not yet implemented)")
	}
	a.authHook = cfg.ManualAuthHook
	a.cleanupHook = cfg.ManualCleanupHook
	a.allDomains = append([]string(nil), domains...)
	a.remaining.Store(int64(len(domains)))
	kind := plugins.HTTP01
	for _, c := range cfg.PreferredChallenges {
		if c == "dns-01" || c == "dns" {
			kind = plugins.DNS01
			break
		}
	}
	return kind, a, nil
}

func (a *Authenticator) Cleanup(_ context.Context) error { return nil }

// Present runs the auth hook for the given domain. The hook publishes the
// challenge response somewhere reachable by the CA (e.g. drop the http-01
// file in a webroot, or update a DNS TXT record).
func (a *Authenticator) Present(ctx context.Context, domain, token, keyAuth string) error {
	env := a.baseEnv(domain, keyAuth, token)
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

	env := a.baseEnv(domain, keyAuth, token)
	env = append(env, "CERTBOT_AUTH_OUTPUT="+authOutput)
	// Decrement remaining now that we're cleaning this one up. After Present
	// for N domains we'll do N CleanUps; the env var counts down so hooks
	// know when they're on the last call.
	a.remaining.Add(-1)
	if err := hooks.Run(ctx, a.cleanupHook, env); err != nil {
		fmt.Fprintf(os.Stderr, "manual: cleanup hook for %s failed: %v\n", domain, err)
	}
	return nil
}

func (a *Authenticator) baseEnv(domain, keyAuth, token string) []string {
	all := strings.Join(a.allDomains, " ")
	env := []string{
		"CERTBOT_DOMAIN=" + domain,
		"CERTBOT_IDENTIFIER=" + domain,
		"CERTBOT_VALIDATION=" + keyAuth,
		"CERTBOT_ALL_DOMAINS=" + all,
		"CERTBOT_ALL_IDENTIFIERS=" + all,
		"CERTBOT_REMAINING_CHALLENGES=" + strconv.FormatInt(a.remaining.Load(), 10),
	}
	if token != "" {
		env = append(env, "CERTBOT_TOKEN="+token)
	}
	return env
}
