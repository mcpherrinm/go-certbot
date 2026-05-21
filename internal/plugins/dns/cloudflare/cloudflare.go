// Package cloudflare wraps lego's cloudflare DNS-01 provider as a
// go-certbot authenticator. Reads --dns-cloudflare-credentials in Certbot's
// dns_common INI format.
//
// Credentials keys (any one form accepted, matching certbot-dns-cloudflare):
//
//	dns_cloudflare_api_token = ...                # preferred (scoped token)
//	dns_cloudflare_email = ...                    # legacy
//	dns_cloudflare_api_key = ...                  # legacy
package cloudflare

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator { return &Authenticator{} }

func (a *Authenticator) Name() string { return "dns-cloudflare" }
func (a *Authenticator) Description() string {
	return "Obtain certificates using a DNS TXT record via the Cloudflare API."
}
func (a *Authenticator) Cleanup(_ context.Context) error { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "cloudflare"), "dns_cloudflare")
	if err != nil {
		return 0, nil, err
	}
	hasToken := cred.Get("api_token") != ""
	hasLegacy := cred.Get("email") != "" || cred.Get("api_key") != ""
	if hasToken && hasLegacy {
		// Matches certbot-dns-cloudflare's _validate_credentials: rejecting
		// both forms at once prevents accidental fallback to the wrong one.
		return 0, nil, fmt.Errorf("cloudflare: set dns_cloudflare_api_token OR (dns_cloudflare_email + dns_cloudflare_api_key), not both")
	}
	if hasToken {
		_ = cred.SetEnv("api_token", "CLOUDFLARE_DNS_API_TOKEN")
	} else {
		if err := cred.Required("email", "api_key"); err != nil {
			return 0, nil, fmt.Errorf("cloudflare: need api_token OR (email + api_key); %w", err)
		}
		_ = cred.SetEnv("email", "CLOUDFLARE_EMAIL")
		_ = cred.SetEnv("api_key", "CLOUDFLARE_API_KEY")
	}
	common.PropagationEnv("CLOUDFLARE_", common.PropagationFor(cfg, "cloudflare", 10))
	p, err := cloudflare.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("cloudflare: %w", err)
	}
	return common.PluginKind, p, nil
}
