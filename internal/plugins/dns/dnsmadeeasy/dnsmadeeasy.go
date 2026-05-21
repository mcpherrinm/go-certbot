// Package dnsmadeeasy wraps lego's dnsmadeeasy DNS-01 provider.
// Credentials keys:
//
//	dns_dnsmadeeasy_api_key = ...
//	dns_dnsmadeeasy_secret_key = ...
package dnsmadeeasy

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/dnsmadeeasy"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator             { return &Authenticator{} }
func (a *Authenticator) Name() string { return "dns-dnsmadeeasy" }
func (a *Authenticator) Description() string {
	return "Obtain certificates using a DNS TXT record via the DNS Made Easy API."
}
func (a *Authenticator) Cleanup(_ context.Context) error { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "dnsmadeeasy"), "dns_dnsmadeeasy")
	if err != nil {
		return 0, nil, err
	}
	if err := cred.Required("api_key", "secret_key"); err != nil {
		return 0, nil, err
	}
	_ = cred.SetEnv("api_key", "DNSMADEEASY_API_KEY")
	_ = cred.SetEnv("secret_key", "DNSMADEEASY_API_SECRET")
	common.PropagationEnv("DNSMADEEASY_", common.PropagationFor(cfg, "dnsmadeeasy", 60))
	p, err := dnsmadeeasy.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("dnsmadeeasy: %w", err)
	}
	return common.PluginKind, p, nil
}
