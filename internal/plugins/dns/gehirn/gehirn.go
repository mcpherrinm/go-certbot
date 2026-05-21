// Package gehirn wraps lego's gehirn DNS-01 provider.
// Credentials keys:
//
//	dns_gehirn_api_token = ...
//	dns_gehirn_api_secret = ...
package gehirn

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/gehirn"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator             { return &Authenticator{} }
func (a *Authenticator) Name() string { return "dns-gehirn" }
func (a *Authenticator) Description() string {
	return "Obtain certificates using a DNS TXT record via the Gehirn DNS API."
}
func (a *Authenticator) Cleanup(_ context.Context) error { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "gehirn"), "dns_gehirn")
	if err != nil {
		return 0, nil, err
	}
	if err := cred.Required("api_token", "api_secret"); err != nil {
		return 0, nil, err
	}
	// lego v5's gehirn provider expects GEHIRN_TOKEN_ID / GEHIRN_TOKEN_SECRET
	// (not API_TOKEN / API_SECRET). See lego providers/dns/gehirn/gehirn.go:23-24.
	_ = cred.SetEnv("api_token", "GEHIRN_TOKEN_ID")
	_ = cred.SetEnv("api_secret", "GEHIRN_TOKEN_SECRET")
	common.PropagationEnv("GEHIRN_", common.PropagationFor(cfg, "gehirn", 30))
	p, err := gehirn.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("gehirn: %w", err)
	}
	return common.PluginKind, p, nil
}
