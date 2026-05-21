// Package digitalocean wraps lego's digitalocean DNS-01 provider.
// Credentials keys:
//
//	dns_digitalocean_token = ...
package digitalocean

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/digitalocean"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator                                 { return &Authenticator{} }
func (a *Authenticator) Name() string                     { return "dns-digitalocean" }
func (a *Authenticator) Description() string              { return "Obtain certificates using a DNS TXT record via the DigitalOcean API." }
func (a *Authenticator) Cleanup(_ context.Context) error  { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "digitalocean"), "dns_digitalocean")
	if err != nil {
		return 0, nil, err
	}
	if err := cred.Required("token"); err != nil {
		return 0, nil, err
	}
	_ = cred.SetEnv("token", "DO_AUTH_TOKEN")
	common.PropagationEnv("DO_", common.PropagationFor(cfg, "digitalocean"))
	p, err := digitalocean.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("digitalocean: %w", err)
	}
	return common.PluginKind, p, nil
}
