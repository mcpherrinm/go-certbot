// Package dnsimple wraps lego's dnsimple DNS-01 provider.
// Credentials keys: dns_dnsimple_token = ...
package dnsimple

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/dnsimple"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator                                 { return &Authenticator{} }
func (a *Authenticator) Name() string                     { return "dns-dnsimple" }
func (a *Authenticator) Description() string              { return "Obtain certificates using a DNS TXT record via the DNSimple API." }
func (a *Authenticator) Cleanup(_ context.Context) error  { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "dnsimple"), "dns_dnsimple")
	if err != nil {
		return 0, nil, err
	}
	if err := cred.Required("token"); err != nil {
		return 0, nil, err
	}
	_ = cred.SetEnv("token", "DNSIMPLE_OAUTH_TOKEN")
	common.PropagationEnv("DNSIMPLE_", common.PropagationFor(cfg, "dnsimple", 30))
	p, err := dnsimple.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("dnsimple: %w", err)
	}
	return common.PluginKind, p, nil
}
