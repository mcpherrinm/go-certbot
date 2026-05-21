// Package ovh wraps lego's ovh DNS-01 provider.
// Credentials keys:
//
//	dns_ovh_endpoint = ovh-eu
//	dns_ovh_application_key = ...
//	dns_ovh_application_secret = ...
//	dns_ovh_consumer_key = ...
package ovh

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/ovh"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator             { return &Authenticator{} }
func (a *Authenticator) Name() string { return "dns-ovh" }
func (a *Authenticator) Description() string {
	return "Obtain certificates using a DNS TXT record via the OVH API."
}
func (a *Authenticator) Cleanup(_ context.Context) error { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "ovh"), "dns_ovh")
	if err != nil {
		return 0, nil, err
	}
	if err := cred.Required("endpoint", "application_key", "application_secret", "consumer_key"); err != nil {
		return 0, nil, err
	}
	_ = cred.SetEnv("endpoint", "OVH_ENDPOINT")
	_ = cred.SetEnv("application_key", "OVH_APPLICATION_KEY")
	_ = cred.SetEnv("application_secret", "OVH_APPLICATION_SECRET")
	_ = cred.SetEnv("consumer_key", "OVH_CONSUMER_KEY")
	common.PropagationEnv("OVH_", common.PropagationFor(cfg, "ovh", 120))
	p, err := ovh.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("ovh: %w", err)
	}
	return common.PluginKind, p, nil
}
