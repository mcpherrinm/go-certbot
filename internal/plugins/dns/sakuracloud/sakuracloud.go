// Package sakuracloud wraps lego's sakuracloud DNS-01 provider.
// Credentials keys:
//
//	dns_sakuracloud_api_token = ...
//	dns_sakuracloud_api_secret = ...
package sakuracloud

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/sakuracloud"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator             { return &Authenticator{} }
func (a *Authenticator) Name() string { return "dns-sakuracloud" }
func (a *Authenticator) Description() string {
	return "Obtain certificates using a DNS TXT record via the Sakura Cloud API."
}
func (a *Authenticator) Cleanup(_ context.Context) error { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "sakuracloud"), "dns_sakuracloud")
	if err != nil {
		return 0, nil, err
	}
	if err := cred.Required("api_token", "api_secret"); err != nil {
		return 0, nil, err
	}
	_ = cred.SetEnv("api_token", "SAKURACLOUD_ACCESS_TOKEN")
	_ = cred.SetEnv("api_secret", "SAKURACLOUD_ACCESS_TOKEN_SECRET")
	common.PropagationEnv("SAKURACLOUD_", common.PropagationFor(cfg, "sakuracloud", 90))
	p, err := sakuracloud.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("sakuracloud: %w", err)
	}
	return common.PluginKind, p, nil
}
