// Package luadns wraps lego's luadns DNS-01 provider.
// Credentials keys:
//
//	dns_luadns_email = ...
//	dns_luadns_token = ...
package luadns

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/luadns"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator                                 { return &Authenticator{} }
func (a *Authenticator) Name() string                     { return "dns-luadns" }
func (a *Authenticator) Description() string              { return "Obtain certificates using a DNS TXT record via the LuaDNS API." }
func (a *Authenticator) Cleanup(_ context.Context) error  { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "luadns"), "dns_luadns")
	if err != nil {
		return 0, nil, err
	}
	if err := cred.Required("email", "token"); err != nil {
		return 0, nil, err
	}
	_ = cred.SetEnv("email", "LUADNS_API_USERNAME")
	_ = cred.SetEnv("token", "LUADNS_API_TOKEN")
	common.PropagationEnv("LUADNS_", common.PropagationFor(cfg, "luadns"))
	p, err := luadns.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("luadns: %w", err)
	}
	return common.PluginKind, p, nil
}
