// Package nsone wraps lego's ns1 DNS-01 provider as a go-certbot
// authenticator named "dns-nsone" (matching Certbot, despite lego's package
// being ns1).
// Credentials keys: dns_nsone_api_key = ...
package nsone

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/ns1"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator                                 { return &Authenticator{} }
func (a *Authenticator) Name() string                     { return "dns-nsone" }
func (a *Authenticator) Description() string              { return "Obtain certificates using a DNS TXT record via the NS1 API." }
func (a *Authenticator) Cleanup(_ context.Context) error  { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "nsone"), "dns_nsone")
	if err != nil {
		return 0, nil, err
	}
	if err := cred.Required("api_key"); err != nil {
		return 0, nil, err
	}
	_ = cred.SetEnv("api_key", "NS1_API_KEY")
	common.PropagationEnv("NS1_", common.PropagationFor(cfg, "nsone"))
	p, err := ns1.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("dns-nsone: %w", err)
	}
	return common.PluginKind, p, nil
}
