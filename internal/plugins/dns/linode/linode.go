// Package linode wraps lego's linode DNS-01 provider.
// Credentials keys: dns_linode_key = ...
package linode

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/linode"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator                                 { return &Authenticator{} }
func (a *Authenticator) Name() string                     { return "dns-linode" }
func (a *Authenticator) Description() string              { return "Obtain certificates using a DNS TXT record via the Linode API." }
func (a *Authenticator) Cleanup(_ context.Context) error  { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	cred, err := common.LoadCredentials(common.CredentialsFor(cfg, "linode"), "dns_linode")
	if err != nil {
		return 0, nil, err
	}
	if err := cred.Required("key"); err != nil {
		return 0, nil, err
	}
	_ = cred.SetEnv("key", "LINODE_TOKEN")
	common.PropagationEnv("LINODE_", common.PropagationFor(cfg, "linode"))
	p, err := linode.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("linode: %w", err)
	}
	return common.PluginKind, p, nil
}
