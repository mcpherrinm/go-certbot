// Package google wraps lego's Google Cloud DNS provider as a go-certbot
// authenticator named "dns-google" (matching Certbot, despite lego's package
// being gcloud).
//
// Unlike Certbot's other DNS plugins this one's credentials flag points at a
// service-account JSON file directly, not at an INI. Translation:
//
//	--dns-google-credentials /path/to/sa.json  →  GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
package google

import (
	"context"
	"fmt"
	"os"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/gcloud"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/plugins/dns/common"
)

type Authenticator struct{}

func New() *Authenticator                                 { return &Authenticator{} }
func (a *Authenticator) Name() string                     { return "dns-google" }
func (a *Authenticator) Description() string              { return "Obtain certificates using a DNS TXT record via the Google Cloud DNS API." }
func (a *Authenticator) Cleanup(_ context.Context) error  { return nil }

func (a *Authenticator) Prepare(_ context.Context, cfg *config.Config, _ []string) (plugins.ChallengeKind, challenge.Provider, error) {
	path := common.CredentialsFor(cfg, "google")
	if path == "" {
		// Allow Application Default Credentials on GCE/GKE — lego will pick
		// them up if no explicit creds are set. Document in CHANGES.md as a
		// behavior difference vs Certbot, which requires the JSON path.
		fmt.Fprintln(os.Stderr,
			"dns-google: no --dns-google-credentials; falling back to Application Default Credentials")
	} else {
		if _, err := os.Stat(path); err != nil {
			return 0, nil, fmt.Errorf("dns-google: %s: %w", path, err)
		}
		_ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
	}
	common.PropagationEnv("GCE_", common.PropagationFor(cfg, "google", 60))
	p, err := gcloud.NewDNSProvider()
	if err != nil {
		return 0, nil, fmt.Errorf("dns-google: %w", err)
	}
	return common.PluginKind, p, nil
}
