package verbs

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/letsencrypt/go-certbot/internal/account"
	"github.com/letsencrypt/go-certbot/internal/client"
	"github.com/letsencrypt/go-certbot/internal/config"
)

// ariDecision returns a non-nil time only if the ACME server's RFC 9773
// renewalInfo endpoint says we should defer renewal until later. An error or
// (nil, nil) means "no ARI hint; fall back to renew_before_expiry".
//
// The implementation is intentionally tolerant: anything other than a
// definitive "renew at <future time>" response → return nil and let the
// caller decide via the static window.
func ariDecision(ctx context.Context, cfg *config.Config, leafPath string) (*time.Time, error) {
	b, err := os.ReadFile(leafPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("ari: empty PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	accountsDir, err := cfg.AccountsDir()
	if err != nil {
		return nil, err
	}
	store := &account.FileStorage{AccountsDir: accountsDir, StrictPermissions: cfg.StrictPermissions}
	acc, err := loadOrCreateAccount(cfg, store)
	if err != nil {
		return nil, err
	}
	c, err := client.New(cfg, acc)
	if err != nil {
		return nil, err
	}
	info, err := c.RenewalInfo(ctx, leaf)
	if err != nil || info == nil {
		return nil, err
	}
	// Use a 0 willingToSleep so ShouldRenewAt either returns "now" or a
	// future time. We treat "now" (i.e. <= time.Now()) as "renew" and a
	// future time as "wait".
	due := info.ShouldRenewAt(time.Now(), 0)
	return due, nil
}
