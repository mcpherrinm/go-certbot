package verbs

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/letsencrypt/go-certbot/internal/account"
	"github.com/letsencrypt/go-certbot/internal/client"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

// ariErrorCooldown is the time Certbot caches an ARI-fetch failure for
// before retrying. Matches renewal.py:378-388 (6 hours).
const ariErrorCooldown = 6 * time.Hour

// ariDecision returns a non-nil time only if the ACME server's RFC 9773
// renewalInfo endpoint says we should defer renewal until later. An error or
// (nil, nil) means "no ARI hint; fall back to renew_before_expiry".
//
// The implementation honors a previously-cached ari_retry_after stored in
// the renewal conf's [acme_renewal_info] section, and persists either a
// server-supplied retry time or — on error — a 6-hour cooldown. ARI is
// always fetched from the lineage's server (the issuing CA), regardless of
// the CLI --server, mirroring Certbot (renewal.py:367-376).
func ariDecision(ctx context.Context, cfg *config.Config, conf *renewalconf.File, confPath, leafPath string) (*time.Time, error) {
	// Honor a cached retry-after; only refresh the ARI hint once the cache
	// expires.
	if cached := readARIRetryAfter(conf); cached != nil && cached.After(time.Now()) {
		slog.Debug("ARI cache still valid", "retry_after", cached.Format(time.RFC3339))
		due := *cached
		return &due, nil
	}
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
	// Force the ACME directory URL to the lineage's server even if --server
	// was user-set, so ARI hits the CA that issued the cert.
	server := conf.RenewalParams["server"]
	if server == "" {
		server = cfg.EffectiveServer()
	}
	ariCfg := *cfg
	ariCfg.Server = server
	accountsDir, err := ariCfg.AccountsDir()
	if err != nil {
		return nil, err
	}
	store := &account.FileStorage{AccountsDir: accountsDir, StrictPermissions: ariCfg.StrictPermissions}
	acc, err := loadOrCreateAccount(&ariCfg, store)
	if err != nil {
		writeARIRetryAfter(conf, confPath, time.Now().Add(ariErrorCooldown))
		return nil, err
	}
	c, err := client.New(&ariCfg, acc)
	if err != nil {
		writeARIRetryAfter(conf, confPath, time.Now().Add(ariErrorCooldown))
		return nil, err
	}
	info, err := c.RenewalInfo(ctx, leaf)
	if err != nil {
		writeARIRetryAfter(conf, confPath, time.Now().Add(ariErrorCooldown))
		return nil, err
	}
	if info == nil {
		return nil, nil
	}
	// Use a 0 willingToSleep so ShouldRenewAt either returns "now" or a
	// future time. We treat "now" (i.e. <= time.Now()) as "renew" and a
	// future time as "wait".
	due := info.ShouldRenewAt(time.Now(), 0)
	if due != nil {
		writeARIRetryAfter(conf, confPath, *due)
	}
	return due, nil
}

func readARIRetryAfter(conf *renewalconf.File) *time.Time {
	if conf == nil {
		return nil
	}
	sec, ok := conf.Sections["acme_renewal_info"]
	if !ok {
		return nil
	}
	raw, ok := sec["ari_retry_after"]
	if !ok || raw == "" {
		return nil
	}
	// Certbot writes the timestamp via Python's datetime.isoformat(
	// timespec="seconds") on a NAIVE datetime (no tzinfo) — see
	// renewal.py:407. The resulting form is `2026-05-21T12:34:56`
	// (no `Z`, no offset). Parsing as RFC3339 would fail because
	// time.RFC3339 requires the suffix. Try the naive form first,
	// then fall back to RFC3339 in case an older go-certbot wrote a
	// tz-suffixed value.
	t, err := time.Parse("2006-01-02T15:04:05", raw)
	if err != nil {
		if t, err = time.Parse(time.RFC3339, raw); err != nil {
			return nil
		}
	}
	return &t
}

func writeARIRetryAfter(conf *renewalconf.File, confPath string, at time.Time) {
	if conf == nil || confPath == "" {
		return
	}
	// Match Certbot's naive (timezone-less) ISO format. Certbot's reader
	// (renewal.py:381-383) does `datetime.fromisoformat(value)` and then
	// compares to `datetime.now()` (also naive); a tz-aware value here
	// causes Python to raise `can't compare offset-naive and offset-aware
	// datetimes` and aborts the renewal. The value is implicitly UTC
	// because both sides use naive UTC throughout the ARI flow.
	conf.SetSection("acme_renewal_info", "ari_retry_after", at.UTC().Format("2006-01-02T15:04:05"))
	_ = conf.Save(confPath)
}
