package verbs

import (
	"testing"
	"time"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/storage/renewalconf"
)

func TestMergeFromRenewalConfRespectsUserOverride(t *testing.T) {
	cfg := config.NewDefault()
	cfg.Server = "https://override.test/dir"
	cfg.MarkSet("server", config.SourceCommandLine)

	conf := renewalconf.New()
	conf.SetParam("server", "https://from-renewal.test/dir")
	conf.SetParam("authenticator", "standalone")
	conf.SetParam("key_type", "rsa")
	conf.SetParam("rsa_key_size", "4096")
	conf.SetParam("domains", "a.test,b.test,")

	mergeFromRenewalConf(cfg, conf)

	if cfg.Server != "https://override.test/dir" {
		t.Errorf("user-set server should win, got %q", cfg.Server)
	}
	if cfg.Authenticator != "standalone" {
		t.Errorf("auth not restored: %q", cfg.Authenticator)
	}
	if cfg.KeyType != "rsa" {
		t.Errorf("key_type not restored: %q", cfg.KeyType)
	}
	if cfg.RSAKeySize != 4096 {
		t.Errorf("rsa_key_size not restored: %d", cfg.RSAKeySize)
	}
	if len(cfg.Domains) != 2 || cfg.Domains[0] != "a.test" || cfg.Domains[1] != "b.test" {
		t.Errorf("domains not restored: %v", cfg.Domains)
	}
}

func TestParseRenewBefore(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"30 days", 30 * 24 * time.Hour},
		{"6 weeks", 6 * 7 * 24 * time.Hour},
		{"3 months", 3 * 30 * 24 * time.Hour},
		{"1 hour", time.Hour},
		{"45", 45 * 24 * time.Hour}, // bare int = days
	}
	for _, tc := range tests {
		got, err := parseRenewBefore(tc.in)
		if err != nil {
			t.Errorf("parseRenewBefore(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseRenewBefore(%q): got %v want %v", tc.in, got, tc.want)
		}
	}
}
