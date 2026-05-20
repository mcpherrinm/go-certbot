package cmd

import (
	"testing"

	"github.com/spf13/pflag"

	"github.com/letsencrypt/go-certbot/internal/config"
)

func TestRegisterDNSPluginFlags(t *testing.T) {
	// Reset module-level backing maps so tests don't leak between cases.
	dnsBackings.bools = map[string]*bool{}
	dnsBackings.strings = map[string]*string{}
	dnsBackings.ints = map[string]*int{}

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	c := config.NewDefault()
	for _, name := range dnsPluginNames {
		registerDNSPluginFlags(fs, c, name)
	}
	args := []string{
		"--dns-cloudflare",
		"--dns-cloudflare-credentials", "/path/to/cf.ini",
		"--dns-cloudflare-propagation-seconds", "45",
	}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	materializeDNSMaps(c)

	if !c.DNSSelected["cloudflare"] {
		t.Errorf("cloudflare should be selected")
	}
	if c.DNSCredentials["cloudflare"] != "/path/to/cf.ini" {
		t.Errorf("cf creds: %q", c.DNSCredentials["cloudflare"])
	}
	if c.DNSPropagationSeconds["cloudflare"] != 45 {
		t.Errorf("cf propagation: %d", c.DNSPropagationSeconds["cloudflare"])
	}
	// Untouched plugins should keep their defaults.
	if c.DNSSelected["route53"] {
		t.Errorf("route53 should not be selected")
	}
	if c.DNSPropagationSeconds["route53"] != dnsDefaultPropagation("route53") {
		t.Errorf("route53 default propagation: %d", c.DNSPropagationSeconds["route53"])
	}
}

func TestDNSDefaultPropagation(t *testing.T) {
	cases := map[string]int{
		"cloudflare":  10,
		"dnsmadeeasy": 60,
		"sakuracloud": 90,
		"linode":      120,
		"unknown":     30,
	}
	for name, want := range cases {
		if got := dnsDefaultPropagation(name); got != want {
			t.Errorf("dnsDefaultPropagation(%q) = %d, want %d", name, got, want)
		}
	}
}
