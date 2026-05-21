package cmd

import (
	"github.com/spf13/pflag"

	"github.com/letsencrypt/go-certbot/internal/config"
)

// dnsPluginNames lists every DNS plugin we ship, matching Certbot's bundled
// names. Iteration order is stable for help output.
var dnsPluginNames = []string{
	"cloudflare",
	"digitalocean",
	"dnsimple",
	"dnsmadeeasy",
	"gehirn",
	"google",
	"linode",
	"luadns",
	"nsone",
	"ovh",
	"rfc2136",
	"route53",
	"sakuracloud",
}

// dnsDefaultPropagation returns Certbot's default propagation seconds for a
// given DNS plugin (matches certbot-dns-*/.../dns_*.py:DEFAULT_PROPAGATION).
// Values were verified against each upstream plugin's default.
func dnsDefaultPropagation(name string) int {
	switch name {
	case "cloudflare", "digitalocean":
		return 10
	case "dnsimple", "luadns", "nsone", "gehirn":
		return 30
	case "ovh":
		return 120
	case "dnsmadeeasy", "google", "rfc2136", "route53":
		return 60
	case "sakuracloud":
		return 90
	case "linode":
		return 120
	}
	return 30
}

// registerDNSPluginFlags wires --dns-<name>, --dns-<name>-credentials, and
// --dns-<name>-propagation-seconds into the FlagSet.
func registerDNSPluginFlags(fs *pflag.FlagSet, c *config.Config, name string) {
	if c.DNSSelected == nil {
		c.DNSSelected = map[string]bool{}
	}
	if c.DNSCredentials == nil {
		c.DNSCredentials = map[string]string{}
	}
	if c.DNSPropagationSeconds == nil {
		c.DNSPropagationSeconds = map[string]int{}
	}
	// Pflag's *Var APIs need stable pointers; the map-value-pointer trick
	// doesn't work, so use proxy variables and copy back via PreRun.
	selectFlag := "dns-" + name
	credentialsFlag := "dns-" + name + "-credentials"
	propagationFlag := "dns-" + name + "-propagation-seconds"

	defaultPropagation := dnsDefaultPropagation(name)
	c.DNSPropagationSeconds[name] = defaultPropagation

	fs.BoolVar(boolPtr(c.DNSSelected, name), selectFlag, false,
		"Use the dns-"+name+" plugin.")
	fs.StringVar(stringPtr(c.DNSCredentials, name), credentialsFlag, "",
		"Path to a credentials INI file for the dns-"+name+" plugin.")
	fs.IntVar(intPtr(c.DNSPropagationSeconds, name), propagationFlag, defaultPropagation,
		"Seconds to wait for DNS changes to propagate before validating (dns-"+name+").")
}

// boolPtr / stringPtr / intPtr return persistent pointers to map slots. pflag
// holds onto the pointer, and map values are not addressable, so we allocate
// a slot and arrange for the map to be re-populated after Parse via Visit.
//
// Implementation: we return a pointer to a freshly-allocated value and rely
// on the caller (cmd.Main) to call materializeDNSMaps after pflag parsing to
// copy the values back into the maps.
//
// In practice that copy is hidden behind the helper below.
type dnsFlagBackings struct {
	bools   map[string]*bool
	strings map[string]*string
	ints    map[string]*int
}

var dnsBackings = dnsFlagBackings{
	bools:   map[string]*bool{},
	strings: map[string]*string{},
	ints:    map[string]*int{},
}

func boolPtr(_ map[string]bool, name string) *bool {
	v := new(bool)
	dnsBackings.bools[name] = v
	return v
}

func stringPtr(_ map[string]string, name string) *string {
	v := new(string)
	dnsBackings.strings[name] = v
	return v
}

func intPtr(_ map[string]int, name string) *int {
	v := new(int)
	dnsBackings.ints[name] = v
	return v
}

// materializeDNSMaps copies the per-plugin pointer values into the Config maps
// after pflag has populated them. Called once after fs.Parse returns.
func materializeDNSMaps(c *config.Config) {
	for name, p := range dnsBackings.bools {
		c.DNSSelected[name] = *p
	}
	for name, p := range dnsBackings.strings {
		c.DNSCredentials[name] = *p
	}
	for name, p := range dnsBackings.ints {
		c.DNSPropagationSeconds[name] = *p
	}
}
