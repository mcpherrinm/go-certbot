package cmd

import (
	"github.com/spf13/pflag"

	"github.com/letsencrypt/go-certbot/internal/config"
)

// registerRedirectFlags wires the tri-state --redirect / --no-redirect pair.
// nil = not specified (plugins should fall back to safe defaults), true =
// always add the HTTPS redirect, false = never add it.
func registerRedirectFlags(fs *pflag.FlagSet, c *config.Config) {
	if c.Redirect == nil {
		c.Redirect = new(bool)
		*c.Redirect = false
	}
	// pflag doesn't have a clean tri-state boolean, so we register the two
	// flags separately and read which was set via flagSet.Visit in trackSources.
	fs.BoolVar(c.Redirect, "redirect", *c.Redirect,
		"Add an HTTP→HTTPS redirect to managed server blocks (nginx).")
	noRedirect := false
	fs.BoolVar(&noRedirect, "no-redirect", false,
		"Do not add an HTTP→HTTPS redirect.")
	// Hook to flip cfg.Redirect to false if --no-redirect was set; the
	// post-parse trackSources runs Visit() and our hook plays follow-up.
	c.PostParseHooks = append(c.PostParseHooks, func() {
		if c.SetByUser("no-redirect") {
			b := false
			c.Redirect = &b
		} else if c.SetByUser("redirect") {
			b := true
			c.Redirect = &b
		}
		_ = noRedirect
	})
}
