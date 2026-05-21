package cmd

import (
	"github.com/spf13/pflag"

	"github.com/letsencrypt/go-certbot/internal/config"
)

// registerRedirectFlags wires the tri-state --redirect / --no-redirect pair.
// Certbot represents this as None / True / False (constants.py:67); we use a
// *bool. The pre-parse value is nil so plugins can distinguish "user didn't
// pick" (fall back to interactive/auto) from "user said false".
func registerRedirectFlags(fs *pflag.FlagSet, c *config.Config) {
	// Use throwaway locals for pflag binding so c.Redirect stays nil until a
	// user explicitly picks via --redirect or --no-redirect (otherwise plugins
	// would see *false from the unparsed default).
	redirect := false
	noRedirect := false
	fs.BoolVar(&redirect, "redirect", false,
		"Add an HTTP→HTTPS redirect to managed server blocks.")
	fs.BoolVar(&noRedirect, "no-redirect", false,
		"Do not add an HTTP→HTTPS redirect.")
	c.PostParseHooks = append(c.PostParseHooks, func() {
		switch {
		case c.SetByUser("no-redirect"):
			b := false
			c.Redirect = &b
		case c.SetByUser("redirect"):
			b := redirect
			c.Redirect = &b
		}
	})
}
