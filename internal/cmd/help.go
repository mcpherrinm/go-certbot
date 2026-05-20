package cmd

import (
	"fmt"
	"io"
	"sort"
)

// usage matches the shape of certbot's short usage block (cli_constants.py).
const usage = `usage:
  go-certbot [SUBCOMMAND] [options] [-d DOMAIN] [-d DOMAIN] ...

go-certbot can obtain and install HTTPS/TLS/SSL certificates, drop-in
compatible with Certbot.

The most common SUBCOMMANDS and flags are:

obtain, install, and renew certificates:
    (default) run   Obtain & install a certificate in your current webserver
    certonly        Obtain or renew a certificate, but do not install it
    renew           Renew all previously obtained certificates that are near expiry
    enhance         Add security enhancements to your existing configuration
   -d DOMAINS       Comma-separated list of domains to obtain a certificate for

  --apache          Use the apache plugin                  (Phase 6)
  --standalone      Run a standalone webserver for authentication
  --nginx           Use the nginx plugin                   (Phase 5)
  --webroot         Place files in a server's webroot folder for authentication (Phase 2)
  --manual          Obtain certificates interactively, or using shell script hooks (Phase 2)

   -n               Run non-interactively
  --test-cert       Obtain a test certificate from a staging server
  --dry-run         Test "renew" or "certonly" without saving any certificates to disk

manage certificates:
    certificates    Display information about certificates you have from Certbot
    revoke          Revoke a certificate (supply --cert-name or --cert-path)
    delete          Delete a certificate (supply --cert-name)
    reconfigure     Update a certificate's configuration (supply --cert-name)

manage your account:
    register        Create an ACME account
    unregister      Deactivate an ACME account
    update_account  Update an ACME account
    show_account    Display account details
  --agree-tos       Agree to the ACME server's Subscriber Agreement
   -m EMAIL         Email address for important account notifications

Phase 1 implements: certonly --standalone, account creation, on-disk format
compatible with Certbot 5.x. See CHANGES.md for the rollout plan.
`

func printUsage(out io.Writer) {
	fmt.Fprint(out, usage)
}

// verbsHelp describes every verb the CLI accepts.
// summaries are copied verbatim from certbot/_internal/cli/verb_help.py so
// `--help` output matches Certbot.
var verbsHelp = []struct {
	name, summary string
}{
	{"run", "Obtain/renew a certificate, and install it (default)"},
	{"certonly", "Obtain or renew a certificate, but do not install it"},
	{"renew", "Renew all certificates (or one specified with --cert-name)"},
	{"certificates", "List certificates managed by Certbot"},
	{"delete", "Clean up all files related to a certificate"},
	{"revoke", "Revoke a certificate specified with --cert-path or --cert-name"},
	{"register", "Register for an account with the ACME server"},
	{"update_account", "Update existing account with the ACME server"},
	{"unregister", "Irrevocably deactivate your account"},
	{"show_account", "Show account details from an ACME server"},
	{"install", "Install an arbitrary certificate in a server"},
	{"rollback", "Roll back server conf changes made during certificate installation"},
	{"plugins", "List plugins that are installed and available on your system"},
	{"enhance", "Add security enhancements to your existing configuration"},
	{"reconfigure", "Update renewal configuration for a certificate specified by --cert-name"},
}

func printCommands(out io.Writer) {
	names := make([]string, len(verbsHelp))
	for i, v := range verbsHelp {
		names[i] = v.name
	}
	sort.Strings(names)
	fmt.Fprintln(out, "Subcommands:")
	for _, v := range verbsHelp {
		fmt.Fprintf(out, "  %-15s %s\n", v.name, v.summary)
	}
}
