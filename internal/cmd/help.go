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

  --apache          Use the apache plugin
  --standalone      Run a standalone webserver for authentication
  --nginx           Use the nginx plugin
  --webroot         Place files in a server's webroot folder for authentication
  --manual          Obtain certificates interactively, or using shell script hooks

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

More detailed help:

  -h, --help [TOPIC]    print this message, or detailed help on a topic;
                        the available TOPICS are:

   all, automation, commands, paths, security, testing, or any of the
   subcommands or plugins (certonly, renew, install, register, nginx,
   apache, standalone, webroot, etc.)
  -h all                print a detailed help page including all topics
  --version             print the version number
`

func printUsage(out io.Writer) {
	fmt.Fprint(out, usage)
}

// verbsHelp matches certbot/_internal/cli/verb_help.py's VERB_HELP. Pulled
// verbatim from upstream so `--help <verb>` shows what users expect.
var verbsHelp = []struct {
	name, summary, body string
}{
	{
		"run", "Obtain/renew a certificate, and install it (default)",
		"Obtain and install a certificate via the current authenticator/installer pair.\n",
	},
	{
		"certonly", "Obtain or renew a certificate, but do not install it",
		"\n\n  certbot certonly [options] [-d DOMAIN] [-d DOMAIN] ...\n\n" +
			"This command obtains a TLS/SSL certificate without installing it anywhere.\n",
	},
	{
		"renew", "Renew all certificates (or one specified with --cert-name)",
		"The 'renew' subcommand will attempt to renew any certificates previously " +
			"obtained if they are close to expiry, and print a summary of the results.\n",
	},
	{"certificates", "List certificates managed by Certbot", "Print information about the status of certificates managed by Certbot.\n"},
	{"delete", "Clean up all files related to a certificate", "\n  certbot delete --cert-name CERTNAME\n"},
	{"revoke", "Revoke a certificate specified with --cert-path or --cert-name",
		"\n  certbot revoke [--cert-path /path/to/fullchain.pem | --cert-name example.com] [options]\n"},
	{"register", "Register for an account with the ACME server",
		"\n  certbot register --email user@example.com [options]\n"},
	{"update_account", "Update existing account with the ACME server",
		"\n  certbot update_account --email updated_email@example.com [options]\n"},
	{"unregister", "Irrevocably deactivate your account", "\n  certbot unregister [options]\n"},
	{"show_account", "Show account details from an ACME server", "\n  certbot show_account [options]\n"},
	{"install", "Install an arbitrary certificate in a server",
		"\n  certbot install --cert-path /path/to/fullchain.pem --key-path /path/to/private-key [options]\n"},
	{"rollback", "Roll back server conf changes made during certificate installation",
		"\n  certbot rollback --checkpoints 3 [options]\n"},
	{"plugins", "List plugins that are installed and available on your system", "\n  certbot plugins [options]\n"},
	{"enhance", "Add security enhancements to your existing configuration", "\n  certbot enhance [options]\n"},
	{"reconfigure", "Update renewal configuration for a certificate specified by --cert-name",
		"\n  certbot reconfigure --cert-name CERTNAME [options]\n"},
}

// topicGroups defines the Certbot topic system from cli_constants.py.
var topicGroups = []string{"all", "automation", "commands", "paths", "security", "testing"}

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

// printHelpTopic dispatches the topic for `-h <topic>`. Matches Certbot's
// helpful.HelpfulArgumentParser.help_topics list.
func printHelpTopic(out io.Writer, topic string) {
	switch topic {
	case "", "all":
		printUsage(out)
		printCommands(out)
	case "commands":
		printCommands(out)
	case "automation":
		fmt.Fprintln(out, "Automation flags:")
		fmt.Fprintln(out, "  -n, --non-interactive   Run without prompts.")
		fmt.Fprintln(out, "  --agree-tos             Agree to ACME server's Subscriber Agreement.")
		fmt.Fprintln(out, "  --no-eff-email          Don't subscribe to the EFF mailing list.")
		fmt.Fprintln(out, "  --quiet                 Quiet mode (implies --non-interactive).")
		fmt.Fprintln(out, "  --random-sleep-on-renew Sleep before renew (jitter for cron).")
	case "paths":
		fmt.Fprintln(out, "Path flags:")
		fmt.Fprintln(out, "  --config-dir DIR        /etc/letsencrypt by default.")
		fmt.Fprintln(out, "  --work-dir DIR          /var/lib/letsencrypt.")
		fmt.Fprintln(out, "  --logs-dir DIR          /var/log/letsencrypt.")
		fmt.Fprintln(out, "  --cert-path PATH        Where to write the leaf cert (--csr).")
		fmt.Fprintln(out, "  --chain-path PATH       Where to write the chain (--csr).")
		fmt.Fprintln(out, "  --fullchain-path PATH   Where to write the fullchain (--csr).")
	case "security":
		fmt.Fprintln(out, "Security flags:")
		fmt.Fprintln(out, "  --hsts                  Add Strict-Transport-Security header.")
		fmt.Fprintln(out, "  --staple-ocsp           Enable OCSP stapling.")
		fmt.Fprintln(out, "  --uir                   Content-Security-Policy: upgrade-insecure-requests.")
		fmt.Fprintln(out, "  --must-staple           Include the OCSP Must-Staple extension in the issued cert.")
		fmt.Fprintln(out, "  --redirect/--no-redirect Manage HTTP→HTTPS redirect.")
	case "testing":
		fmt.Fprintln(out, "Testing flags:")
		fmt.Fprintln(out, "  --test-cert / --staging Use Let's Encrypt staging.")
		fmt.Fprintln(out, "  --dry-run               Test issuance without writing to disk.")
		fmt.Fprintln(out, "  --debug-challenges      Pause before submitting challenges.")
		fmt.Fprintln(out, "  --break-my-certs        Acknowledge non-default ACME server may break existing certs.")
	default:
		// Try a verb name.
		for _, v := range verbsHelp {
			if v.name == topic {
				fmt.Fprintf(out, "%s — %s\n%s\n", v.name, v.summary, v.body)
				return
			}
		}
		// Plugin name?
		switch topic {
		case "nginx", "apache", "standalone", "webroot", "manual",
			"dns-cloudflare", "dns-digitalocean", "dns-dnsimple", "dns-dnsmadeeasy",
			"dns-gehirn", "dns-google", "dns-linode", "dns-luadns", "dns-nsone",
			"dns-ovh", "dns-rfc2136", "dns-route53", "dns-sakuracloud":
			fmt.Fprintf(out, "%s plugin — see `certbot --%s --help` for details.\n", topic, topic)
			return
		}
		fmt.Fprintf(out, "Unknown help topic %q. Try: all, commands, automation, paths, security, testing, or any subcommand or plugin name.\n", topic)
	}
}
