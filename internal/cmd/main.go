// Package cmd implements go-certbot's CLI entrypoint and verb dispatch.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	dnscloudflare "github.com/letsencrypt/go-certbot/internal/plugins/dns/cloudflare"
	dnsdigitalocean "github.com/letsencrypt/go-certbot/internal/plugins/dns/digitalocean"
	dnsdnsimple "github.com/letsencrypt/go-certbot/internal/plugins/dns/dnsimple"
	dnsdnsmadeeasy "github.com/letsencrypt/go-certbot/internal/plugins/dns/dnsmadeeasy"
	dnsgehirn "github.com/letsencrypt/go-certbot/internal/plugins/dns/gehirn"
	dnsgoogle "github.com/letsencrypt/go-certbot/internal/plugins/dns/google"
	dnslinode "github.com/letsencrypt/go-certbot/internal/plugins/dns/linode"
	dnsluadns "github.com/letsencrypt/go-certbot/internal/plugins/dns/luadns"
	dnsnsone "github.com/letsencrypt/go-certbot/internal/plugins/dns/nsone"
	dnsovh "github.com/letsencrypt/go-certbot/internal/plugins/dns/ovh"
	dnsrfc2136 "github.com/letsencrypt/go-certbot/internal/plugins/dns/rfc2136"
	dnsroute53 "github.com/letsencrypt/go-certbot/internal/plugins/dns/route53"
	dnssakuracloud "github.com/letsencrypt/go-certbot/internal/plugins/dns/sakuracloud"
	"github.com/letsencrypt/go-certbot/internal/plugins/apache"
	"github.com/letsencrypt/go-certbot/internal/plugins/manual"
	"github.com/letsencrypt/go-certbot/internal/plugins/nginx"
	"github.com/letsencrypt/go-certbot/internal/plugins/standalone"
	"github.com/letsencrypt/go-certbot/internal/plugins/webroot"
	"github.com/letsencrypt/go-certbot/internal/verbs"
)

// Main runs the CLI with the given args (omit os.Args[0]). Returns the
// process exit code.
func Main(args []string) int {
	// `--version` always prints and exits.
	for _, a := range args {
		if a == "--version" {
			fmt.Println("go-certbot 0.6.0-phase6")
			return 0
		}
	}
	// `--help` / `-h` may carry a topic as the next arg (e.g. `-h security`).
	// `help` as a positional verb behaves the same: `certbot help renew`.
	for i, a := range args {
		switch a {
		case "--help", "-h", "help":
			topic := ""
			if i+1 < len(args) {
				topic = args[i+1]
			}
			printHelp(os.Stdout, topic)
			return 0
		}
	}
	verb, rest := extractVerb(args)

	cfg := config.NewDefault()
	cfg.Verb = verb
	// Pre-scan argv to capture -w/-d interleaving for the webroot plugin
	// before pflag flattens the slices and loses cross-flag order.
	applyWebrootMap(cfg, args)

	fs := pflag.NewFlagSet("go-certbot", pflag.ContinueOnError)
	fs.Usage = func() { printHelp(os.Stderr, verb) }
	// Phase 1 ignores -h inside flag parsing so we can pre-handle it above.
	fs.SetOutput(io.Discard)
	registerFlags(fs, cfg)

	// pflag returns ErrHelp on --help/-h; we catch and reprint our help.
	var configPath string
	fs.StringVar(&configPath, "config", "", "Path to an additional cli.ini.")

	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printHelp(os.Stdout, verb)
			return 0
		}
		fmt.Fprintln(os.Stderr, "go-certbot:", err)
		return 2
	}
	trackSources(fs, cfg)

	// Load cli.ini after parsing flags so command-line wins. Apply found
	// files in order: default search paths, then --config override.
	for _, p := range config.CLIIniSearchPaths(cfg.ConfigDir) {
		if err := loadIni(p, fs, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "go-certbot:", err)
			return 2
		}
	}
	if configPath != "" {
		if err := loadIni(configPath, fs, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "go-certbot:", err)
			return 2
		}
	}
	// Re-parse argv so flags override anything loaded from ini.
	if err := fs.Parse(rest); err != nil {
		fmt.Fprintln(os.Stderr, "go-certbot:", err)
		return 2
	}
	trackSources(fs, cfg)
	materializeDNSMaps(cfg)
	for _, h := range cfg.PostParseHooks {
		h()
	}

	configureLogging(cfg)

	reg := plugins.NewRegistry()
	reg.RegisterAuthenticator(standalone.New())
	reg.RegisterAuthenticator(webroot.New())
	reg.RegisterAuthenticator(manual.New())
	reg.RegisterAuthenticator(dnscloudflare.New())
	reg.RegisterAuthenticator(dnsdigitalocean.New())
	reg.RegisterAuthenticator(dnsdnsimple.New())
	reg.RegisterAuthenticator(dnsdnsmadeeasy.New())
	reg.RegisterAuthenticator(dnsgehirn.New())
	reg.RegisterAuthenticator(dnsgoogle.New())
	reg.RegisterAuthenticator(dnslinode.New())
	reg.RegisterAuthenticator(dnsluadns.New())
	reg.RegisterAuthenticator(dnsnsone.New())
	reg.RegisterAuthenticator(dnsovh.New())
	reg.RegisterAuthenticator(dnsrfc2136.New())
	reg.RegisterAuthenticator(dnsroute53.New())
	reg.RegisterAuthenticator(dnssakuracloud.New())
	nginxPlugin := nginx.New()
	reg.RegisterAuthenticator(nginxPlugin)
	reg.RegisterInstaller(nginxPlugin)
	apachePlugin := apache.New()
	reg.RegisterAuthenticator(apachePlugin)
	reg.RegisterInstaller(apachePlugin)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	handler := dispatch(verb)
	if handler == nil {
		fmt.Fprintf(os.Stderr, "go-certbot: unknown subcommand %q\n", verb)
		printCommands(os.Stderr)
		return 2
	}
	if err := handler(ctx, cfg, reg); err != nil {
		fmt.Fprintln(os.Stderr, "go-certbot:", err)
		return 1
	}
	return 0
}

func dispatch(verb string) func(context.Context, *config.Config, *plugins.Registry) error {
	switch verb {
	case "", "run":
		return verbs.Run
	case "certonly":
		return verbs.Certonly
	case "renew":
		return verbs.Renew
	case "certificates":
		return verbs.Certificates
	case "delete":
		return verbs.Delete
	case "revoke":
		return verbs.Revoke
	case "register":
		return verbs.Register
	case "unregister":
		return verbs.Unregister
	case "update_account":
		return verbs.UpdateAccount
	case "show_account":
		return verbs.ShowAccount
	case "install":
		return verbs.Install
	case "enhance":
		return verbs.Enhance
	case "rollback":
		return verbs.Rollback
	case "plugins":
		return verbs.Plugins
	case "reconfigure":
		return verbs.Reconfigure
	}
	return nil
}

// extractVerb pulls the leading positional subcommand (if any) from args.
// Returns ("", args) if the first arg is a flag or args is empty (which
// matches Certbot's "run" default).
func extractVerb(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	first := args[0]
	if len(first) > 0 && first[0] == '-' {
		return "", args
	}
	return first, args[1:]
}

func printHelp(out io.Writer, topic string) {
	printHelpTopic(out, topic)
}

// configureLogging maps Certbot's --verbose / --quiet / --verbose-level onto
// slog. Note that Certbot's --debug controls TRACEBACK display (not log
// level); we honor that by leaving log level alone when only --debug is set.
func configureLogging(cfg *config.Config) {
	level := slog.LevelInfo
	switch {
	case cfg.Quiet:
		level = slog.LevelError
	case cfg.Verbose >= 2:
		level = slog.LevelDebug
	case cfg.Verbose == 1:
		level = slog.LevelInfo // already default
	}
	switch cfg.VerboseLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warning", "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
}
