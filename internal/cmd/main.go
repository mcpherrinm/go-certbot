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
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/letsencrypt/go-certbot/internal/checkpoint"
	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/logfile"
	"github.com/letsencrypt/go-certbot/internal/plugins"
	"github.com/letsencrypt/go-certbot/internal/processlock"
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
			fmt.Println("go-certbot 1.4.0")
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
	// `--config` and `-c` are accepted, can repeat (matches Certbot).
	var configPaths []string
	fs.StringArrayVarP(&configPaths, "config", "c", nil, "Path to an additional cli.ini (repeatable).")

	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printHelp(os.Stdout, verb)
			return 0
		}
		fmt.Fprintln(os.Stderr, "go-certbot:", err)
		return 2
	}
	trackSources(fs, cfg)
	// Snapshot the post-argv flag set so we can restore values after ini
	// load without re-parsing argv (which would *append* to slice flags
	// because pflag's StringSliceValue.Set appends once Changed=true).
	argvSnapshot := snapshotFlags(fs)

	// Load cli.ini after parsing flags so command-line wins. Apply found
	// files in order: default search paths, then --config override.
	for _, p := range config.CLIIniSearchPaths(cfg.ConfigDir) {
		if err := loadIni(p, fs, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "go-certbot:", err)
			return 2
		}
	}
	for _, p := range configPaths {
		if err := loadIni(p, fs, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "go-certbot:", err)
			return 2
		}
	}
	// Restore argv values: for each flag that was set on argv, overwrite
	// what ini loading set. Avoids the slice-append bug a second Parse
	// would cause.
	restoreFlags(fs, argvSnapshot)
	trackSources(fs, cfg)
	materializeDNSMaps(cfg)
	for _, h := range cfg.PostParseHooks {
		h()
	}
	applyDryRunSideEffects(cfg)
	// --staging + custom --server is an error per Certbot
	// cli_utils.py:272-273. Disallow.
	if cfg.SetByUser("staging") && cfg.SetByUser("server") &&
		cfg.Server != config.StagingDirectory && cfg.Server != config.DefaultLetsEncryptDirectory {
		fmt.Fprintln(os.Stderr, "go-certbot: --staging is incompatible with a custom --server")
		return 2
	}

	configureLogging(cfg)
	// Open the rotating log file at <logs_dir>/letsencrypt.log so a debug
	// log survives the process. Mirrors certbot._internal.log.
	if closer, err := logfile.Setup(cfg.LogsDir, logLevel(cfg), cfg.MaxLogBackups); err == nil {
		defer closer.Close()
	}
	// Acquire process locks on config/work/logs dirs so concurrent
	// invocations don't trample shared state. Mirrors
	// certbot._internal.lock.lock_dir_until_exit.
	locks, err := processlock.AcquireDirs(cfg.ConfigDir, cfg.WorkDir, cfg.LogsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "go-certbot:", err)
		return 2
	}
	defer locks.Release()

	// Roll back any in-progress checkpoint left over by a crashed earlier
	// run. Matches Certbot's Reverter.recovery_routine (reverter.py:80-104).
	if err := checkpoint.RecoverInterrupted(cfg.WorkDir); err != nil {
		fmt.Fprintln(os.Stderr, "go-certbot: warning: failed to recover interrupted checkpoint:", err)
	}

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

	// Background goroutine: when ctx is cancelled by SIGINT/SIGTERM (NOT
	// by the deferred cancel() on normal exit), restore any in-flight
	// checkpoint and print Certbot's exit message. The handlerDone signal
	// lets us tell the two apart: if the handler has already finished
	// when ctx.Done() fires, the cancel was the deferred one and we
	// shouldn't act.
	handlerDone := make(chan struct{})
	sigFired := make(chan struct{})
	go func() {
		<-ctx.Done()
		select {
		case <-handlerDone:
			// Normal exit via deferred cancel(); nothing to do.
			return
		default:
		}
		if err := checkpoint.RestoreInFlight(); err == nil {
			fmt.Fprintln(os.Stderr, "Exiting due to user request.")
		} else {
			fmt.Fprintln(os.Stderr, "Exiting due to user request (warning: in-flight checkpoint rollback failed:", err, ")")
		}
		close(sigFired)
		// Give the active handler a moment to wrap up, then force-exit
		// so we don't hang on a misbehaving plugin.
		go func() {
			time.Sleep(5 * time.Second)
			os.Exit(130)
		}()
	}()

	handler := dispatch(verb)
	if handler == nil {
		fmt.Fprintf(os.Stderr, "go-certbot: unknown subcommand %q\n", verb)
		printCommands(os.Stderr)
		close(handlerDone)
		return 2
	}
	handlerErr := handler(ctx, cfg, reg)
	close(handlerDone)
	err = handlerErr
	if err != nil {
		// If a signal already fired, the goroutine printed the exit
		// message; suppress the handler error.
		select {
		case <-sigFired:
			return 130
		default:
		}
		fmt.Fprintln(os.Stderr, "go-certbot:", err)
		return 1
	}
	return 0
}

func dispatch(verb string) func(context.Context, *config.Config, *plugins.Registry) error {
	switch verb {
	case "", "run", "everything":
		return verbs.Run
	case "certonly", "auth":
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

// logLevel maps Certbot's --verbose / --quiet / --verbose-level onto slog.
// Certbot's default stderr level is WARNING (lowered by 10 per -v;
// log.py:130-145). --debug controls traceback display, not the level.
func logLevel(cfg *config.Config) slog.Level {
	level := slog.LevelWarn
	switch {
	case cfg.Quiet:
		level = slog.LevelError
	case cfg.Verbose >= 2:
		level = slog.LevelDebug
	case cfg.Verbose == 1:
		level = slog.LevelInfo
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
	return level
}

// snapshotFlags captures the user-set values of every flag the user
// changed on argv. Used to re-apply over ini-loaded values without
// re-parsing argv (which would double slice-flag values).
func snapshotFlags(fs *pflag.FlagSet) map[string]string {
	out := map[string]string{}
	fs.Visit(func(f *pflag.Flag) {
		out[f.Name] = f.Value.String()
	})
	return out
}

// restoreFlags re-applies argv-set values. For slice flags we must clear
// the existing value first (since Set appends when Changed=true), which
// we do by clearing the underlying slice via Type-specific handling.
func restoreFlags(fs *pflag.FlagSet, snap map[string]string) {
	for name, val := range snap {
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		// Reset slice flags to avoid the append-on-Set behavior.
		if sv, ok := f.Value.(interface{ Replace([]string) error }); ok {
			// pflag's StringSlice / IPSlice etc. expose Replace which
			// honors Changed semantics properly.
			vals := splitCSVList(val)
			_ = sv.Replace(vals)
			continue
		}
		// For scalars Set is fine (replaces).
		_ = f.Value.Set(val)
	}
}

// splitCSVList parses the `[a,b,c]` form pflag's StringSlice.String() emits.
func splitCSVList(s string) []string {
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// configureLogging seeds slog with a stderr-only handler at the right level.
// logfile.Setup will replace it with a tee handler if the logs dir is
// writable.
func configureLogging(cfg *config.Config) {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(cfg)})
	slog.SetDefault(slog.New(h))
	// --quiet implies --non-interactive (log.py:140-141).
	if cfg.Quiet {
		cfg.NonInteractive = true
	}
}
