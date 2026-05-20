package cmd

import (
	"strings"

	"github.com/letsencrypt/go-certbot/internal/config"
)

// buildWebrootMap pre-scans argv before pflag parsing to record the
// `-w`/`-d` (or `--webroot-path`/`--domain`) interleaving and build a
// domain → webroot map. Matches Certbot's _WebrootPathProcessor action
// (cli/cli_utils.py).
//
// Rules:
//   - Each `-w` sets the current webroot path. Each `-d` after that maps to
//     the most recent `-w`.
//   - `-d` values before any `-w` carry no path; they'll be mapped after
//     parsing (if only one `-w` was given, all `-d` values map to it).
//   - `--webroot-path=...` and `--domain=...` (with `=`) are also recognized.
//   - Comma-separated lists in a single `-d` or `--domain` value are split.
//
// If no `-w` ever appears the result is nil (caller can still use the flat
// WebrootPath list).
func buildWebrootMap(args []string) map[string]string {
	var (
		currentRoot string
		seenRoots   []string
		pendingDoms []string
		out         = map[string]string{}
	)

	add := func(domain, root string) {
		if domain == "" {
			return
		}
		if root == "" {
			pendingDoms = append(pendingDoms, domain)
			return
		}
		out[domain] = root
	}

	wantValue := ""
	for _, a := range args {
		if wantValue != "" {
			switch wantValue {
			case "-w":
				currentRoot = a
				seenRoots = append(seenRoots, currentRoot)
			case "-d":
				for _, d := range splitCSV(a) {
					add(d, currentRoot)
				}
			}
			wantValue = ""
			continue
		}
		switch {
		case a == "-w" || a == "--webroot-path":
			wantValue = "-w"
		case a == "-d" || a == "--domain" || a == "--domains":
			wantValue = "-d"
		case strings.HasPrefix(a, "--webroot-path="):
			currentRoot = strings.TrimPrefix(a, "--webroot-path=")
			seenRoots = append(seenRoots, currentRoot)
		case strings.HasPrefix(a, "-w="):
			currentRoot = strings.TrimPrefix(a, "-w=")
			seenRoots = append(seenRoots, currentRoot)
		case strings.HasPrefix(a, "--domain="):
			for _, d := range splitCSV(strings.TrimPrefix(a, "--domain=")) {
				add(d, currentRoot)
			}
		case strings.HasPrefix(a, "--domains="):
			for _, d := range splitCSV(strings.TrimPrefix(a, "--domains=")) {
				add(d, currentRoot)
			}
		case strings.HasPrefix(a, "-d="):
			for _, d := range splitCSV(strings.TrimPrefix(a, "-d=")) {
				add(d, currentRoot)
			}
		}
	}

	if len(seenRoots) == 0 {
		return nil
	}
	// Map any pre-`-w` `-d` values to the first webroot path.
	if len(pendingDoms) > 0 {
		first := seenRoots[0]
		for _, d := range pendingDoms {
			if _, ok := out[d]; !ok {
				out[d] = first
			}
		}
	}
	return out
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// applyWebrootMap stores the pre-parsed map onto cfg if present. Called from
// Main before fs.Parse so the plugin sees it.
func applyWebrootMap(cfg *config.Config, args []string) {
	if m := buildWebrootMap(args); m != nil {
		cfg.WebrootMap = m
	}
}
