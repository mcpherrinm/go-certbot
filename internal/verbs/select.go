package verbs

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/display"
)

// chooseCertName returns the lineage name to act on. If --cert-name was set
// on argv, returns it unchanged. Otherwise lists the lineages under
// renewal/ and prompts the user; in non-interactive mode the missing flag
// is an error matching certbot/_internal/cert_manager.get_certnames.
func chooseCertName(cfg *config.Config, verb string) (string, error) {
	if cfg.CertName != "" {
		return cfg.CertName, nil
	}
	names, err := listCertNames(cfg)
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", fmt.Errorf("%s: no certificates found in %s", verb, cfg.RenewalConfigsDir())
	}
	if cfg.NonInteractive {
		return "", fmt.Errorf("%s: --cert-name is required in non-interactive mode (available: %s)", verb, strings.Join(names, ", "))
	}
	idx := display.Menu(fmt.Sprintf("Which certificate would you like to %s?", verb), names, 0)
	if idx < 0 || idx >= len(names) {
		return "", errors.New("no certificate selected")
	}
	return names[idx], nil
}

// listCertNames returns the lineage names found under renewal/ in sorted
// order. Mirrors cert_manager.renewal_filename_for_lineagename inverse.
func listCertNames(cfg *config.Config) ([]string, error) {
	entries, err := os.ReadDir(cfg.RenewalConfigsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		out = append(out, strings.TrimSuffix(name, ".conf"))
	}
	sort.Strings(out)
	return out, nil
}

// chooseCertNames returns one or more lineage names to act on. If
// --cert-name was set, returns just that. Otherwise prompts the user with
// a multi-select checklist (Certbot's get_certnames with allow_multiple=True).
func chooseCertNames(cfg *config.Config, verb string) ([]string, error) {
	if cfg.CertName != "" {
		return []string{cfg.CertName}, nil
	}
	names, err := listCertNames(cfg)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s: no certificates found in %s", verb, cfg.RenewalConfigsDir())
	}
	if cfg.NonInteractive {
		return nil, fmt.Errorf("%s: --cert-name is required in non-interactive mode (available: %s)", verb, strings.Join(names, ", "))
	}
	picks := display.Checklist(fmt.Sprintf("Which certificate(s) would you like to %s?", verb), names)
	if len(picks) == 0 {
		return nil, errors.New("no certificate selected")
	}
	out := make([]string, 0, len(picks))
	for _, i := range picks {
		if i >= 0 && i < len(names) {
			out = append(out, names[i])
		}
	}
	return out, nil
}

// confirmDeleteAll asks the user to confirm a delete. Returns true if the
// user agreed. Wording mirrors Certbot's cert_manager.py:56-66 so user-
// facing scripts grepping for stable text keep working.
func confirmDeleteAll(cfg *config.Config, names []string) bool {
	if cfg.NonInteractive {
		return true
	}
	var sb strings.Builder
	sb.WriteString("The following certificate(s) are selected for deletion:\n")
	for _, name := range names {
		fmt.Fprintf(&sb, "  * %s\n", name)
	}
	sb.WriteString("WARNING: Before continuing, ensure that the listed certificates are not being used by any installed server software (e.g. Apache, nginx, mail servers).\n")
	sb.WriteString("Additional details about deleting certificates are available at https://certbot.eff.org/docs/using.html#deleting-certificates\n")
	fmt.Fprint(os.Stderr, sb.String())
	return display.YesNoDefault("Are you sure you want to delete the above certificate(s)?", true)
}
