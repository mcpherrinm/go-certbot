package verbs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	fmt.Fprintf(os.Stderr, "Which certificate would you like to %s?\n", verb)
	for i, n := range names {
		fmt.Fprintf(os.Stderr, "  %d. %s\n", i+1, n)
	}
	fmt.Fprint(os.Stderr, "Enter a number (or name): ")
	var buf [256]byte
	n, _ := os.Stdin.Read(buf[:])
	pick := strings.TrimSpace(string(buf[:n]))
	if pick == "" {
		return "", errors.New("no certificate selected")
	}
	if idx, err := strconv.Atoi(pick); err == nil && idx >= 1 && idx <= len(names) {
		return names[idx-1], nil
	}
	for _, n := range names {
		if n == pick {
			return n, nil
		}
	}
	return "", fmt.Errorf("%s: %q is not a known certificate name", verb, pick)
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

// confirmDelete asks the user to confirm a delete. Returns true if the user
// agreed (or non-interactive without --no-delete-after-revoke).
func confirmDelete(cfg *config.Config, certName string) bool {
	if cfg.NonInteractive {
		return true
	}
	// Match Certbot's wording (cert_manager.py:56-66) for grep-compat with
	// existing user-facing scripts.
	fmt.Fprintf(os.Stderr,
		"WARNING: Before continuing, ensure that the listed certificates are not being used by any installed server software (e.g. Apache, nginx, mail servers).\n"+
			"This will delete:\n"+
			"  %s\n"+
			"  %s\n"+
			"  %s\n",
		filepath.Join(cfg.LiveDir(), certName),
		filepath.Join(cfg.ArchiveDir(), certName),
		filepath.Join(cfg.RenewalConfigsDir(), certName+".conf"))
	return display.YesNoDefault("Are you sure you want to delete the above certificate(s)?", true)
}
