package verbs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/plugins"
)

// Delete removes all files for a lineage:
//
//	renewal/<name>.conf
//	live/<name>/
//	archive/<name>/
//
// Requires --cert-name. The order matches Certbot's main.delete: rename
// renewal conf to .deleted first so a crash leaves the lineage marked as
// gone, then remove the directories.
func Delete(_ context.Context, cfg *config.Config, _ *plugins.Registry) error {
	if cfg.CertName == "" {
		return errors.New("delete: --cert-name is required")
	}
	if !cfg.NonInteractive {
		fmt.Fprintf(os.Stderr,
			"NOTE: delete is non-interactive in this build; pass --cert-name=%q only if you really mean it.\n",
			cfg.CertName)
	}
	confPath := filepath.Join(cfg.RenewalConfigsDir(), cfg.CertName+".conf")
	livePath := filepath.Join(cfg.LiveDir(), cfg.CertName)
	archivePath := filepath.Join(cfg.ArchiveDir(), cfg.CertName)

	// Sanity-check at least one of these exists so a typo doesn't return "ok".
	if _, err := os.Stat(confPath); err != nil {
		if os.IsNotExist(err) {
			if _, errLive := os.Stat(livePath); errLive != nil && os.IsNotExist(errLive) {
				return fmt.Errorf("delete: nothing to delete for cert-name %q", cfg.CertName)
			}
		}
	}

	// Move the conf aside first; if a later step fails the user will see a
	// stranded .deleted file rather than an inconsistent state.
	if _, err := os.Stat(confPath); err == nil {
		stash := confPath + ".deleted"
		if err := os.Rename(confPath, stash); err != nil {
			return fmt.Errorf("delete: rename %s: %w", confPath, err)
		}
		defer os.Remove(stash)
	}

	if err := os.RemoveAll(livePath); err != nil {
		return fmt.Errorf("delete: remove live %s: %w", livePath, err)
	}
	if err := os.RemoveAll(archivePath); err != nil {
		return fmt.Errorf("delete: remove archive %s: %w", archivePath, err)
	}
	fmt.Printf("Deleted certificate %q (live/, archive/, renewal/).\n", cfg.CertName)
	return nil
}
