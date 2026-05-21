package verbs

import (
	"context"
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
// Without --cert-name the user is prompted with a multi-select checklist
// like `certbot delete` (cert_manager.py:55-72 via get_certnames with
// allow_multiple=True).
func Delete(_ context.Context, cfg *config.Config, _ *plugins.Registry) error {
	names, err := chooseCertNames(cfg, "delete")
	if err != nil {
		return err
	}
	if !cfg.NonInteractive {
		if !confirmDeleteAll(cfg, names) {
			fmt.Println("delete: aborted by user.")
			return nil
		}
	}
	for _, name := range names {
		if err := deleteOne(cfg, name); err != nil {
			return err
		}
		fmt.Printf("Deleted all files relating to certificate %s.\n", name)
	}
	return nil
}

func deleteOne(cfg *config.Config, name string) error {
	confPath := filepath.Join(cfg.RenewalConfigsDir(), name+".conf")
	livePath := filepath.Join(cfg.LiveDir(), name)
	archivePath := filepath.Join(cfg.ArchiveDir(), name)

	// Sanity-check at least one of these exists so a typo doesn't return "ok".
	if _, err := os.Stat(confPath); err != nil && os.IsNotExist(err) {
		if _, errLive := os.Stat(livePath); errLive != nil && os.IsNotExist(errLive) {
			return fmt.Errorf("delete: nothing to delete for cert-name %q", name)
		}
	}

	// Certbot removes the renewal conf directly via os.remove (storage.py:
	// delete_files), without an intermediate .deleted file. Match that so
	// scratch state doesn't accumulate after a crash.
	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete: remove %s: %w", confPath, err)
	}
	if err := os.RemoveAll(livePath); err != nil {
		return fmt.Errorf("delete: remove live %s: %w", livePath, err)
	}
	if err := os.RemoveAll(archivePath); err != nil {
		return fmt.Errorf("delete: remove archive %s: %w", archivePath, err)
	}
	return nil
}
