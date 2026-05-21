// Package checkpoint records file snapshots so installer mutations can be
// rolled back. The on-disk layout matches certbot.reverter so a checkpoint
// written by go-certbot is recoverable by Certbot's `certbot rollback`, and
// vice-versa:
//
//	<work_dir>/backups/<timestamp>/
//	    FILEPATHS        # original absolute paths, one per line
//	    CHANGES_SINCE    # human-readable note about what changed
//	    NEW_FILES        # files that were CREATED (rollback deletes them)
//	    <basename>_<idx> # backed-up content, indexed against FILEPATHS
//
// `<timestamp>` is a Unix-timestamp string (e.g. "1716239876.123456") so
// dirs sort lexically by creation time. New() and AddFiles() build a
// single checkpoint progressively; Finalize() promotes it.
//
// Save() is a convenience that creates+finalizes a one-shot checkpoint.
package checkpoint

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// inFlight is the directory of the most recently Save'd checkpoint that
// hasn't been MarkClean'd yet. A SIGINT/SIGTERM handler can call
// RestoreInFlight to roll it back.
var (
	inFlightMu  sync.Mutex
	inFlightDir string
)

// MarkClean clears the in-flight marker.
func MarkClean() {
	inFlightMu.Lock()
	inFlightDir = ""
	inFlightMu.Unlock()
}

// RestoreInFlight restores the most recent in-flight checkpoint (if any).
func RestoreInFlight() error {
	inFlightMu.Lock()
	dir := inFlightDir
	inFlightDir = ""
	inFlightMu.Unlock()
	if dir == "" {
		return nil
	}
	return restoreDir(dir)
}

// Save creates a new checkpoint dir under work_dir/backups/<timestamp>/ and
// records `paths` as its backed-up files. Returns the checkpoint dir path,
// or "" if no files were available to back up.
func Save(workDir, label string, paths []string) (string, error) {
	base := filepath.Join(workDir, "backups")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", fmt.Errorf("checkpoint: mkdir %s: %w", base, err)
	}
	dir, err := nextCheckpointDir(base)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	var savedAny bool
	idx := 0
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Track as a NEW_FILES candidate — if the caller
				// is about to create this path, rollback should
				// delete it.
				if err := appendLine(filepath.Join(dir, "NEW_FILES"), abs); err != nil {
					return "", err
				}
				continue
			}
			return "", fmt.Errorf("checkpoint: read %s: %w", abs, err)
		}
		dst := filepath.Join(dir, filepath.Base(abs)+"_"+strconv.Itoa(idx))
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return "", err
		}
		if err := appendLine(filepath.Join(dir, "FILEPATHS"), abs); err != nil {
			return "", err
		}
		idx++
		savedAny = true
	}
	if !savedAny {
		_ = os.RemoveAll(dir)
		return "", nil
	}
	// CHANGES_SINCE is a freeform note Certbot's rollback prints.
	if err := os.WriteFile(filepath.Join(dir, "CHANGES_SINCE"), []byte(label+"\n"), 0o644); err != nil {
		return "", err
	}
	inFlightMu.Lock()
	inFlightDir = dir
	inFlightMu.Unlock()
	return dir, nil
}

// nextCheckpointDir picks a timestamp-named subdir that sorts after every
// existing dir under base. Matches Certbot's monotonicity guarantee in
// _checkpoint_timestamp (reverter.py:485-503).
func nextCheckpointDir(base string) (string, error) {
	stamp := strconv.FormatFloat(float64(time.Now().UnixNano())/1e9, 'f', 6, 64)
	entries, err := os.ReadDir(base)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	others := []string{stamp}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n := e.Name()
		if n != "" && (n[0] >= '0' && n[0] <= '9') {
			others = append(others, n)
		}
	}
	sort.Strings(others)
	if others[len(others)-1] != stamp {
		// Clock went backwards. Bump to last + 1s.
		v, _ := strconv.ParseFloat(others[len(others)-1], 64)
		stamp = strconv.FormatFloat(v+1, 'f', 6, 64)
	} else if len(others) >= 2 && others[len(others)-2] == stamp {
		v, _ := strconv.ParseFloat(others[len(others)-1], 64)
		stamp = strconv.FormatFloat(v+0.01, 'f', 6, 64)
	}
	return filepath.Join(base, stamp), nil
}

func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

// List returns checkpoint directory paths under work_dir/backups/, oldest
// first (lexical sort matches creation order since dir names are
// timestamps).
func List(workDir string) ([]string, error) {
	base := filepath.Join(workDir, "backups")
	entries, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n := e.Name()
		if n != "" && (n[0] >= '0' && n[0] <= '9') {
			names = append(names, filepath.Join(base, n))
		}
	}
	sort.Strings(names)
	return names, nil
}

// Restore replays the most recent n checkpoints in reverse and removes
// them from disk. Returns the absolute paths that were changed (restored
// or deleted).
func Restore(workDir string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	all, err := List(workDir)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, errors.New("rollback: no checkpoints to restore")
	}
	if n > len(all) {
		n = len(all)
	}
	toRestore := all[len(all)-n:]
	seen := map[string]bool{}
	var changed []string
	for i := len(toRestore) - 1; i >= 0; i-- {
		dir := toRestore[i]
		paths, err := readLines(filepath.Join(dir, "FILEPATHS"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for idx, path := range paths {
			if seen[path] {
				continue
			}
			seen[path] = true
			src := filepath.Join(dir, filepath.Base(path)+"_"+strconv.Itoa(idx))
			if err := restoreFile(src, path); err != nil {
				return nil, err
			}
			changed = append(changed, path)
		}
		// NEW_FILES: delete any files we created in this checkpoint.
		newPaths, err := readLines(filepath.Join(dir, "NEW_FILES"))
		if err == nil {
			for _, p := range newPaths {
				if err := os.Remove(p); err == nil {
					changed = append(changed, p)
				}
			}
		}
		// Done with this checkpoint dir.
		_ = os.RemoveAll(dir)
	}
	return changed, nil
}

// restoreDir replays a single checkpoint dir (used by RestoreInFlight on
// signal exit). Equivalent to Restore() but takes a specific dir.
func restoreDir(dir string) error {
	paths, err := readLines(filepath.Join(dir, "FILEPATHS"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for idx, path := range paths {
		src := filepath.Join(dir, filepath.Base(path)+"_"+strconv.Itoa(idx))
		if err := restoreFile(src, path); err != nil {
			return err
		}
	}
	newPaths, err := readLines(filepath.Join(dir, "NEW_FILES"))
	if err == nil {
		for _, p := range newPaths {
			_ = os.Remove(p)
		}
	}
	return os.RemoveAll(dir)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		if s != "" {
			out = append(out, s)
		}
	}
	return out, scanner.Err()
}

func restoreFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("checkpoint: read backup %s: %w", src, err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	// Preserve original mode if dst exists.
	mode := os.FileMode(0o644)
	if info, err := os.Stat(dst); err == nil {
		mode = info.Mode().Perm()
	}
	return os.WriteFile(dst, data, mode)
}

// copyFile (used by tests to verify backups round-trip).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// sanitize trims label down to filesystem-safe characters. Kept for tests
// from the old layout.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}
