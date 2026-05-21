// Package checkpoint records file snapshots so installer mutations can be
// rolled back. The on-disk layout matches certbot.reverter so a checkpoint
// written by go-certbot is recoverable by Certbot's `certbot rollback`, and
// vice-versa:
//
//	<work_dir>/in-progress/
//	    FILEPATHS        # original absolute paths, one per line
//	    CHANGES_SINCE    # human-readable note about what changed
//	    NEW_FILES        # files that were CREATED (rollback deletes them)
//	    <basename>_<idx> # backed-up content, indexed against FILEPATHS
//
// On successful run completion the caller invokes MarkClean (the reverter
// equivalent of finalize_checkpoint) which atomically renames the in-progress
// dir to <work_dir>/backups/<timestamp>/. A crash that drops the run before
// MarkClean leaves the in-progress dir on disk; RecoverInterrupted (called at
// startup) restores from it and clears it, matching Certbot's recovery_routine
// (reverter.py:80-104).
//
// `<timestamp>` is a Unix-timestamp string (e.g. "1716239876.0408928") so
// dirs sort lexically by creation time.
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

// IN_PROGRESS_DIR mirrors Certbot constants.IN_PROGRESS_DIR. Lives directly
// under work_dir; not a per-run path.
const inProgressName = "in-progress"

// tempCheckpointName mirrors Certbot constants.TEMP_CHECKPOINT_DIR.
const tempCheckpointName = "temp_checkpoint"

var (
	inFlightMu sync.Mutex
	// inFlightDir is the working in-progress dir (or "" if none).
	inFlightDir string
)

// markInFlight records dir as the currently open checkpoint.
func markInFlight(dir string) {
	inFlightMu.Lock()
	inFlightDir = dir
	inFlightMu.Unlock()
}

// MarkClean atomically promotes the in-progress checkpoint to a permanent
// timestamped backup under <work_dir>/backups/, then clears the in-flight
// marker so a subsequent signal will not roll it back.
func MarkClean() {
	inFlightMu.Lock()
	dir := inFlightDir
	inFlightDir = ""
	inFlightMu.Unlock()
	if dir == "" {
		return
	}
	if _, err := os.Stat(dir); err != nil {
		return
	}
	workDir := filepath.Dir(dir)
	base := filepath.Join(workDir, "backups")
	_ = os.MkdirAll(base, 0o755)
	stamp, err := nextTimestamp(base)
	if err != nil {
		return
	}
	final := filepath.Join(base, stamp)
	_ = os.Rename(dir, final)
}

// RestoreInFlight restores the most recent in-flight checkpoint (if any),
// matching what Certbot's error_handler does for a signal-interrupted run.
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

// RecoverInterrupted is called at process startup to roll back a stale
// <work_dir>/in-progress/ left over by a crashed earlier run. Mirrors
// Certbot's Reverter.recovery_routine (reverter.py:80-104).
func RecoverInterrupted(workDir string) error {
	dir := filepath.Join(workDir, inProgressName)
	if _, err := os.Stat(dir); err != nil {
		return nil
	}
	return restoreDir(dir)
}

// Save appends file snapshots to the in-progress checkpoint. The first call
// in a run creates <work_dir>/in-progress/; subsequent calls append to it
// until MarkClean promotes the directory. Returns the checkpoint dir path,
// or "" if no files were available to back up.
func Save(workDir, label string, paths []string) (string, error) {
	dir := filepath.Join(workDir, inProgressName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("checkpoint: mkdir %s: %w", dir, err)
	}
	// Already-recorded paths so duplicate Save() calls don't re-snapshot
	// (matches Certbot's _add_to_checkpoint_dir dedup).
	existing, _ := readLines(filepath.Join(dir, "FILEPATHS"))
	existingSet := map[string]bool{}
	for _, p := range existing {
		existingSet[p] = true
	}
	idx := len(existing)
	var addedFiles, addedNew []string
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		if existingSet[abs] {
			continue
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				addedNew = append(addedNew, abs)
				continue
			}
			return "", fmt.Errorf("checkpoint: read %s: %w", abs, err)
		}
		dst := filepath.Join(dir, filepath.Base(abs)+"_"+strconv.Itoa(idx))
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return "", err
		}
		// Preserve mtime so installers using stat-based change detection
		// (e.g. apache .conf reload) see a faithful restore.
		if info, err := os.Stat(abs); err == nil {
			_ = os.Chtimes(dst, info.ModTime(), info.ModTime())
		}
		addedFiles = append(addedFiles, abs)
		idx++
	}
	if len(addedFiles) == 0 && len(existing) == 0 {
		// Nothing to back up. NEW_FILES on its own doesn't justify holding
		// open a checkpoint — the caller typically registers
		// to-be-created paths via a different code path.
		_ = os.RemoveAll(dir)
		return "", nil
	}
	for _, p := range addedFiles {
		if err := appendLine(filepath.Join(dir, "FILEPATHS"), p); err != nil {
			return "", err
		}
	}
	for _, p := range addedNew {
		if err := appendLine(filepath.Join(dir, "NEW_FILES"), p); err != nil {
			return "", err
		}
	}
	if label != "" {
		if err := appendLine(filepath.Join(dir, "CHANGES_SINCE"), label); err != nil {
			return "", err
		}
	}
	markInFlight(dir)
	return dir, nil
}

// nextTimestamp picks a timestamp-named string that sorts after every
// existing entry under base. Mirrors Certbot's _checkpoint_timestamp
// (reverter.py:485-503) — uses str(time.time())-style variable-length
// fractional seconds rather than fixed-6.
func nextTimestamp(base string) (string, error) {
	stamp := formatPyTime(time.Now())
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
		v, _ := strconv.ParseFloat(others[len(others)-1], 64)
		stamp = formatPyFloat(v + 1)
	} else if len(others) >= 2 && others[len(others)-2] == stamp {
		v, _ := strconv.ParseFloat(others[len(others)-1], 64)
		stamp = formatPyFloat(v + 0.01)
	}
	return stamp, nil
}

// formatPyTime emits "{int}.{usec}" similar to Python's str(time.time()).
func formatPyTime(t time.Time) string {
	whole := t.Unix()
	usec := t.Nanosecond() / 1000
	return fmt.Sprintf("%d.%06d", whole, usec)
}

func formatPyFloat(v float64) string {
	// Python's float-to-str rendering uses repr which trims trailing
	// zeros; %g approximates this for our timestamp range.
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
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
		newPaths, err := readLines(filepath.Join(dir, "NEW_FILES"))
		if err == nil {
			for _, p := range newPaths {
				if err := os.Remove(p); err == nil {
					changed = append(changed, p)
				}
			}
		}
		_ = os.RemoveAll(dir)
	}
	return changed, nil
}

// restoreDir replays a single checkpoint dir (used by RestoreInFlight on
// signal exit and RecoverInterrupted at startup).
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

// restoreFile is the shutil.copy2 equivalent: preserves both file mode and
// mtime from the backup copy (which itself captured the original mtime in
// Save). On dst pre-existing, the existing mode is preferred since it
// reflects the installer's most recent setting.
func restoreFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("checkpoint: read backup %s: %w", src, err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(dst); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".rb.*")
	if err != nil {
		return err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return err
	}
	if info, err := os.Stat(src); err == nil {
		_ = os.Chtimes(dst, info.ModTime(), info.ModTime())
	}
	return nil
}

// SaveTemp adds files to the temp_checkpoint dir, which Certbot uses for
// "this-run-only" snapshots that should be wiped at finalize regardless of
// outcome (e.g. an installer's transient state). The current go-certbot
// caller set doesn't yet need this, but the directory is reserved to match
// Certbot's reverter.py layout.
func SaveTemp(workDir, label string, paths []string) (string, error) {
	dir := filepath.Join(workDir, tempCheckpointName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return saveInto(dir, label, paths)
}

// saveInto is the body of Save/SaveTemp parameterized by destination.
func saveInto(dir, label string, paths []string) (string, error) {
	existing, _ := readLines(filepath.Join(dir, "FILEPATHS"))
	existingSet := map[string]bool{}
	for _, p := range existing {
		existingSet[p] = true
	}
	idx := len(existing)
	var addedFiles, addedNew []string
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		if existingSet[abs] {
			continue
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				addedNew = append(addedNew, abs)
				continue
			}
			return "", err
		}
		dst := filepath.Join(dir, filepath.Base(abs)+"_"+strconv.Itoa(idx))
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return "", err
		}
		if info, err := os.Stat(abs); err == nil {
			_ = os.Chtimes(dst, info.ModTime(), info.ModTime())
		}
		addedFiles = append(addedFiles, abs)
		idx++
	}
	for _, p := range addedFiles {
		_ = appendLine(filepath.Join(dir, "FILEPATHS"), p)
	}
	for _, p := range addedNew {
		_ = appendLine(filepath.Join(dir, "NEW_FILES"), p)
	}
	if label != "" {
		_ = appendLine(filepath.Join(dir, "CHANGES_SINCE"), label)
	}
	return dir, nil
}

// (sanitize / copyFile remain for test helpers in checkpoint_test.go)

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
