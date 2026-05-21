//go:build !windows

package storage

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// copyGroupOwnership chowns dst to share gid with src (user owner left
// unchanged). Mirrors certbot.compat.filesystem.copy_ownership_and_apply_mode
// with copy_user=False, copy_group=True. POSIX-only — Windows builds use a
// no-op.
//
// Best-effort: on EPERM (typical when not root and not in src's group) we
// log and swallow rather than fail the renewal. Certbot does the same.
func copyGroupOwnership(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if err := os.Chown(dst, -1, int(sys.Gid)); err != nil {
		// Permission errors are common when not root; don't fail the
		// renewal. Mirrors Certbot's silent best-effort.
		var pErr *fs.PathError
		if errors.As(err, &pErr) {
			if errors.Is(pErr.Err, syscall.EPERM) {
				return nil
			}
		}
		return err
	}
	return nil
}
