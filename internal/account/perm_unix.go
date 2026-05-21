//go:build !windows

package account

import (
	"fmt"
	"os"
	"syscall"
)

// strictCheckDir refuses to operate on dir when it exists and is owned by
// a different uid than the running process. Matches Certbot's
// util.check_permissions semantics when --strict-permissions is set.
func strictCheckDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("account: --strict-permissions: %s is owned by uid %d (running as %d)",
			dir, stat.Uid, os.Geteuid())
	}
	return nil
}
