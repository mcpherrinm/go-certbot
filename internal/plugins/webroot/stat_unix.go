//go:build !windows

package webroot

import "syscall"

// unixStat aliases the platform stat type so copyOwnership can extract
// uid/gid. Windows doesn't have this; copyOwnership becomes a no-op there.
type unixStat = syscall.Stat_t
