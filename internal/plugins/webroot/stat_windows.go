//go:build windows

package webroot

// unixStat is unused on Windows. copyOwnership type-asserts and returns nil.
type unixStat struct {
	Uid uint32
	Gid uint32
}

// setUmask is a no-op on Windows; the umask concept doesn't exist there.
func setUmask(int) int { return 0 }
