//go:build windows

package webroot

// unixStat is unused on Windows. copyOwnership type-asserts and returns nil.
type unixStat struct {
	Uid uint32
	Gid uint32
}
