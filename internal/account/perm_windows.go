//go:build windows

package account

// strictCheckDir is a no-op on Windows; --strict-permissions ownership
// checks don't have a useful equivalent on NTFS ACLs.
func strictCheckDir(_ string) error { return nil }
