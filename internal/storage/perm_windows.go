//go:build windows

package storage

// copyGroupOwnership is a no-op on Windows. Certbot's equivalent
// `copy_ownership_and_apply_mode` with copy_group=True is also a no-op
// on Windows: filesystem.compute_private_key_mode (filesystem.py:467-468)
// returns base_mode unchanged, and copy_ownership_and_apply_mode skips the
// chown call.
func copyGroupOwnership(src, dst string) error { return nil }
