// Package extenv builds the environment slice passed to external programs
// invoked by go-certbot (hooks, nginx/apache reload, etc.).
//
// Mirrors certbot.util.env_no_snap_for_external_calls: when go-certbot is
// installed as a snap, the snap runtime pre-loads private builds of
// OpenSSL/Python via SNAP*, LD_LIBRARY_PATH, OPENSSL_MODULES,
// OPENSSL_FORCE_FIPS_MODE, and PYTHONPATH. Forwarding those into nginx or
// apache (or a user hook) will pin the child process to the snap's libc and
// can break ABI-sensitive operations like loading OpenSSL providers.
package extenv

import (
	"os"
	"strings"
)

// Env returns os.Environ() with snap-specific entries stripped or pared
// down. Used in place of an unset cmd.Env so the child process inherits the
// usual locale, PATH, HOME, etc.
//
// Behavior:
//   - drop SNAP* (SNAP, SNAP_INSTANCE_NAME, etc.)
//   - drop LD_PRELOAD, PYTHONPATH, OPENSSL_MODULES, OPENSSL_FORCE_FIPS_MODE
//   - for PATH and LD_LIBRARY_PATH, remove only the colon-separated entries
//     that live under /snap/ — preserve the rest. (Dropping LD_LIBRARY_PATH
//     wholesale would, on some distros, also remove ld.so cache hints set by
//     the operator.)
func Env() []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	for _, e := range src {
		i := strings.IndexByte(e, '=')
		if i <= 0 {
			out = append(out, e)
			continue
		}
		k, v := e[:i], e[i+1:]
		switch {
		case strings.HasPrefix(k, "SNAP"):
			continue
		case k == "LD_PRELOAD", k == "PYTHONPATH",
			k == "OPENSSL_MODULES", k == "OPENSSL_FORCE_FIPS_MODE":
			continue
		case k == "PATH", k == "LD_LIBRARY_PATH":
			if cleaned := stripSnapEntries(v); cleaned != "" {
				out = append(out, k+"="+cleaned)
			}
		default:
			out = append(out, e)
		}
	}
	return out
}

func stripSnapEntries(v string) string {
	parts := strings.Split(v, ":")
	kept := parts[:0]
	for _, p := range parts {
		if strings.HasPrefix(p, "/snap/") || strings.Contains(p, "/snap/core") {
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, ":")
}
