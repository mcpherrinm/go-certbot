package apache

import "testing"

func TestDetectOSOptionsFallback(t *testing.T) {
	// On macOS / dev systems with no /etc/os-release, we should fall back
	// to Debian defaults. This is the "default" path inside detectOSOptions.
	opts := detectOSOptions()
	if opts.ConfigPath == "" || opts.Ctl == "" {
		t.Errorf("default options missing fields: %+v", opts)
	}
}

func TestRewritePortIPv6(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"*:80", "*:443"},
		{"_default_:80", "_default_:443"},
		{"1.2.3.4:80", "1.2.3.4:443"},
		{"[::1]:80", "[::1]:443"},
		{`"[::1]:80"`, `"[::1]:443"`},
		{"*", "*"},                             // no port, unchanged
		{"unix:/var/run/apache.sock", "unix:/var/run/apache.sock"}, // no port suffix
	}
	for _, tc := range cases {
		got := rewritePortIn(tc.in, "80", "443")
		if got != tc.want {
			t.Errorf("rewritePortIn(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
