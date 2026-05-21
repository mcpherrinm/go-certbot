package apache

import (
	"os"
	"runtime"
	"strings"
)

// osOptions mirrors Certbot's per-OS overrides (override_centos / _debian /
// _alpine / _gentoo): default config path, control binary, vhost root.
// Selected based on /etc/os-release ID at runtime when the CLI doesn't
// override.
type osOptions struct {
	ConfigPath string // default apache2.conf / httpd.conf
	ServerRoot string // /etc/apache2 / /etc/httpd
	Ctl        string // apachectl / apache2ctl — must be apachectl-style (supports `configtest`/`graceful`)
	A2EnMod    string // a2enmod (Debian); empty when the platform inserts LoadModule directly
	// VHostRoot is the directory where SSL vhost clones (foo-le-ssl.conf)
	// land. Falls back to dirname(ConfigPath) when empty. Mirrors Certbot's
	// per-OS `vhost_root` (override_*.py).
	VHostRoot string
}

var (
	osDebian = osOptions{
		ConfigPath: "/etc/apache2/apache2.conf",
		ServerRoot: "/etc/apache2",
		Ctl:        "apachectl",
		A2EnMod:    "a2enmod",
		VHostRoot:  "/etc/apache2/sites-available",
	}
	// RHEL uses `apachectl` (httpd's wrapper); plain `httpd configtest`
	// fails because `configtest` is an apachectl verb. Cert generation on
	// modern RHEL needs the wrapper. (override_centos.py:18-30)
	osRHEL = osOptions{
		ConfigPath: "/etc/httpd/conf/httpd.conf",
		ServerRoot: "/etc/httpd",
		Ctl:        "apachectl",
		VHostRoot:  "/etc/httpd/conf.d",
	}
	osFedora = osOptions{
		ConfigPath: "/etc/httpd/conf/httpd.conf",
		ServerRoot: "/etc/httpd",
		Ctl:        "apachectl",
		VHostRoot:  "/etc/httpd/conf.d",
	}
	osAlpine = osOptions{
		ConfigPath: "/etc/apache2/httpd.conf",
		ServerRoot: "/etc/apache2",
		// Alpine ships apachectl as a wrapper around httpd; `configtest`
		// and `graceful` are apachectl-only verbs (override_alpine.py).
		Ctl:       "apachectl",
		VHostRoot: "/etc/apache2/conf.d",
	}
	osGentoo = osOptions{
		ConfigPath: "/etc/apache2/httpd.conf",
		ServerRoot: "/etc/apache2",
		Ctl:        "apache2ctl",
		VHostRoot:  "/etc/apache2/vhosts.d",
	}
	osArch = osOptions{
		ConfigPath: "/etc/httpd/conf/httpd.conf",
		ServerRoot: "/etc/httpd",
		Ctl:        "apachectl",
		VHostRoot:  "/etc/httpd/conf", // override_arch.py:11 (siblings of httpd.conf)
	}
	osDarwin = osOptions{
		ConfigPath: "/etc/apache2/httpd.conf",
		ServerRoot: "/etc/apache2",
		Ctl:        "apachectl",
		VHostRoot:  "/etc/apache2/other", // override_darwin.py
	}
	osVoid = osOptions{
		ConfigPath: "/etc/apache/httpd.conf",
		ServerRoot: "/etc/apache",
		Ctl:        "apachectl",
		VHostRoot:  "/etc/apache/extra", // override_void.py
	}
	osSUSE = osOptions{
		ConfigPath: "/etc/apache2/httpd.conf",
		ServerRoot: "/etc/apache2",
		Ctl:        "apachectl",
		VHostRoot:  "/etc/apache2/vhosts.d",
	}
)

// detectOSOptions reads /etc/os-release and returns the matching osOptions.
// On macOS we fall back to the Darwin record (no /etc/os-release there).
// Other dev systems default to Debian.
func detectOSOptions() osOptions {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		if runtime.GOOS == "darwin" {
			return osDarwin
		}
		return osDebian
	}
	id := ""
	idLike := ""
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = v
		case "ID_LIKE":
			idLike = v
		}
	}
	switch id {
	case "debian", "ubuntu", "raspbian", "linuxmint":
		return osDebian
	case "fedora":
		return osFedora
	case "rhel", "centos", "rocky", "almalinux", "amzn", "ol", "cloudlinux", "scientific":
		return osRHEL
	case "alpine":
		return osAlpine
	case "gentoo":
		return osGentoo
	case "arch", "manjaro":
		return osArch
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "suse":
		return osSUSE
	case "darwin", "macos":
		return osDarwin
	case "void":
		return osVoid
	}
	// macOS doesn't ship /etc/os-release; detect via runtime.GOOS
	// elsewhere if needed. The hard-coded build-tag detection lives in
	// detectByGOOS (called after this map fails).
	for _, like := range strings.Fields(idLike) {
		switch like {
		case "debian":
			return osDebian
		case "fedora":
			return osFedora
		case "rhel":
			return osRHEL
		case "suse":
			return osSUSE
		case "arch":
			return osArch
		}
	}
	return osDebian
}
