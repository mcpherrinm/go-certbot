package apache

import (
	"os"
	"strings"
)

// osOptions mirrors Certbot's per-OS overrides (override_centos / _debian /
// _alpine / _gentoo): default config path, control binary, vhost root.
// Selected based on /etc/os-release ID at runtime when the CLI doesn't
// override.
type osOptions struct {
	ConfigPath string // default apache2.conf / httpd.conf
	ServerRoot string // /etc/apache2 / /etc/httpd
	Ctl        string // apachectl / httpd
	A2EnMod    string // a2enmod (Debian); empty when the platform inserts LoadModule directly
}

var (
	osDebian = osOptions{
		ConfigPath: "/etc/apache2/apache2.conf",
		ServerRoot: "/etc/apache2",
		Ctl:        "apachectl",
		A2EnMod:    "a2enmod",
	}
	osRHEL = osOptions{
		ConfigPath: "/etc/httpd/conf/httpd.conf",
		ServerRoot: "/etc/httpd",
		Ctl:        "httpd",
	}
	osAlpine = osOptions{
		ConfigPath: "/etc/apache2/httpd.conf",
		ServerRoot: "/etc/apache2",
		Ctl:        "httpd",
	}
	osGentoo = osOptions{
		ConfigPath: "/etc/apache2/httpd.conf",
		ServerRoot: "/etc/apache2",
		Ctl:        "apache2ctl",
	}
)

// detectOSOptions reads /etc/os-release and returns the matching osOptions.
// Defaults to Debian when nothing matches (and on macOS/dev systems).
func detectOSOptions() osOptions {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
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
	case "rhel", "centos", "fedora", "rocky", "almalinux", "amzn", "ol":
		return osRHEL
	case "alpine":
		return osAlpine
	case "gentoo":
		return osGentoo
	}
	for _, like := range strings.Fields(idLike) {
		switch like {
		case "debian":
			return osDebian
		case "rhel", "fedora":
			return osRHEL
		}
	}
	return osDebian
}
