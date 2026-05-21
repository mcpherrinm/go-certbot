// Command go-certbot is an experimental Go rewrite of Certbot built on top of
// lego v5. See CHANGES.md for compatibility notes vs. upstream Certbot 5.x.
package main

import (
	"os"

	"github.com/letsencrypt/go-certbot/internal/cmd"
)

func main() {
	os.Exit(cmd.Main(os.Args[1:]))
}
