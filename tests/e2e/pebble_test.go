// Package e2e is the end-to-end harness: starts a Pebble ACME server,
// drives the go-certbot binary against it, and asserts on the on-disk state.
//
// The tests skip cleanly when `pebble` isn't on PATH, so they can live in the
// standard `go test ./...` run without forcing a Pebble dependency on every
// contributor. To run them locally:
//
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
//	go test ./tests/e2e -v -run E2E
//
// Background: Pebble exposes its ACME directory at https://localhost:14000/dir
// with a self-signed TLS cert and (via the bundled `pebble-challtestsrv`) a
// DNS server we point at 127.0.0.1, so HTTP-01 validation reaches our
// in-process standalone server.
package e2e

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/go-certbot/internal/cmd"
)

// requirePebble looks for `pebble` and `pebble-challtestsrv` on PATH and
// reports a clear skip message if either is missing.
func requirePebble(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pebble"); err != nil {
		t.Skip("pebble binary not on PATH; install with " +
			"`go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest`")
	}
	if _, err := exec.LookPath("pebble-challtestsrv"); err != nil {
		t.Skip("pebble-challtestsrv binary not on PATH; install with " +
			"`go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest`")
	}
}

// pebbleHarness is a running Pebble instance + chall test server.
type pebbleHarness struct {
	configDir string
	pebble    *exec.Cmd
	chall     *exec.Cmd
	dirURL    string
	httpPort  int
}

func (h *pebbleHarness) stop() {
	if h.pebble != nil && h.pebble.Process != nil {
		_ = h.pebble.Process.Kill()
		_ = h.pebble.Wait()
	}
	if h.chall != nil && h.chall.Process != nil {
		_ = h.chall.Process.Kill()
		_ = h.chall.Wait()
	}
}

// startPebble launches both processes and returns once Pebble responds to a
// directory request. A self-signed cert is generated for Pebble's ACME
// listener so the test doesn't depend on Pebble's bundled test certs (which
// don't ship with `go install`).
func startPebble(t *testing.T) *pebbleHarness {
	t.Helper()
	requirePebble(t)
	dir := t.TempDir()

	certPath, keyPath, err := writeSelfSignedCert(dir, "localhost")
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}

	cfg := fmt.Sprintf(`{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": %q,
    "privateKey": %q,
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}`, certPath, keyPath)
	cfgPath := filepath.Join(dir, "pebble.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// pebble-challtestsrv: -dns01 8053 makes it serve DNS responses, and
	// -defaultIPv4 127.0.0.1 makes any A lookup return 127.0.0.1 so we
	// don't need to register every domain we test against.
	chall := exec.Command("pebble-challtestsrv",
		"-management", ":8055",
		"-http01", "",
		"-https01", "",
		"-tlsalpn01", "",
		"-dns01", ":8053",
		"-defaultIPv4", "127.0.0.1",
		"-defaultIPv6", "")
	chall.Stdout = io.Discard
	chall.Stderr = io.Discard
	if err := chall.Start(); err != nil {
		t.Fatalf("start pebble-challtestsrv: %v", err)
	}
	pebble := exec.Command("pebble", "-config", cfgPath, "-strict",
		"-dnsserver", "127.0.0.1:8053")
	pebble.Stdout = io.Discard
	pebble.Stderr = io.Discard
	pebble.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1")
	if err := pebble.Start(); err != nil {
		_ = chall.Process.Kill()
		t.Fatalf("start pebble: %v", err)
	}

	h := &pebbleHarness{
		configDir: dir,
		pebble:    pebble,
		chall:     chall,
		dirURL:    "https://localhost:14000/dir",
		httpPort:  5002,
	}
	if err := waitFor("https://localhost:14000/dir", 15*time.Second); err != nil {
		h.stop()
		t.Fatalf("pebble didn't come up: %v", err)
	}
	return h
}

// waitFor polls a URL with TLS verification disabled until 200, or timeout.
func waitFor(url string, timeout time.Duration) error {
	client := &http.Client{
		Timeout:   500 * time.Millisecond,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("timed out waiting for " + url)
}

// freePort returns an ephemeral TCP port number. Pebble's pebble-challtestsrv
// HTTP-01 server expects our standalone to bind to 5002 specifically, so this
// helper isn't used for the challenge — only for sanity.
func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 5002
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestE2EStandaloneIssuance issues a cert via standalone against Pebble and
// verifies the on-disk state matches Certbot's layout.
func TestE2EStandaloneIssuance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e under -short")
	}
	h := startPebble(t)
	defer h.stop()

	domain := "example.test"
	leDir := t.TempDir()
	args := []string{
		"certonly",
		"--standalone",
		"--server", h.dirURL,
		"--no-verify-ssl",
		"--agree-tos",
		"--register-unsafely-without-email",
		"--non-interactive",
		"--http-01-port", strconv.Itoa(h.httpPort),
		"-d", domain,
		"--config-dir", leDir,
		"--work-dir", filepath.Join(leDir, "work"),
		"--logs-dir", filepath.Join(leDir, "logs"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_ = ctx // not threaded through cmd.Main yet; reserved for cancellation

	code := cmd.Main(args)
	if code != 0 {
		t.Fatalf("cmd.Main returned %d", code)
	}

	// Verify accounts/<server>/<id>/{regr,private_key,meta}.json all exist.
	accounts := filepath.Join(leDir, "accounts", "localhost:14000", "dir")
	entries, err := os.ReadDir(accounts)
	if err != nil {
		t.Fatalf("accounts dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 account dir, got %d", len(entries))
	}
	for _, name := range []string{"regr.json", "private_key.json", "meta.json"} {
		if _, err := os.Stat(filepath.Join(accounts, entries[0].Name(), name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}

	// Verify live/<domain>/{cert,privkey,chain,fullchain}.pem all exist as
	// symlinks pointing into archive/.
	live := filepath.Join(leDir, "live", domain)
	for _, name := range []string{"cert.pem", "privkey.pem", "chain.pem", "fullchain.pem"} {
		full := filepath.Join(live, name)
		info, err := os.Lstat(full)
		if err != nil {
			t.Errorf("missing %s: %v", name, err)
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Errorf("%s is not a symlink", name)
		}
	}

	// Verify renewal/<domain>.conf has at least the expected keys.
	confPath := filepath.Join(leDir, "renewal", domain+".conf")
	b, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("renewal conf: %v", err)
	}
	conf := string(b)
	for _, want := range []string{
		"cert =", "privkey =", "chain =", "fullchain =",
		"[renewalparams]", "authenticator = standalone", "domains = " + domain + ",",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("renewal conf missing %q:\n%s", want, conf)
		}
	}
}

// TestE2ECertificatesListsIssuedCert checks the `certificates` verb prints
// the lineage after a successful issuance.
func TestE2ECertificatesListsIssuedCert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e under -short")
	}
	h := startPebble(t)
	defer h.stop()

	domain := "list.example.test"
	leDir := t.TempDir()
	issue := []string{
		"certonly", "--standalone",
		"--server", h.dirURL, "--no-verify-ssl",
		"--agree-tos", "--register-unsafely-without-email", "--non-interactive",
		"--http-01-port", strconv.Itoa(h.httpPort),
		"-d", domain,
		"--config-dir", leDir,
		"--work-dir", filepath.Join(leDir, "work"),
		"--logs-dir", filepath.Join(leDir, "logs"),
	}
	if code := cmd.Main(issue); code != 0 {
		t.Fatalf("issue: cmd.Main returned %d", code)
	}

	// Capture stdout for `certificates`.
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	list := []string{
		"certificates",
		"--config-dir", leDir,
		"--work-dir", filepath.Join(leDir, "work"),
		"--logs-dir", filepath.Join(leDir, "logs"),
	}
	code := cmd.Main(list)
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	if code != 0 {
		t.Fatalf("certificates: cmd.Main returned %d\n%s", code, out)
	}
	got := string(out)
	for _, want := range []string{
		"Certificate Name: " + domain,
		"Identifiers: " + domain,
		"VALID:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("certificates output missing %q:\n%s", want, got)
		}
	}
}

// keep fmt-import lit
var _ = fmt.Sprint
