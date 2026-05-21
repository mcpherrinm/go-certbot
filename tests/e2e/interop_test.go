// Interoperability test: run real Certbot to issue + register, then drive
// go-certbot against the same /etc/letsencrypt-shaped config dir and
// confirm go-certbot reuses Certbot's account, writes its own lineage,
// and the resulting on-disk state remains valid for both tools.
//
// Requires `certbot` on PATH (or `CERTBOT_BIN` env var pointing at the
// binary). Skips cleanly when Certbot isn't installed. Install Certbot:
//
//	pipx install certbot
//	# or
//	python3 -m pip install --user certbot
//
// To run this test in isolation:
//
//	go test ./tests/e2e -v -run TestE2EInterop

package e2e

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/go-certbot/internal/cmd"
)

// findCertbot returns the certbot binary path, or "" if not available.
// Honors CERTBOT_BIN env override first.
func findCertbot() string {
	if p := os.Getenv("CERTBOT_BIN"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("certbot"); err == nil {
		return p
	}
	return ""
}

// runCertbot executes certbot with the given args, capturing combined
// output for the test log. Returns the exit code (0 on success) and the
// captured output for diagnostics.
func runCertbot(t *testing.T, ctx context.Context, bin string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, bin, args...)
	// Force Python flushes and ensure certbot writes to our temp dirs even
	// when run by a non-root user. PYTHONDONTWRITEBYTECODE keeps __pycache__
	// out of our temp dirs.
	cmd.Env = append(os.Environ(),
		"PYTHONUNBUFFERED=1",
		"PYTHONDONTWRITEBYTECODE=1",
	)
	out, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("certbot exec error: %v\n%s", err, out)
	}
	return 0, string(out)
}

// TestE2EInterop runs both Certbot and go-certbot against the same Pebble
// instance and the same on-disk config dir, exercising the "user
// auto-upgrades from Certbot to go-certbot" drop-in compatibility story.
//
// Order:
//  1. Certbot certonly --standalone -d cb.example.test (creates account,
//     writes lineage)
//  2. go-certbot certificates --config-dir <same> (must list Certbot's lineage)
//  3. go-certbot certonly --standalone -d gc.example.test --config-dir <same>
//     (must reuse Certbot's account, issue a new lineage)
//  4. Inspect accounts/ — exactly ONE account dir.
//  5. Inspect both lineages (live + renewal conf) — both intact.
//
// Then we also try the OTHER direction:
//  6. Certbot certificates --config-dir <same> — must list both lineages
//     (proves go-certbot's renewal.conf is parseable by Certbot).
func TestE2EInterop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping interop test under -short")
	}
	certbotBin := findCertbot()
	if certbotBin == "" {
		t.Skip("certbot not on PATH; install with `pipx install certbot` (or set CERTBOT_BIN)")
	}
	h := startPebble(t)
	defer h.stop()

	leDir := t.TempDir()
	workDir := filepath.Join(leDir, "work")
	logsDir := filepath.Join(leDir, "logs")

	// --- Step 1: Certbot issues a cert. ---------------------------------
	cbDomain := "cb.example.test"
	cbArgs := []string{
		"certonly",
		"--standalone",
		"--server", h.dirURL,
		"--no-verify-ssl",
		"--agree-tos",
		"--register-unsafely-without-email",
		"--non-interactive",
		"--http-01-port", strconv.Itoa(h.httpPort),
		"-d", cbDomain,
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	code, out := runCertbot(t, ctx, certbotBin, cbArgs...)
	if code != 0 {
		t.Fatalf("certbot certonly exited %d\n%s", code, out)
	}
	t.Logf("certbot certonly OK (output: %s)", trim(out))

	// Verify Certbot's account dir landed where we expect.
	accountsRoot := filepath.Join(leDir, "accounts", "localhost:14000", "dir")
	cbAccounts, err := os.ReadDir(accountsRoot)
	if err != nil {
		t.Fatalf("read certbot accounts dir: %v", err)
	}
	if len(cbAccounts) != 1 {
		t.Fatalf("expected 1 account after certbot, got %d", len(cbAccounts))
	}
	certbotAccountID := cbAccounts[0].Name()
	t.Logf("certbot account id = %s", certbotAccountID)

	// Quick sanity: regr.json, private_key.json, meta.json all there.
	for _, name := range []string{"regr.json", "private_key.json", "meta.json"} {
		full := filepath.Join(accountsRoot, certbotAccountID, name)
		if _, err := os.Stat(full); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}

	// Confirm Certbot's lineage is in place.
	cbLive := filepath.Join(leDir, "live", cbDomain, "fullchain.pem")
	if _, err := os.Stat(cbLive); err != nil {
		t.Fatalf("certbot lineage missing %s: %v", cbLive, err)
	}

	// --- Step 2: go-certbot `certificates` reads Certbot's lineage. -----
	out, code = runGoCertbot(t, []string{
		"certificates",
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
	})
	if code != 0 {
		t.Fatalf("go-certbot certificates exited %d\n%s", code, out)
	}
	if !strings.Contains(out, cbDomain) {
		t.Errorf("go-certbot certificates didn't list %s:\n%s", cbDomain, out)
	}

	// --- Step 3: go-certbot issues a NEW lineage using Certbot's account.
	gcDomain := "gc.example.test"
	gcArgs := []string{
		"certonly",
		"--standalone",
		"--server", h.dirURL,
		"--no-verify-ssl",
		"--agree-tos",
		"--register-unsafely-without-email",
		"--non-interactive",
		"--http-01-port", strconv.Itoa(h.httpPort),
		"-d", gcDomain,
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
	}
	if code := cmd.Main(gcArgs); code != 0 {
		t.Fatalf("go-certbot certonly returned %d", code)
	}

	// --- Step 4: accounts/ still has exactly one dir (no re-registration).
	afterAccounts, err := os.ReadDir(accountsRoot)
	if err != nil {
		t.Fatalf("read accounts dir after go-certbot: %v", err)
	}
	if len(afterAccounts) != 1 {
		var names []string
		for _, e := range afterAccounts {
			names = append(names, e.Name())
		}
		t.Fatalf("go-certbot created a second account; expected 1 dir, got %d: %v",
			len(afterAccounts), names)
	}
	if afterAccounts[0].Name() != certbotAccountID {
		t.Errorf("go-certbot replaced the account dir: was %s, now %s",
			certbotAccountID, afterAccounts[0].Name())
	}

	// --- Step 5: both lineages are intact. ------------------------------
	for _, d := range []string{cbDomain, gcDomain} {
		fc := filepath.Join(leDir, "live", d, "fullchain.pem")
		if _, err := os.Stat(fc); err != nil {
			t.Errorf("lineage %s: missing %s: %v", d, fc, err)
		}
		conf := filepath.Join(leDir, "renewal", d+".conf")
		if _, err := os.Stat(conf); err != nil {
			t.Errorf("lineage %s: missing %s: %v", d, conf, err)
		}
	}

	// --- Step 6: Certbot can read go-certbot's lineage. -----------------
	// `certbot certificates` walks renewal/*.conf and prints each.
	code, out = runCertbot(t, ctx, certbotBin,
		"certificates",
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
		// no-verify-ssl isn't strictly required for certificates verb
		// (no ACME calls), but the underlying NamespaceConfig still
		// dial-tests with the directory URL on some code paths.
		"--server", h.dirURL,
		"--no-verify-ssl",
	)
	if code != 0 {
		t.Fatalf("certbot certificates after go-certbot exited %d\n%s", code, out)
	}
	for _, want := range []string{cbDomain, gcDomain} {
		if !strings.Contains(out, want) {
			t.Errorf("certbot certificates didn't list %s:\n%s", want, out)
		}
	}
}

// TestE2EInteropRenew exercises the other direction: certbot issues, then
// go-certbot renews the SAME lineage. Verifies go-certbot picks up the
// lineage's settings and writes a new archive version Certbot can keep
// renewing.
func TestE2EInteropRenew(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping interop test under -short")
	}
	certbotBin := findCertbot()
	if certbotBin == "" {
		t.Skip("certbot not on PATH; install with `pipx install certbot` (or set CERTBOT_BIN)")
	}
	h := startPebble(t)
	defer h.stop()

	leDir := t.TempDir()
	workDir := filepath.Join(leDir, "work")
	logsDir := filepath.Join(leDir, "logs")
	domain := "renew.example.test"

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Certbot issues.
	code, out := runCertbot(t, ctx, certbotBin,
		"certonly", "--standalone",
		"--server", h.dirURL, "--no-verify-ssl",
		"--agree-tos", "--register-unsafely-without-email", "--non-interactive",
		"--http-01-port", strconv.Itoa(h.httpPort),
		"-d", domain,
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
	)
	if code != 0 {
		t.Fatalf("certbot certonly exited %d\n%s", code, out)
	}

	v1 := filepath.Join(leDir, "archive", domain, "cert1.pem")
	if _, err := os.Stat(v1); err != nil {
		t.Fatalf("certbot didn't write archive/%s/cert1.pem: %v", domain, err)
	}

	// go-certbot renew --force-renewal --cert-name <domain>.
	gcArgs := []string{
		"renew",
		"--force-renewal",
		"--cert-name", domain,
		"--server", h.dirURL,
		"--no-verify-ssl",
		"--http-01-port", strconv.Itoa(h.httpPort),
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
		"--non-interactive",
	}
	if code := cmd.Main(gcArgs); code != 0 {
		t.Fatalf("go-certbot renew returned %d", code)
	}

	// We expect a new archive version: cert2.pem.
	v2 := filepath.Join(leDir, "archive", domain, "cert2.pem")
	if _, err := os.Stat(v2); err != nil {
		t.Errorf("go-certbot didn't write archive/%s/cert2.pem after renew: %v", domain, err)
	}

	// And live/<domain>/cert.pem should point at the new version.
	live := filepath.Join(leDir, "live", domain, "cert.pem")
	target, err := os.Readlink(live)
	if err != nil {
		t.Fatalf("readlink %s: %v", live, err)
	}
	if !strings.HasSuffix(target, "cert2.pem") {
		t.Errorf("live cert.pem points at %s, want cert2.pem", target)
	}
}

// TestE2EInteropGoCertbotFirst is the mirror of TestE2EInterop:
// go-certbot issues + registers, then Certbot lists/renews against the
// same config dir. Exercises the "Certbot reads go-certbot state"
// direction.
//
// Order:
//  1. go-certbot certonly --standalone -d gc.example.test (creates
//     account, writes lineage)
//  2. certbot certificates --config-dir <same> (must list go-certbot's
//     lineage — proves Certbot parses our renewal.conf)
//  3. certbot certonly --standalone -d cb.example.test --config-dir
//     <same> (must reuse go-certbot's account, issue a new lineage)
//  4. accounts/ still has exactly ONE account dir (no re-registration)
//  5. both lineages intact
//  6. go-certbot certificates can list both
func TestE2EInteropGoCertbotFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping interop test under -short")
	}
	certbotBin := findCertbot()
	if certbotBin == "" {
		t.Skip("certbot not on PATH; install with `pipx install certbot` (or set CERTBOT_BIN)")
	}
	h := startPebble(t)
	defer h.stop()

	leDir := t.TempDir()
	workDir := filepath.Join(leDir, "work")
	logsDir := filepath.Join(leDir, "logs")

	// --- Step 1: go-certbot issues a cert. -----------------------------
	gcDomain := "gc.example.test"
	gcArgs := []string{
		"certonly",
		"--standalone",
		"--server", h.dirURL,
		"--no-verify-ssl",
		"--agree-tos",
		"--register-unsafely-without-email",
		"--non-interactive",
		"--http-01-port", strconv.Itoa(h.httpPort),
		"-d", gcDomain,
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
	}
	if code := cmd.Main(gcArgs); code != 0 {
		t.Fatalf("go-certbot certonly returned %d", code)
	}

	accountsRoot := filepath.Join(leDir, "accounts", "localhost:14000", "dir")
	gcAccounts, err := os.ReadDir(accountsRoot)
	if err != nil {
		t.Fatalf("read go-certbot accounts dir: %v", err)
	}
	if len(gcAccounts) != 1 {
		t.Fatalf("expected 1 account after go-certbot, got %d", len(gcAccounts))
	}
	goCertbotAccountID := gcAccounts[0].Name()
	t.Logf("go-certbot account id = %s", goCertbotAccountID)

	gcLive := filepath.Join(leDir, "live", gcDomain, "fullchain.pem")
	if _, err := os.Stat(gcLive); err != nil {
		t.Fatalf("go-certbot lineage missing %s: %v", gcLive, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// --- Step 2: certbot `certificates` reads go-certbot's lineage. -----
	// This proves Certbot can parse our account JSON + renewal.conf.
	code, out := runCertbot(t, ctx, certbotBin,
		"certificates",
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
		"--server", h.dirURL,
		"--no-verify-ssl",
	)
	if code != 0 {
		t.Fatalf("certbot certificates after go-certbot exited %d\n%s", code, out)
	}
	if !strings.Contains(out, gcDomain) {
		t.Errorf("certbot certificates didn't list %s:\n%s", gcDomain, out)
	}

	// --- Step 3: certbot issues a new lineage using go-certbot's account.
	cbDomain := "cb.example.test"
	code, out = runCertbot(t, ctx, certbotBin,
		"certonly", "--standalone",
		"--server", h.dirURL, "--no-verify-ssl",
		"--agree-tos", "--register-unsafely-without-email", "--non-interactive",
		"--http-01-port", strconv.Itoa(h.httpPort),
		"-d", cbDomain,
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
	)
	if code != 0 {
		t.Fatalf("certbot certonly after go-certbot exited %d\n%s", code, out)
	}

	// --- Step 4: accounts/ still has exactly one dir. -------------------
	afterAccounts, err := os.ReadDir(accountsRoot)
	if err != nil {
		t.Fatalf("read accounts dir after certbot: %v", err)
	}
	if len(afterAccounts) != 1 {
		var names []string
		for _, e := range afterAccounts {
			names = append(names, e.Name())
		}
		t.Fatalf("certbot created a second account; expected 1, got %d: %v",
			len(afterAccounts), names)
	}
	if afterAccounts[0].Name() != goCertbotAccountID {
		t.Errorf("certbot replaced the account dir: was %s, now %s",
			goCertbotAccountID, afterAccounts[0].Name())
	}

	// --- Step 5: both lineages intact. ----------------------------------
	for _, d := range []string{gcDomain, cbDomain} {
		fc := filepath.Join(leDir, "live", d, "fullchain.pem")
		if _, err := os.Stat(fc); err != nil {
			t.Errorf("lineage %s: missing %s: %v", d, fc, err)
		}
		conf := filepath.Join(leDir, "renewal", d+".conf")
		if _, err := os.Stat(conf); err != nil {
			t.Errorf("lineage %s: missing %s: %v", d, conf, err)
		}
	}

	// --- Step 6: go-certbot lists both lineages. -----------------------
	out, code = runGoCertbot(t, []string{
		"certificates",
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
	})
	if code != 0 {
		t.Fatalf("go-certbot certificates exited %d\n%s", code, out)
	}
	for _, want := range []string{gcDomain, cbDomain} {
		if !strings.Contains(out, want) {
			t.Errorf("go-certbot certificates didn't list %s:\n%s", want, out)
		}
	}
}

// TestE2EInteropRenewByCertbot exercises the mirror of
// TestE2EInteropRenew: go-certbot issues, then Certbot renews the SAME
// lineage. Verifies Certbot's renewer reads go-certbot's renewal.conf +
// account files and writes a new archive version.
func TestE2EInteropRenewByCertbot(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping interop test under -short")
	}
	certbotBin := findCertbot()
	if certbotBin == "" {
		t.Skip("certbot not on PATH; install with `pipx install certbot` (or set CERTBOT_BIN)")
	}
	h := startPebble(t)
	defer h.stop()

	leDir := t.TempDir()
	workDir := filepath.Join(leDir, "work")
	logsDir := filepath.Join(leDir, "logs")
	domain := "renew2.example.test"

	// go-certbot issues.
	gcArgs := []string{
		"certonly", "--standalone",
		"--server", h.dirURL, "--no-verify-ssl",
		"--agree-tos", "--register-unsafely-without-email", "--non-interactive",
		"--http-01-port", strconv.Itoa(h.httpPort),
		"-d", domain,
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
	}
	if code := cmd.Main(gcArgs); code != 0 {
		t.Fatalf("go-certbot certonly returned %d", code)
	}
	v1 := filepath.Join(leDir, "archive", domain, "cert1.pem")
	if _, err := os.Stat(v1); err != nil {
		t.Fatalf("go-certbot didn't write archive/%s/cert1.pem: %v", domain, err)
	}

	// Certbot renew --force-renewal --cert-name <domain>.
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	code, out := runCertbot(t, ctx, certbotBin,
		"renew",
		"--force-renewal",
		"--cert-name", domain,
		"--server", h.dirURL,
		"--no-verify-ssl",
		"--http-01-port", strconv.Itoa(h.httpPort),
		"--config-dir", leDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
		"--non-interactive",
		// Without this Certbot inserts a 0-8 minute random sleep,
		// which deadlocks our test under -timeout.
		"--no-random-sleep-on-renew",
	)
	if code != 0 {
		t.Fatalf("certbot renew of go-certbot lineage exited %d\n%s", code, out)
	}

	v2 := filepath.Join(leDir, "archive", domain, "cert2.pem")
	if _, err := os.Stat(v2); err != nil {
		t.Errorf("certbot didn't write archive/%s/cert2.pem after renew: %v", domain, err)
	}
	live := filepath.Join(leDir, "live", domain, "cert.pem")
	target, err := os.Readlink(live)
	if err != nil {
		t.Fatalf("readlink %s: %v", live, err)
	}
	if !strings.HasSuffix(target, "cert2.pem") {
		t.Errorf("live cert.pem points at %s, want cert2.pem", target)
	}
}

// runGoCertbot captures stdout from cmd.Main and returns it along with
// the exit code. Mirrors the pattern used by TestE2ECertificatesListsIssuedCert.
func runGoCertbot(t *testing.T, args []string) (string, int) {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := cmd.Main(args)
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), code
}

// trim returns the first 256 chars of s (for log brevity).
func trim(s string) string {
	if len(s) > 256 {
		return s[:256] + "..."
	}
	return s
}

