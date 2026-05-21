// Package storage manages Certbot's on-disk certificate lineage: versioned
// files under archive/<certname>/ and live/<certname>/ symlinks pointing at
// them. Matches certbot._internal.storage layout.
package storage

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FilenameSet groups the four PEM files Certbot tracks per cert version.
type FilenameSet struct {
	Cert      string
	Privkey   string
	Chain     string
	Fullchain string
}

// Lineage represents a managed cert at a specific archive version.
type Lineage struct {
	CertName  string
	ConfigDir string
	Version   int // 1-based version number
	Archive   FilenameSet
	Live      FilenameSet
}

// LiveDir returns <config_dir>/live/<certname>.
func LiveDir(configDir, certName string) string {
	return filepath.Join(configDir, "live", certName)
}

// ArchiveDir returns <config_dir>/archive/<certname>.
func ArchiveDir(configDir, certName string) string {
	return filepath.Join(configDir, "archive", certName)
}

// NextVersion scans archive/<certname>/ and returns the next available
// version number (one more than the highest cert<N>.pem present), or 1 if the
// directory is empty/missing.
func NextVersion(configDir, certName string) (int, error) {
	archive := ArchiveDir(configDir, certName)
	entries, err := os.ReadDir(archive)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 1, nil
		}
		return 0, fmt.Errorf("storage: read archive: %w", err)
	}
	highest := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cert") || !strings.HasSuffix(name, ".pem") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "cert"), ".pem"))
		if err == nil && n > highest {
			highest = n
		}
	}
	return highest + 1, nil
}

// archiveSet returns the four archive/<certname>/<kind>N.pem paths.
func archiveSet(configDir, certName string, version int) FilenameSet {
	d := ArchiveDir(configDir, certName)
	suffix := strconv.Itoa(version) + ".pem"
	return FilenameSet{
		Cert:      filepath.Join(d, "cert"+suffix),
		Privkey:   filepath.Join(d, "privkey"+suffix),
		Chain:     filepath.Join(d, "chain"+suffix),
		Fullchain: filepath.Join(d, "fullchain"+suffix),
	}
}

// liveSet returns the four live/<certname>/<kind>.pem paths.
func liveSet(configDir, certName string) FilenameSet {
	d := LiveDir(configDir, certName)
	return FilenameSet{
		Cert:      filepath.Join(d, "cert.pem"),
		Privkey:   filepath.Join(d, "privkey.pem"),
		Chain:     filepath.Join(d, "chain.pem"),
		Fullchain: filepath.Join(d, "fullchain.pem"),
	}
}

// WriteOptions controls Write.
type WriteOptions struct {
	StrictPermissions bool // 0700 dirs vs default 0755
}

// Write lays down a new lineage version: archive/<certname>/{cert,privkey,
// chain,fullchain}<N>.pem and live/<certname>/*.pem symlinks pointing at them.
// fullchainPEM should be the full chain in PEM (leaf first); chainPEM is the
// chain without the leaf. privkeyPEM is the PEM-encoded private key for the
// cert.
//
// Permissions match Certbot: 0644 for cert/chain/fullchain, 0600 for privkey.
// Live dir contains relative symlinks (`../../archive/...`) to avoid breakage
// when the config root is moved.
func Write(configDir, certName string, fullchainPEM, chainPEM, privkeyPEM []byte, opts WriteOptions) (*Lineage, error) {
	if err := validatePEMChain(fullchainPEM); err != nil {
		return nil, err
	}
	version, err := NextVersion(configDir, certName)
	if err != nil {
		return nil, err
	}

	// Split fullchain → cert (leaf) and the rest. Lego returns chain (cert +
	// issuers) and IssuerCertificate separately; callers pass fullchain and we
	// trust them.
	leaf, rest, err := splitLeaf(fullchainPEM)
	if err != nil {
		return nil, err
	}
	if chainPEM == nil {
		chainPEM = rest
	}

	// Certbot's storage.RenewableCert.new_lineage hardcodes 0o700 for the
	// live/, archive/, and renewal/ tree (storage.py:1038, :1062). We do the
	// same regardless of StrictPermissions so a fresh install doesn't expose
	// the private key directory listing to local users.
	const dirMode = os.FileMode(0o700)
	archive := ArchiveDir(configDir, certName)
	live := LiveDir(configDir, certName)
	if err := os.MkdirAll(archive, dirMode); err != nil {
		return nil, fmt.Errorf("storage: mkdir archive: %w", err)
	}
	if err := os.MkdirAll(live, dirMode); err != nil {
		return nil, fmt.Errorf("storage: mkdir live: %w", err)
	}
	// Drop a README in live/<name>/ matching what Certbot writes (storage.py
	// :1085-1087) so users browsing the directory understand the symlinks.
	if err := writeLiveCertReadme(live, certName); err != nil {
		return nil, err
	}
	if err := writeLiveTopReadme(configDir); err != nil {
		return nil, err
	}

	arc := archiveSet(configDir, certName, version)
	if err := writeFile(arc.Cert, leaf, 0o644); err != nil {
		return nil, err
	}
	if err := writeFile(arc.Chain, chainPEM, 0o644); err != nil {
		return nil, err
	}
	if err := writeFile(arc.Fullchain, fullchainPEM, 0o644); err != nil {
		return nil, err
	}
	// Compute privkey mode + owner from the prior archive version, if any.
	// Mirrors certbot.compat.filesystem.compute_private_key_mode +
	// copy_ownership_and_apply_mode (storage.py:1191-1196): mode is
	// 0600 | (prior_mode & (S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH)) so a user
	// who chmodded an earlier key to add group-read keeps that bit
	// across renewals, and gid is propagated.
	privMode, copyFrom := computePrivkeyMode(configDir, certName, version)
	if err := writeFile(arc.Privkey, privkeyPEM, privMode); err != nil {
		return nil, err
	}
	if copyFrom != "" {
		if err := copyGroupOwnership(copyFrom, arc.Privkey); err != nil {
			return nil, err
		}
	}

	liveFiles := liveSet(configDir, certName)
	for _, sl := range []struct {
		live, target string
	}{
		{liveFiles.Cert, arc.Cert},
		{liveFiles.Privkey, arc.Privkey},
		{liveFiles.Chain, arc.Chain},
		{liveFiles.Fullchain, arc.Fullchain},
	} {
		if err := replaceSymlink(sl.live, sl.target); err != nil {
			return nil, err
		}
	}

	return &Lineage{
		CertName:  certName,
		ConfigDir: configDir,
		Version:   version,
		Archive:   arc,
		Live:      liveFiles,
	}, nil
}

// EnsureDeployed re-links live/<certname>/{cert,chain,fullchain,privkey}.pem
// to the highest-numbered archive version present on disk. Mirrors
// certbot.storage.RenewableCert.ensure_deployed (storage.py:857-870) which
// recovers from interrupted-renewal state where archive/N+1 exists but the
// live/ symlinks still point at N.
//
// Returns the version it pointed at (highest available), or 0 if archive
// is empty.
func EnsureDeployed(configDir, certName string) (int, error) {
	archive := ArchiveDir(configDir, certName)
	entries, err := os.ReadDir(archive)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	highest := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cert") || !strings.HasSuffix(name, ".pem") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "cert"), ".pem"))
		if err == nil && n > highest {
			highest = n
		}
	}
	if highest == 0 {
		return 0, nil
	}
	arc := archiveSet(configDir, certName, highest)
	live := liveSet(configDir, certName)
	for _, sl := range []struct{ live, target string }{
		{live.Cert, arc.Cert},
		{live.Privkey, arc.Privkey},
		{live.Chain, arc.Chain},
		{live.Fullchain, arc.Fullchain},
	} {
		// Read the existing link target — only re-link if it's stale or
		// missing. This avoids writing on every renew run.
		want, err := filepath.Rel(filepath.Dir(sl.live), sl.target)
		if err != nil {
			return 0, err
		}
		got, _ := os.Readlink(sl.live)
		if got == want {
			continue
		}
		if err := replaceSymlink(sl.live, sl.target); err != nil {
			return 0, err
		}
	}
	return highest, nil
}

// replaceSymlink atomically replaces a symlink at linkPath with one pointing
// at target. Uses a relative target so the link survives moves of configDir.
func replaceSymlink(linkPath, target string) error {
	rel, err := filepath.Rel(filepath.Dir(linkPath), target)
	if err != nil {
		return fmt.Errorf("storage: rel %s -> %s: %w", linkPath, target, err)
	}
	tmp := linkPath + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(rel, tmp); err != nil {
		return fmt.Errorf("storage: symlink %s -> %s: %w", tmp, rel, err)
	}
	if err := os.Rename(tmp, linkPath); err != nil {
		return fmt.Errorf("storage: rename symlink: %w", err)
	}
	return nil
}

// writeLiveCertReadme writes README inside live/<certname>/. Matches
// Certbot's _write_live_readme_to (storage.py:1086).
func writeLiveCertReadme(liveDir, certName string) error {
	path := filepath.Join(liveDir, "README")
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	body := "This directory contains your keys and certificates.\n\n" +
		"`privkey.pem`  : the private key for your certificate.\n" +
		"`fullchain.pem`: the certificate file used in most server software.\n" +
		"`chain.pem`    : used for OCSP stapling in Nginx >=1.3.7.\n" +
		"`cert.pem`     : will break many server configurations, and should not be used\n" +
		"                 without reading further documentation (see link below).\n\n" +
		"WARNING: DO NOT MOVE OR RENAME THESE FILES!\n" +
		"         Certbot expects these files to remain in this location in order\n" +
		"         to function properly!\n\n" +
		"We recommend not moving these files. For more information, see the Certbot\n" +
		"User Guide at https://certbot.eff.org/docs/using.html#where-are-my-certificates.\n"
	return writeFile(path, []byte(body), 0o644)
}

// writeLiveTopReadme writes README in <config_dir>/live/.
func writeLiveTopReadme(configDir string) error {
	path := filepath.Join(configDir, "live", "README")
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	body := "This directory contains your Let's Encrypt certificates.\n\n" +
		"Each subdirectory contains four symlinks pointing into archive/. Do not\n" +
		"move or delete the files in here; they are managed by certbot.\n"
	return writeFile(path, []byte(body), 0o644)
}

// computePrivkeyMode returns the file mode + path of the prior version's
// privkey to copy gid from. If there's no prior privkey (initial issuance)
// it returns the base 0o600 mode and "". Mirrors
// certbot.compat.filesystem.compute_private_key_mode (filesystem.py:449):
// preserve user-set group/other read+write+execute bits on the previous
// privkey across renewals.
func computePrivkeyMode(configDir, certName string, newVersion int) (os.FileMode, string) {
	if newVersion <= 1 {
		return 0o600, ""
	}
	prior := archiveSet(configDir, certName, newVersion-1)
	info, err := os.Stat(prior.Privkey)
	if err != nil {
		return 0o600, ""
	}
	const mask os.FileMode = 0o077 // S_IRWXG | S_IROTH | S_IWOTH | S_IXOTH
	// Certbot's mask is narrower: 0o074 = S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH.
	// We use that exact mask to round-trip.
	const certbotMask os.FileMode = 0o074
	_ = mask
	return 0o600 | (info.Mode().Perm() & certbotMask), prior.Privkey
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("storage: create temp: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("storage: write %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("storage: chmod %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("storage: close %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("storage: rename to %s: %w", path, err)
	}
	return nil
}

// validatePEMChain checks that the input parses as at least one CERTIFICATE
// PEM block.
func validatePEMChain(fullchain []byte) error {
	count := 0
	rest := fullchain
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("storage: unexpected PEM block %q in chain", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("storage: parse cert in chain: %w", err)
		}
		count++
	}
	if count == 0 {
		return errors.New("storage: chain contained no CERTIFICATE blocks")
	}
	return nil
}

// splitLeaf separates the first CERTIFICATE PEM block from the rest.
func splitLeaf(fullchain []byte) (leaf, rest []byte, err error) {
	block, remainder := pem.Decode(fullchain)
	if block == nil {
		return nil, nil, errors.New("storage: empty fullchain")
	}
	leaf = pem.EncodeToMemory(block)
	rest = remainder
	return leaf, rest, nil
}
