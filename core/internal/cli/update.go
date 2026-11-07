package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Altonomega/Nexounel/core/internal/version"
)

// Release endpoints. Forgejo is primary; GitHub is the fallback.
// They are variables (not constants) so tests can point them at a
// local test server.
var (
	forgejoLatestRelease = "https://time.plutus.bond:8444/api/v1/repos/mashani/Nexounel/releases/latest"
	githubLatestRelease  = "https://api.github.com/repos/Altonomega/Nexounel/releases/latest"
)

// releaseInfo is the subset of a Forgejo/GitHub latest-release
// response the updater needs.
type releaseInfo struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
	Source string // "forgejo" or "github": where it was found
}

// releaseBinaries are the binaries a release tarball must carry.
var releaseBinaries = []string{"nexounel-server", "nexounel-node", "nexounel-panel", "nexounel"}

// checkRelease queries the Forgejo latest-release API, falling back
// to GitHub. It returns the release, whether it is newer than the
// running build, and any error.
func (a *App) checkRelease(ctx context.Context) (*releaseInfo, bool, error) {
	rel, err := a.fetchRelease(ctx, forgejoLatestRelease, "forgejo")
	if err != nil {
		rel, err = a.fetchRelease(ctx, githubLatestRelease, "github")
		if err != nil {
			return nil, false, fmt.Errorf("check release (forgejo and github both failed): %w", err)
		}
	}
	newer := compareVersions(rel.TagName, version.GetVersion()) > 0
	return rel, newer, nil
}

func (a *App) fetchRelease(ctx context.Context, url, source string) (*releaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	var rel releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("parse release response from %s: %w", url, err)
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("release response from %s has no tag_name", url)
	}
	rel.Source = source
	return &rel, nil
}

// compareVersions compares two version strings ("v1.2.3" or "1.2.3").
// "dev" (and an empty string) sort below everything: a development
// build is always older than a release. An unknown tag that does not
// parse as a version is treated as newer than a parseable one, so an
// unknown release is never silently skipped. It returns -1, 0 or 1.
func compareVersions(a, b string) int {
	av := parseVersion(a)
	bv := parseVersion(b)
	if av != nil && bv != nil {
		for i := 0; i < 3; i++ {
			if av[i] != bv[i] {
				if av[i] < bv[i] {
					return -1
				}
				return 1
			}
		}
		return 0
	}
	if isDevVersion(a) && isDevVersion(b) {
		return 0
	}
	if isDevVersion(a) {
		return -1
	}
	if isDevVersion(b) {
		return 1
	}
	if av == nil && bv == nil {
		return strings.Compare(strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v"))
	}
	if av == nil {
		return 1 // unknown tag: newer, never silently skipped
	}
	return -1
}

// isDevVersion reports whether v is a development build ("dev" or
// empty) rather than a release version.
func isDevVersion(v string) bool {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	return v == "" || v == "dev"
}

// parseVersion parses "v1.2.3" / "1.2.3" into [major minor patch].
// "dev" and anything unparseable return nil.
func parseVersion(v string) *[3]int {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if v == "" || v == "dev" {
		return nil
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	var out [3]int
	for i, p := range parts {
		// Strip a trailing pre-release/build suffix ("1-rc1", "2+build").
		if j := strings.IndexAny(p, "-+"); j >= 0 {
			p = p[:j]
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out[i] = n
	}
	return &out
}

// tarballAsset finds the linux tarball asset for this architecture in
// a release, plus its .sha256 sidecar. The release tarballs are named
// nexounel-<version>-linux-<arch>.tar.gz.
func (rel *releaseInfo) tarballAsset() (tarballURL, shaURL, tarballName string, ok bool) {
	arch := runtime.GOARCH
	suffix := "-linux-" + arch + ".tar.gz"
	for _, asset := range rel.Assets {
		if strings.HasSuffix(asset.Name, suffix) {
			tarballURL = asset.BrowserDownloadURL
			tarballName = asset.Name
			for _, other := range rel.Assets {
				if other.Name == asset.Name+".sha256" {
					shaURL = other.BrowserDownloadURL
					break
				}
			}
			return tarballURL, shaURL, tarballName, true
		}
	}
	return "", "", "", false
}

// downloadFile fetches a URL into a file inside dir and returns the path.
func (a *App) downloadFile(ctx context.Context, url, dir, name string) (string, error) {
	path := filepath.Join(dir, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return path, nil
}

// verifySHA256 checks that file's SHA-256 matches the expected hex
// digest (read from a .sha256 sidecar: "<hash>  <name>" or bare hash).
func verifySHA256(file, expected string) error {
	fields := strings.Fields(strings.TrimSpace(expected))
	if len(fields) == 0 {
		return fmt.Errorf("empty expected SHA-256")
	}
	expected = fields[0]
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return err
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if !strings.EqualFold(got, expected) {
		return fmt.Errorf("SHA-256 mismatch for %s: got %s, expected %s", file, got, expected)
	}
	return nil
}

// installTarball extracts a verified release tarball and installs its
// binaries (0755), units (0644) and logrotate file. Configs are
// installed only when absent. The services must already be stopped:
// replacing a running binary fails with ETXTBSY.
func (a *App) installTarball(tarballPath string) error {
	tmp, err := os.MkdirTemp("", "nexounel-update-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	root, err := extractTarball(tarballPath, tmp)
	if err != nil {
		return err
	}
	for _, bin := range releaseBinaries {
		src := filepath.Join(root, bin)
		if _, err := os.Stat(src); err != nil {
			return fmt.Errorf("release tarball is missing binary %s: %w", bin, err)
		}
		if err := installFile(src, filepath.Join(a.cfg.Home, bin), 0o755); err != nil {
			return err
		}
	}
	if err := installFileIfPresent(filepath.Join(root, "units", "nexounel.service"), filepath.Join(a.cfg.UnitDir, "nexounel.service"), 0o644); err != nil {
		return err
	}
	if err := installFileIfPresent(filepath.Join(root, "units", "nexounel-panel.service"), filepath.Join(a.cfg.UnitDir, "nexounel-panel.service"), 0o644); err != nil {
		return err
	}
	if err := installFileIfPresent(filepath.Join(root, "units", "nexounel-node.service"), filepath.Join(a.cfg.UnitDir, "nexounel-node.service"), 0o644); err != nil {
		return err
	}
	if err := installFileIfPresent(filepath.Join(root, "logrotate", "nexounel"), filepath.Join(a.cfg.LogDir, "..", "logrotate.d", "nexounel"), 0o644); err != nil {
		return err
	}
	// Configs: only when absent, never overwrite a live config.
	for _, name := range []string{"nexounel-server.toml", "nexounel-node.toml", "nodes.toml.example", "client_resolvers.txt"} {
		src := filepath.Join(root, "configs", name)
		dst := filepath.Join(a.cfg.Home, name)
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		if err := installFileIfPresent(src, dst, 0o600); err != nil {
			return err
		}
	}
	if _, err := a.systemctl(context.Background(), "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	return nil
}

// extractTarball extracts a .tar.gz into dir and returns the root
// directory holding the binaries (the tarball's top-level dir, or dir
// itself when the binaries are at the top level).
func extractTarball(tarballPath, dir string) (string, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("open tarball %s: %w", tarballPath, err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tarball %s: %w", tarballPath, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Reject paths that would escape the extraction directory.
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return "", fmt.Errorf("tarball entry %q escapes the extraction directory", hdr.Name)
		}
		dst := filepath.Join(dir, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return "", err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, tr); err != nil {
			_ = out.Close()
			return "", err
		}
		_ = out.Close()
	}
	// The release tarballs carry one top-level directory
	// (nexounel-<version>/); the binaries live inside it.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() {
			if _, err := os.Stat(filepath.Join(dir, e.Name(), "nexounel-server")); err == nil {
				return filepath.Join(dir, e.Name()), nil
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "nexounel-server")); err == nil {
		return dir, nil
	}
	return "", fmt.Errorf("tarball %s has no recognizable layout (no nexounel-server found)", tarballPath)
}

// installFile copies src to dst atomically (temp file + rename) with
// the given mode. It never modifies a running binary in place: the
// rename replaces the path, and the old inode stays valid for the
// running process until it exits.
func installFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".nexounel-install-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

// installFileIfPresent installs src to dst when src exists; a missing
// src is a no-op (older tarballs may not carry every file).
func installFileIfPresent(src, dst string, mode os.FileMode) error {
	if _, err := os.Stat(src); err != nil {
		return nil
	}
	return installFile(src, dst, mode)
}

// updateAction is the `update` flow: check, confirm, download,
// SHA-256 verify, stop, install, start. checkOnly only reports.
func (a *App) updateAction(ctx context.Context, role Role, checkOnly bool) error {
	rel, newer, err := a.checkRelease(ctx)
	if err != nil {
		return err
	}
	current := version.GetVersion()
	if !newer {
		a.Printf("Already up to date: %s (latest %s, %s).", current, rel.TagName, rel.Source)
		return nil
	}
	a.Printf("Update available: %s -> %s (%s)", current, rel.TagName, rel.Source)
	if rel.HTMLURL != "" {
		a.Printf("Release notes: %s", rel.HTMLURL)
	}
	if checkOnly {
		return nil
	}
	if !a.confirm("Download and install " + rel.TagName + "?") {
		a.Printf("Update cancelled.")
		return nil
	}
	return a.applyUpdate(ctx, role, rel)
}

// applyUpdate downloads, verifies and installs a release, then
// restarts the services. The services are stopped before the
// binaries are replaced (a running binary cannot be overwritten).
func (a *App) applyUpdate(ctx context.Context, role Role, rel *releaseInfo) error {
	tarballURL, shaURL, tarballName, ok := rel.tarballAsset()
	if !ok {
		return fmt.Errorf("release %s has no linux-%s tarball asset", rel.TagName, runtime.GOARCH)
	}
	if shaURL == "" {
		return fmt.Errorf("release %s has no .sha256 sidecar for %s: refusing to install an unverified tarball", rel.TagName, tarballName)
	}
	tmp, err := os.MkdirTemp("", "nexounel-download-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	a.Printf("Downloading %s ...", tarballName)
	tarballPath, err := a.downloadFile(ctx, tarballURL, tmp, tarballName)
	if err != nil {
		return fmt.Errorf("download %s: %w", tarballName, err)
	}
	shaPath, err := a.downloadFile(ctx, shaURL, tmp, tarballName+".sha256")
	if err != nil {
		return fmt.Errorf("download %s.sha256: %w", tarballName, err)
	}
	expected, err := os.ReadFile(shaPath)
	if err != nil {
		return err
	}
	if err := verifySHA256(tarballPath, string(expected)); err != nil {
		return fmt.Errorf("refusing to install: %w", err)
	}
	a.Printf("SHA-256 verified for %s.", tarballName)
	units := role.Units()
	for _, unit := range units {
		if _, err := a.systemctl(ctx, "stop", unit); err != nil {
			a.Errorf("warning: could not stop %s: %v", unit, err)
		}
	}
	if err := a.installTarball(tarballPath); err != nil {
		return fmt.Errorf("install %s: %w (services are stopped; run `nexounel start` after fixing)", tarballName, err)
	}
	for _, unit := range units {
		if _, err := a.systemctl(ctx, "start", unit); err != nil {
			a.Errorf("warning: could not start %s: %v", unit, err)
		}
	}
	a.Printf("Updated to %s.", rel.TagName)
	for _, st := range a.ServiceStates(ctx, units) {
		a.Printf("%-24s active=%s", st.Unit, st.Active)
	}
	return nil
}
