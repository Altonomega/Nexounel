package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.3.0", "v0.3.0", 0},
		{"v0.3.1", "v0.3.0", 1},
		{"v0.3.0", "v0.4.0", -1},
		{"v1.0.0", "v0.9.9", 1},
		{"v0.3.0", "dev", 1},  // dev sorts below everything
		{"dev", "v0.3.0", -1}, // a dev build is always "older"
		{"v0.3.0", "v0.3.0-rc1", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	if v := parseVersion("v1.2.3"); v == nil || *v != [3]int{1, 2, 3} {
		t.Errorf("parseVersion(v1.2.3) = %v", v)
	}
	if v := parseVersion("dev"); v != nil {
		t.Errorf("parseVersion(dev) = %v, want nil", v)
	}
	if v := parseVersion("not-a-version"); v != nil {
		t.Errorf("parseVersion(not-a-version) = %v, want nil", v)
	}
	if v := parseVersion("1.2"); v != nil {
		t.Errorf("parseVersion(1.2) = %v, want nil", v)
	}
}

func TestVerifySHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.bin")
	content := []byte("nexounel release bytes")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])

	if err := verifySHA256(path, want+"  file.bin\n"); err != nil {
		t.Errorf("verifySHA256 correct digest: %v", err)
	}
	if err := verifySHA256(path, want); err != nil {
		t.Errorf("verifySHA256 bare digest: %v", err)
	}
	if err := verifySHA256(path, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Errorf("verifySHA256 accepted a wrong digest")
	}
	if err := verifySHA256(path, ""); err == nil {
		t.Errorf("verifySHA256 accepted an empty digest")
	}
}

func TestTarballAsset(t *testing.T) {
	rel := &releaseInfo{
		TagName: "v0.4.0",
		Assets: []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		}{
			{"nexounel-v0.4.0-linux-amd64.tar.gz", "https://example.invalid/amd64.tar.gz"},
			{"nexounel-v0.4.0-linux-amd64.tar.gz.sha256", "https://example.invalid/amd64.tar.gz.sha256"},
			{"nexounel-v0.4.0-linux-arm64.tar.gz", "https://example.invalid/arm64.tar.gz"},
		},
	}
	url, sha, name, ok := rel.tarballAsset()
	if !ok {
		t.Fatalf("tarballAsset not found")
	}
	if name != "nexounel-v0.4.0-linux-amd64.tar.gz" {
		t.Errorf("tarball name = %q", name)
	}
	if url != "https://example.invalid/amd64.tar.gz" || sha != "https://example.invalid/amd64.tar.gz.sha256" {
		t.Errorf("urls = %q / %q", url, sha)
	}
	// No .sha256 sidecar: the tarball is found but the sidecar is empty.
	rel.Assets = rel.Assets[:1]
	_, sha, _, ok = rel.tarballAsset()
	if !ok || sha != "" {
		t.Errorf("tarballAsset without sidecar: ok=%v sha=%q", ok, sha)
	}
}

// fakeReleaseServer serves a release API response plus a tarball and
// its .sha256, all from one httptest server.
func fakeReleaseServer(t *testing.T, tarball []byte) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(tarball)
	sha := hex.EncodeToString(sum[:])
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/repos/mashani/Nexounel/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v9.9.9","html_url":"%s/releases/tag/v9.9.9","assets":[
			{"name":"nexounel-v9.9.9-linux-amd64.tar.gz","browser_download_url":"%s/nexounel-v9.9.9-linux-amd64.tar.gz"},
			{"name":"nexounel-v9.9.9-linux-amd64.tar.gz.sha256","browser_download_url":"%s/nexounel-v9.9.9-linux-amd64.tar.gz.sha256"}
		]}`, srv.URL, srv.URL, srv.URL)
	})
	mux.HandleFunc("/nexounel-v9.9.9-linux-amd64.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarball)
	})
	mux.HandleFunc("/nexounel-v9.9.9-linux-amd64.tar.gz.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  nexounel-v9.9.9-linux-amd64.tar.gz\n", sha)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// buildTestTarball builds a .tar.gz with the release layout:
// nexounel-v9.9.9/nexounel-{server,node,panel,cli} + configs + units.
func buildTestTarball(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name, content string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	for _, bin := range releaseBinaries {
		add("nexounel-v9.9.9/"+bin, "#!/bin/sh\necho fake "+bin+"\n")
	}
	add("nexounel-v9.9.9/configs/nexounel-server.toml", "# server\n")
	add("nexounel-v9.9.9/units/nexounel.service", "[Unit]\n")
	add("nexounel-v9.9.9/units/nexounel-panel.service", "[Unit]\n")
	add("nexounel-v9.9.9/units/nexounel-node.service", "[Unit]\n")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCheckReleaseAgainstFakeForgejo(t *testing.T) {
	srv := fakeReleaseServer(t, buildTestTarball(t))
	oldForgejo, oldGithub := forgejoLatestRelease, githubLatestRelease
	forgejoLatestRelease = srv.URL + "/api/v1/repos/mashani/Nexounel/releases/latest"
	githubLatestRelease = srv.URL + "/unused"
	defer func() { forgejoLatestRelease, githubLatestRelease = oldForgejo, oldGithub }()

	app, _ := newTestApp(t, t.TempDir(), t.TempDir())
	rel, newer, err := app.checkRelease(context.Background())
	if err != nil {
		t.Fatalf("checkRelease: %v", err)
	}
	if rel.TagName != "v9.9.9" || rel.Source != "forgejo" {
		t.Errorf("release = %+v", rel)
	}
	if !newer {
		t.Errorf("v9.9.9 should be newer than dev")
	}
}

func TestCheckReleaseFallsBackToGitHub(t *testing.T) {
	srv := fakeReleaseServer(t, buildTestTarball(t))
	oldForgejo, oldGithub := forgejoLatestRelease, githubLatestRelease
	// Forgejo is down; GitHub serves the same payload.
	forgejoLatestRelease = "http://127.0.0.1:1/unreachable"
	githubLatestRelease = srv.URL + "/api/v1/repos/mashani/Nexounel/releases/latest"
	defer func() { forgejoLatestRelease, githubLatestRelease = oldForgejo, oldGithub }()

	app, _ := newTestApp(t, t.TempDir(), t.TempDir())
	rel, _, err := app.checkRelease(context.Background())
	if err != nil {
		t.Fatalf("checkRelease: %v", err)
	}
	if rel.Source != "github" {
		t.Errorf("source = %q, want github", rel.Source)
	}
}

func TestInstallTarball(t *testing.T) {
	home := t.TempDir()
	unitDir := t.TempDir()
	app, r := newTestApp(t, home, unitDir)
	app.cfg.LogDir = t.TempDir()
	r.script("systemctl", []string{"daemon-reload"}, "", nil)

	tarballPath := filepath.Join(t.TempDir(), "rel.tar.gz")
	if err := os.WriteFile(tarballPath, buildTestTarball(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.installTarball(tarballPath); err != nil {
		t.Fatalf("installTarball: %v", err)
	}
	for _, bin := range releaseBinaries {
		info, err := os.Stat(filepath.Join(home, bin))
		if err != nil {
			t.Errorf("binary %s not installed: %v", bin, err)
			continue
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("binary %s mode = %o, want 0755", bin, info.Mode().Perm())
		}
	}
	if _, err := os.Stat(filepath.Join(unitDir, "nexounel.service")); err != nil {
		t.Errorf("unit not installed: %v", err)
	}
	// Configs are installed only when absent: the server config
	// from the tarball should exist now.
	if _, err := os.Stat(filepath.Join(home, "nexounel-server.toml")); err != nil {
		t.Errorf("config not installed: %v", err)
	}
	// A second install must not overwrite an existing config.
	if err := os.WriteFile(filepath.Join(home, "nexounel-server.toml"), []byte("live config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.installTarball(tarballPath); err != nil {
		t.Fatalf("second installTarball: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(home, "nexounel-server.toml"))
	if string(data) != "live config\n" {
		t.Errorf("second install overwrote the live config")
	}
}

func TestApplyUpdateRefusesTamperedTarball(t *testing.T) {
	// The server's .sha256 claims the original tarball, but the
	// tarball it serves is tampered. applyUpdate must refuse it
	// before installing anything.
	good := buildTestTarball(t)
	sum := sha256.Sum256(good)
	sha := hex.EncodeToString(sum[:])
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/repos/mashani/Nexounel/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v9.9.9","html_url":"%s/releases/tag/v9.9.9","assets":[
			{"name":"nexounel-v9.9.9-linux-amd64.tar.gz","browser_download_url":"%s/nexounel-v9.9.9-linux-amd64.tar.gz"},
			{"name":"nexounel-v9.9.9-linux-amd64.tar.gz.sha256","browser_download_url":"%s/nexounel-v9.9.9-linux-amd64.tar.gz.sha256"}
		]}`, srv.URL, srv.URL, srv.URL)
	})
	mux.HandleFunc("/nexounel-v9.9.9-linux-amd64.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		tampered := append([]byte{}, good...)
		tampered[100] ^= 0xff
		_, _ = w.Write(tampered)
	})
	mux.HandleFunc("/nexounel-v9.9.9-linux-amd64.tar.gz.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  nexounel-v9.9.9-linux-amd64.tar.gz\n", sha)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	oldForgejo, oldGithub := forgejoLatestRelease, githubLatestRelease
	forgejoLatestRelease = srv.URL + "/api/v1/repos/mashani/Nexounel/releases/latest"
	githubLatestRelease = srv.URL + "/unused"
	defer func() { forgejoLatestRelease, githubLatestRelease = oldForgejo, oldGithub }()

	home := t.TempDir()
	app, r := newTestApp(t, home, t.TempDir())
	scriptRole(r, true, false)
	rel, _, err := app.checkRelease(context.Background())
	if err != nil {
		t.Fatalf("checkRelease: %v", err)
	}
	err = app.applyUpdate(context.Background(), Role{Mother: true}, rel)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("applyUpdate with tampered tarball: err=%v", err)
	}
	// Nothing was installed.
	if _, err := os.Stat(filepath.Join(home, "nexounel-server")); !os.IsNotExist(err) {
		t.Errorf("tampered tarball was installed")
	}
	if r.called("systemctl stop") {
		t.Errorf("services were stopped before the hash check failed")
	}
}
