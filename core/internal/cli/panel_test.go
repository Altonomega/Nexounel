package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Altonomega/Nexounel/core/internal/panel"
)

// validPanelConfig creates a real panel config in dir and returns
// its path. It uses the panel's own CreateInitialConfig so the file
// is valid by construction.
func validPanelConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "nexounel-panel.toml")
	if _, err := panel.CreateInitialConfig(path, false, "admin", "old-password-123"); err != nil {
		t.Fatalf("CreateInitialConfig: %v", err)
	}
	return path
}

func TestSavePanelConfigPreservesBak(t *testing.T) {
	home := t.TempDir()
	confPath := validPanelConfig(t, home)
	before, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	app, _ := newTestApp(t, home, t.TempDir())
	app.cfg.PanelConf = confPath

	cfg, err := app.loadPanelConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Username = "new-admin"
	if err := app.savePanelConfig(cfg); err != nil {
		t.Fatalf("savePanelConfig: %v", err)
	}
	// The .bak holds the previous file, byte for byte.
	bak, err := os.ReadFile(confPath + ".bak")
	if err != nil {
		t.Fatalf("read .bak: %v", err)
	}
	if string(bak) != string(before) {
		t.Errorf(".bak does not match the previous config")
	}
	// The new file is 0600 and carries the new username.
	info, err := os.Stat(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %o, want 0600", info.Mode().Perm())
	}
	after, err := panel.LoadConfig(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Username != "new-admin" {
		t.Errorf("username = %q, want new-admin", after.Username)
	}
}

func TestSavePanelConfigRefusesInvalid(t *testing.T) {
	home := t.TempDir()
	confPath := validPanelConfig(t, home)
	before, _ := os.ReadFile(confPath)
	app, _ := newTestApp(t, home, t.TempDir())
	app.cfg.PanelConf = confPath

	cfg, err := app.loadPanelConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.WebPath = "not-a-valid-path" // no leading slash
	if err := app.savePanelConfig(cfg); err == nil {
		t.Fatalf("savePanelConfig accepted an invalid web path")
	}
	// The working config is untouched and no .bak was written for
	// a failed edit.
	after, _ := os.ReadFile(confPath)
	if string(after) != string(before) {
		t.Errorf("failed edit changed the working config")
	}
	if _, err := os.Stat(confPath + ".bak"); !os.IsNotExist(err) {
		t.Errorf("failed edit wrote a .bak")
	}
}

func TestResetCredentials(t *testing.T) {
	home := t.TempDir()
	confPath := validPanelConfig(t, home)
	app, r := newTestApp(t, home, t.TempDir())
	app.cfg.PanelConf = confPath
	// username, password, password again.
	app.in = strings.NewReader("operator\nnew-secret-456\nnew-secret-456\n")
	r.script("systemctl", []string{"restart", PanelUnit}, "", nil)
	r.script("systemctl", []string{"is-active", PanelUnit}, "active\n", nil)

	if err := app.resetCredentials(context.Background()); err != nil {
		t.Fatalf("resetCredentials: %v", err)
	}
	cfg, err := panel.LoadConfig(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "operator" {
		t.Errorf("username = %q, want operator", cfg.Username)
	}
	// The new password verifies against the stored hash; the old
	// one does not. The hash itself is never printed.
	ok, err := panel.VerifyPassword(cfg.PasswordHash, "new-secret-456")
	if err != nil || !ok {
		t.Errorf("new password does not verify: ok=%v err=%v", ok, err)
	}
	ok, _ = panel.VerifyPassword(cfg.PasswordHash, "old-password-123")
	if ok {
		t.Errorf("old password still verifies")
	}
	if strings.Contains(app.stdout(), "new-secret-456") || strings.Contains(app.stdout(), cfg.PasswordHash) {
		t.Errorf("password or hash was printed")
	}
	if !r.called("systemctl restart nexounel-panel.service") {
		t.Errorf("panel was not restarted")
	}
}

func TestResetCredentialsMismatch(t *testing.T) {
	home := t.TempDir()
	confPath := validPanelConfig(t, home)
	before, _ := os.ReadFile(confPath)
	app, _ := newTestApp(t, home, t.TempDir())
	app.cfg.PanelConf = confPath
	app.in = strings.NewReader("operator\none-password\nanother-password\n")

	err := app.resetCredentials(context.Background())
	if err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("resetCredentials with mismatched passwords: err=%v", err)
	}
	after, _ := os.ReadFile(confPath)
	if string(after) != string(before) {
		t.Errorf("mismatched passwords changed the config")
	}
}

func TestChangeWebpath(t *testing.T) {
	home := t.TempDir()
	confPath := validPanelConfig(t, home)
	app, r := newTestApp(t, home, t.TempDir())
	app.cfg.PanelConf = confPath
	r.script("systemctl", []string{"restart", PanelUnit}, "", nil)
	r.script("systemctl", []string{"is-active", PanelUnit}, "active\n", nil)

	old, err := app.loadPanelConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := app.changeWebpath(context.Background(), ""); err != nil {
		t.Fatalf("changeWebpath: %v", err)
	}
	cfg, err := panel.LoadConfig(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebPath == old.WebPath {
		t.Errorf("web path did not change")
	}
	if err := panel.ValidateWebPath(cfg.WebPath); err != nil {
		t.Errorf("new web path is invalid: %v", err)
	}
	// The new URL is printed (the operator needs it); the old
	// path is gone.
	if !strings.Contains(app.stdout(), cfg.WebPath) {
		t.Errorf("new panel URL was not printed")
	}
}

func TestChangeWebpathExplicitInvalid(t *testing.T) {
	home := t.TempDir()
	confPath := validPanelConfig(t, home)
	before, _ := os.ReadFile(confPath)
	app, _ := newTestApp(t, home, t.TempDir())
	app.cfg.PanelConf = confPath

	if err := app.changeWebpath(context.Background(), "no-leading-slash"); err == nil {
		t.Fatalf("changeWebpath accepted an invalid path")
	}
	after, _ := os.ReadFile(confPath)
	if string(after) != string(before) {
		t.Errorf("invalid web path changed the config")
	}
}

func TestChangePort(t *testing.T) {
	home := t.TempDir()
	confPath := validPanelConfig(t, home)
	app, r := newTestApp(t, home, t.TempDir())
	app.cfg.PanelConf = confPath
	r.script("systemctl", []string{"restart", PanelUnit}, "", nil)
	r.script("systemctl", []string{"is-active", PanelUnit}, "active\n", nil)

	// 18082 is free on the test host (the panel listens on 18081
	// in production, and nothing listens here).
	if err := app.changePort(context.Background(), 18082); err != nil {
		t.Fatalf("changePort: %v", err)
	}
	cfg, err := panel.LoadConfig(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "0.0.0.0:18082" {
		t.Errorf("listen_addr = %q, want 0.0.0.0:18082", cfg.ListenAddr)
	}
	if !strings.Contains(app.stdout(), "18082") {
		t.Errorf("new port was not reported")
	}
}

func TestChangePortSamePortNoop(t *testing.T) {
	home := t.TempDir()
	confPath := validPanelConfig(t, home)
	app, r := newTestApp(t, home, t.TempDir())
	app.cfg.PanelConf = confPath
	before, _ := os.ReadFile(confPath)

	// The default config listens on 0.0.0.0:18081.
	if err := app.changePort(context.Background(), 18081); err != nil {
		t.Fatalf("changePort same port: %v", err)
	}
	after, _ := os.ReadFile(confPath)
	if string(after) != string(before) {
		t.Errorf("same-port change rewrote the config")
	}
	if r.called("systemctl restart") {
		t.Errorf("same-port change restarted the panel")
	}
}
