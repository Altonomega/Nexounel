package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeInstall lays out a plausible installed tree in home/unitDir.
func fakeInstall(t *testing.T, home, unitDir string) {
	t.Helper()
	for _, bin := range releaseBinaries {
		if err := writeFileMode(filepath.Join(home, bin), "#!/bin/sh\n", 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, unit := range []string{ServerUnit, PanelUnit, NodeUnit} {
		if err := writeFileMode(filepath.Join(unitDir, unit), "[Unit]\n", 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"nexounel-server.toml", "nexounel-node.toml", "nexounel-panel.toml", "nodes.toml"} {
		if err := writeFileMode(filepath.Join(home, name), "# config\n", 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeFileMode(filepath.Join(home, "mesh-control-secret.key"), "secret\n", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "nexounel"), filepath.Join(home, "nexounel-link")); err != nil {
		t.Fatal(err)
	}
}

func TestUninstallCancelledWithoutYes(t *testing.T) {
	home := t.TempDir()
	unitDir := t.TempDir()
	fakeInstall(t, home, unitDir)
	app, r := newTestApp(t, home, unitDir)
	scriptRole(r, true, true)
	app.in = strings.NewReader("no\n")

	if err := app.uninstallAction(context.Background(), Role{Mother: true, Node: true}, false); err != nil {
		t.Fatalf("uninstallAction: %v", err)
	}
	if !strings.Contains(app.stdout(), "Uninstall cancelled") {
		t.Errorf("cancel message missing:\n%s", app.stdout())
	}
	// Nothing was removed.
	if _, err := os.Stat(filepath.Join(home, "nexounel-server")); err != nil {
		t.Errorf("binary removed after cancel: %v", err)
	}
	if r.called("systemctl stop") {
		t.Errorf("services were stopped after cancel")
	}
}

func TestUninstallRemovesBinariesAndPreservesConfigs(t *testing.T) {
	home := t.TempDir()
	unitDir := t.TempDir()
	fakeInstall(t, home, unitDir)
	app, r := newTestApp(t, home, unitDir)
	scriptRole(r, true, true)
	for _, unit := range []string{ServerUnit, PanelUnit, NodeUnit} {
		r.script("systemctl", []string{"stop", unit}, "", nil)
		r.script("systemctl", []string{"disable", unit}, "", nil)
	}
	r.script("systemctl", []string{"daemon-reload"}, "", nil)
	// "Delete configuration?" -> n. "Remove the log directory?" -> n.
	app.in = strings.NewReader("n\nn\n")

	if err := app.uninstallAction(context.Background(), Role{Mother: true, Node: true}, true); err != nil {
		t.Fatalf("uninstallAction: %v", err)
	}
	for _, bin := range releaseBinaries {
		if _, err := os.Stat(filepath.Join(home, bin)); !os.IsNotExist(err) {
			t.Errorf("binary %s still present after uninstall", bin)
		}
	}
	for _, unit := range []string{ServerUnit, PanelUnit, NodeUnit} {
		if _, err := os.Stat(filepath.Join(unitDir, unit)); !os.IsNotExist(err) {
			t.Errorf("unit %s still present after uninstall", unit)
		}
	}
	if _, err := os.Lstat(filepath.Join(home, "nexounel-link")); !os.IsNotExist(err) {
		t.Errorf("symlink still present after uninstall")
	}
	// Configs and keys are preserved by default.
	for _, name := range []string{"nexounel-server.toml", "nexounel-panel.toml", "nodes.toml", "mesh-control-secret.key"} {
		if _, err := os.Stat(filepath.Join(home, name)); err != nil {
			t.Errorf("config %s was removed without confirmation: %v", name, err)
		}
	}
	if !strings.Contains(app.stdout(), "Preserved:") {
		t.Errorf("preserved list missing:\n%s", app.stdout())
	}
	if !strings.Contains(app.stdout(), "Removed:") {
		t.Errorf("removed list missing:\n%s", app.stdout())
	}
}

func TestUninstallRemovesConfigsWhenConfirmed(t *testing.T) {
	home := t.TempDir()
	unitDir := t.TempDir()
	fakeInstall(t, home, unitDir)
	app, r := newTestApp(t, home, unitDir)
	scriptRole(r, true, true)
	for _, unit := range []string{ServerUnit, PanelUnit, NodeUnit} {
		r.script("systemctl", []string{"stop", unit}, "", nil)
		r.script("systemctl", []string{"disable", unit}, "", nil)
	}
	r.script("systemctl", []string{"daemon-reload"}, "", nil)
	// "Delete configuration?" -> y. "Remove the data directory?" -> n.
	// "Remove the log directory?" -> n.
	app.in = strings.NewReader("y\nn\nn\n")

	if err := app.uninstallAction(context.Background(), Role{Mother: true, Node: true}, true); err != nil {
		t.Fatalf("uninstallAction: %v", err)
	}
	for _, name := range []string{"nexounel-server.toml", "nexounel-panel.toml", "nodes.toml", "mesh-control-secret.key"} {
		if _, err := os.Stat(filepath.Join(home, name)); !os.IsNotExist(err) {
			t.Errorf("config %s still present after confirmed removal", name)
		}
	}
}
