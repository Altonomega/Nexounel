package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// uninstallAction removes Nexounel from this box. It requires an
// explicit "yes" confirmation. It stops and disables the units,
// removes the binaries, units and logrotate file, and (only on a
// second confirmation, default NO) the configs/keys and the data
// and log directories. It prints exactly what was removed and what
// was preserved. It never touches anything outside the Nexounel
// install root, the unit directory and the logrotate file.
func (a *App) uninstallAction(ctx context.Context, role Role, confirmed bool) error {
	if !confirmed {
		if !a.confirmYes("uninstall Nexounel from this box (stop and disable the services, remove the binaries, units and logrotate file)") {
			a.Printf("Uninstall cancelled.")
			return nil
		}
	}
	units := []string{ServerUnit, PanelUnit, NodeUnit}
	var removed, preserved []string
	// Stop + disable only the units installed on this box; removing
	// the files below covers all three either way.
	for _, unit := range role.Units() {
		if _, err := a.systemctl(ctx, "stop", unit); err != nil {
			// Not running: not fatal.
			continue
		}
		if _, err := a.systemctl(ctx, "disable", unit); err != nil {
			a.Errorf("warning: could not disable %s: %v", unit, err)
		}
		removed = append(removed, unit+" (stopped, disabled)")
	}
	for _, name := range releaseBinaries {
		path := filepath.Join(a.cfg.Home, name)
		if removeIfExists(path) {
			removed = append(removed, path)
		}
	}
	for _, unit := range units {
		path := filepath.Join(a.cfg.UnitDir, unit)
		if removeIfExists(path) {
			removed = append(removed, path)
		}
	}
	if removeIfExists(a.cfg.BinLink) {
		removed = append(removed, a.cfg.BinLink)
	}
	// The logrotate file lives beside the unit dir's parent
	// (/etc/logrotate.d/nexounel for the default unit dir).
	logrotatePath := filepath.Join(filepath.Dir(a.cfg.UnitDir), "logrotate.d", "nexounel")
	if removeIfExists(logrotatePath) {
		removed = append(removed, logrotatePath)
	}
	if _, err := a.systemctl(ctx, "daemon-reload"); err != nil {
		a.Errorf("warning: systemctl daemon-reload failed: %v", err)
	}

	// Configs and keys: ask once, default NO.
	configFiles := []string{"nexounel-server.toml", "nexounel-node.toml", "nexounel-panel.toml", "nodes.toml", "nodes.toml.example", "client_resolvers.txt"}
	var keys []string
	if entries, err := filepath.Glob(filepath.Join(a.cfg.Home, "*.key")); err == nil {
		keys = entries
	}
	if a.confirm("Delete configuration and key files in " + a.cfg.Home + "?") {
		for _, name := range configFiles {
			path := filepath.Join(a.cfg.Home, name)
			if removeIfExists(path) {
				removed = append(removed, path)
			}
		}
		for _, path := range keys {
			if removeIfExists(path) {
				removed = append(removed, path)
			}
		}
		// Offer the data directory itself once the configs are gone.
		if a.confirm("Remove the data directory " + a.cfg.Home + "?") {
			if err := os.Remove(a.cfg.Home); err == nil {
				removed = append(removed, a.cfg.Home+" (directory)")
			} else {
				a.Errorf("could not remove %s (not empty?): %v", a.cfg.Home, err)
			}
		}
	} else {
		for _, name := range configFiles {
			path := filepath.Join(a.cfg.Home, name)
			if fileExists(path) {
				preserved = append(preserved, path)
			}
		}
		preserved = append(preserved, keys...)
	}
	if a.confirm("Remove the log directory " + a.cfg.LogDir + "?") {
		if err := os.RemoveAll(a.cfg.LogDir); err == nil {
			removed = append(removed, a.cfg.LogDir+" (directory)")
		} else {
			a.Errorf("could not remove %s: %v", a.cfg.LogDir, err)
		}
	}

	a.Printf("Uninstall complete.")
	if len(removed) > 0 {
		a.Printf("Removed:\n  %s", strings.Join(removed, "\n  "))
	} else {
		a.Printf("Nothing was removed (no Nexounel files were present).")
	}
	if len(preserved) > 0 {
		a.Printf("Preserved:\n  %s", strings.Join(preserved, "\n  "))
	}
	return nil
}

// removeIfExists removes a file (or symlink) when present and reports
// whether it removed anything. Directories are never removed here.
func removeIfExists(path string) bool {
	if _, err := os.Lstat(path); err != nil {
		return false
	}
	if err := os.Remove(path); err != nil {
		return false
	}
	return true
}
