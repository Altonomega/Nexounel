package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/Altonomega/Nexounel/core/internal/version"
)

// installAction is the "Install / Reinstall" menu action. When
// Nexounel is already installed on this box it confirms and then
// re-installs the binaries and units from the latest verified
// release (configs are preserved). When nothing is installed it
// performs a fresh install from the latest verified release:
// binaries, units and default configs (only when absent), then
// enables and starts the services. The installer script itself is
// not needed on the box: the release tarball carries everything.
func (a *App) installAction(ctx context.Context, role Role) error {
	if role.Any() {
		if !a.confirm("Reinstall Nexounel (binaries and units are replaced; configs are preserved)?") {
			a.Printf("Reinstall cancelled.")
			return nil
		}
	} else {
		a.Printf("No Nexounel services are installed on this box. Installing the latest release...")
	}
	rel, newer, err := a.checkRelease(ctx)
	if err != nil {
		return fmt.Errorf("check release: %w", err)
	}
	if !newer && role.Any() {
		a.Printf("Already on the latest release (%s). Reinstalling the same version.", version.GetVersion())
	}
	if rel.HTMLURL != "" {
		a.Printf("Release: %s (%s)", rel.TagName, rel.Source)
	}
	tarballURL, shaURL, tarballName, ok := rel.tarballAsset()
	if !ok {
		return fmt.Errorf("release %s has no linux-%s tarball asset", rel.TagName, runtime.GOARCH)
	}
	if shaURL == "" {
		return fmt.Errorf("release %s has no .sha256 sidecar for %s: refusing to install an unverified tarball", rel.TagName, tarballName)
	}
	tmp, err := os.MkdirTemp("", "nexounel-install-*")
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
		return fmt.Errorf("install %s: %w", tarballName, err)
	}
	// Fresh install: enable the units the tarball just installed.
	// Reinstall: the units were already enabled; enable is idempotent.
	role = a.DetectRole(ctx)
	for _, unit := range role.Units() {
		if _, err := a.systemctl(ctx, "enable", unit); err != nil {
			a.Errorf("warning: could not enable %s: %v", unit, err)
		}
		if _, err := a.systemctl(ctx, "start", unit); err != nil {
			a.Errorf("warning: could not start %s: %v", unit, err)
		}
	}
	a.Printf("Installed Nexounel %s.", rel.TagName)
	for _, st := range a.ServiceStates(ctx, role.Units()) {
		a.Printf("%-24s active=%-10s enabled=%s", st.Unit, st.Active, st.Enabled)
	}
	if role.Mother {
		if url := a.panelURL(); url != "" {
			a.Printf("Panel URL: %s", url)
		} else {
			a.Printf("Panel is not initialized yet. Run `nexounel-panel -init` as root, then `nexounel start`.")
		}
	}
	a.Printf("Run `nexounel` to manage Nexounel.")
	return nil
}
