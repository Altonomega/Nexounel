package cli

import "context"

// Exported wrappers for the `nexounel` subcommands. The interactive
// menu uses the unexported methods directly; these wrappers are the
// non-interactive surface.

// CheckStatus prints service states and server/node health.
func (a *App) CheckStatus(ctx context.Context, role Role) error {
	return a.checkStatus(ctx, role)
}

// StartServices starts the units present on this box.
func (a *App) StartServices(ctx context.Context, role Role) error {
	return a.startServices(ctx, role)
}

// StopServices stops the units present on this box.
func (a *App) StopServices(ctx context.Context, role Role) error {
	return a.stopServices(ctx, role)
}

// RestartServices restarts the units present on this box.
func (a *App) RestartServices(ctx context.Context, role Role) error {
	return a.restartServices(ctx, role)
}

// ViewLogs shows (or follows) the service logs.
func (a *App) ViewLogs(ctx context.Context, role Role, follow bool) error {
	return a.viewLogs(ctx, role, follow)
}

// ViewSettings prints the current settings.
func (a *App) ViewSettings(ctx context.Context, role Role) error {
	return a.viewSettings(ctx, role)
}

// PanelInfo prints panel version, address and health (mother).
func (a *App) PanelInfo(ctx context.Context) error {
	return a.panelInfo(ctx)
}

// TunnelHealth prints loss, resolvers and sessions.
func (a *App) TunnelHealth(ctx context.Context, role Role) error {
	return a.tunnelHealth(ctx, role)
}

// Update checks for and installs the latest release. When checkOnly
// is true it only reports whether an update is available.
func (a *App) Update(ctx context.Context, role Role, checkOnly bool) error {
	return a.updateAction(ctx, role, checkOnly)
}

// Install installs or reinstalls from the latest release.
func (a *App) Install(ctx context.Context, role Role) error {
	return a.installAction(ctx, role)
}

// Uninstall removes Nexounel from this box. The caller must already
// have confirmed (--yes); the config/data questions still default
// to NO.
func (a *App) Uninstall(ctx context.Context, role Role) error {
	return a.uninstallAction(ctx, role, true)
}

// ResetPassword sets a new panel admin username and password. The
// caller must already have confirmed (--yes).
func (a *App) ResetPassword(ctx context.Context, username string) error {
	return a.resetCredentialsNonInteractive(ctx, username)
}

// SetWebpath changes the panel secret path; an empty webpath
// generates a new random one. The caller must already have
// confirmed (--yes).
func (a *App) SetWebpath(ctx context.Context, webpath string) error {
	return a.changeWebpath(ctx, webpath)
}

// SetPort changes the panel port. The caller must already have
// confirmed (--yes).
func (a *App) SetPort(ctx context.Context, port int) error {
	return a.changePort(ctx, port)
}
