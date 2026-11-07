package cli

import (
	"context"
	"fmt"
	"strings"
)

// menuItem is one numbered menu action. motherOnly items are hidden
// on a node-only box (the choice is rejected with an explanation
// when typed anyway).
type menuItem struct {
	num        int
	label      string
	motherOnly bool
	action     func(ctx context.Context, a *App, role Role) error
}

func menuItems() []menuItem {
	return []menuItem{
		{0, "Exit", false, func(ctx context.Context, a *App, role Role) error { return errExit }},
		{1, "Install / Reinstall", false, func(ctx context.Context, a *App, role Role) error {
			return a.installAction(ctx, role)
		}},
		{2, "Update (check + apply)", false, func(ctx context.Context, a *App, role Role) error {
			return a.updateAction(ctx, role, false)
		}},
		{3, "Uninstall", false, func(ctx context.Context, a *App, role Role) error {
			return a.uninstallAction(ctx, role, false)
		}},
		{4, "Reset panel username & password", true, func(ctx context.Context, a *App, role Role) error {
			return a.resetCredentials(ctx)
		}},
		{5, "Change panel webpath (secret path)", true, func(ctx context.Context, a *App, role Role) error {
			return a.changeWebpath(ctx, "")
		}},
		{6, "Change panel port", true, func(ctx context.Context, a *App, role Role) error {
			port, err := a.readPort("New panel port: ")
			if err != nil {
				return err
			}
			return a.changePort(ctx, port)
		}},
		{7, "View current settings", false, func(ctx context.Context, a *App, role Role) error {
			return a.viewSettings(ctx, role)
		}},
		{8, "Start services", false, func(ctx context.Context, a *App, role Role) error {
			return a.startServices(ctx, role)
		}},
		{9, "Stop services", false, func(ctx context.Context, a *App, role Role) error {
			return a.stopServices(ctx, role)
		}},
		{10, "Restart services", false, func(ctx context.Context, a *App, role Role) error {
			return a.restartServices(ctx, role)
		}},
		{11, "Check status", false, func(ctx context.Context, a *App, role Role) error {
			return a.checkStatus(ctx, role)
		}},
		{12, "View logs", false, func(ctx context.Context, a *App, role Role) error {
			follow := a.confirm("Follow the logs live?")
			return a.viewLogs(ctx, role, follow)
		}},
		{13, "Enable autostart (systemd)", false, func(ctx context.Context, a *App, role Role) error {
			return a.setAutostart(ctx, role, true)
		}},
		{14, "Disable autostart", false, func(ctx context.Context, a *App, role Role) error {
			return a.setAutostart(ctx, role, false)
		}},
		{15, "Panel info (version, address, health)", true, func(ctx context.Context, a *App, role Role) error {
			return a.panelInfo(ctx)
		}},
		{16, "Tunnel health (loss, resolvers, sessions)", false, func(ctx context.Context, a *App, role Role) error {
			return a.tunnelHealth(ctx, role)
		}},
	}
}

// errExit is returned by the Exit action to stop the menu loop.
var errExit = fmt.Errorf("exit")

// RunMenu renders the interactive menu, reads choices from stdin and
// dispatches them until the operator exits (choice 0 or EOF).
func (a *App) RunMenu(ctx context.Context) error {
	role := a.DetectRole(ctx)
	for {
		a.renderMenu(ctx, role)
		choice := a.readChoice()
		if choice == 0 {
			return nil
		}
		if err := a.dispatch(ctx, role, choice); err != nil {
			if err == errExit {
				return nil
			}
			a.Errorf("error: %v", err)
		}
		fmt.Fprint(a.out, "\nPress Enter to continue...")
		if _, err := a.readLine(); err != nil {
			return nil
		}
	}
}

// dispatch runs one menu choice. A mother-only choice on a node-only
// box is rejected with an explanation.
func (a *App) dispatch(ctx context.Context, role Role, choice int) error {
	for _, item := range menuItems() {
		if item.num != choice {
			continue
		}
		if item.motherOnly && !role.Mother {
			return fmt.Errorf("action %d (%s) is only available on the mother (panel host); this box runs the node service only", item.num, item.label)
		}
		return item.action(ctx, a, role)
	}
	return fmt.Errorf("unknown choice %d: enter a number from the menu", choice)
}

// renderMenu prints the menu box and the live state footer.
func (a *App) renderMenu(ctx context.Context, role Role) {
	var b strings.Builder
	b.WriteString("╔══════════════════════════════════════════════════╗\n")
	b.WriteString("│  Nexounel Management                             │\n")
	groups := [][]int{{0}, {1, 2, 3}, {4, 5, 6, 7}, {8, 9, 10, 11, 12}, {13, 14}, {15, 16}}
	items := menuItems()
	byNum := map[int]menuItem{}
	for _, item := range items {
		byNum[item.num] = item
	}
	for gi, group := range groups {
		if gi > 0 {
			b.WriteString("│──────────────────────────────────────────────────│\n")
		}
		for _, num := range group {
			item := byNum[num]
			if item.motherOnly && !role.Mother {
				continue
			}
			fmt.Fprintf(&b, "│ %2d. %-42s│\n", item.num, item.label)
		}
	}
	b.WriteString("╚══════════════════════════════════════════════════╝\n")
	fmt.Fprint(a.out, b.String())
	a.renderFooter(ctx, role)
	if !role.Mother && role.Node {
		fmt.Fprint(a.out, "Panel actions (4, 5, 6, 15) are available on the mother only.\n")
	}
	fmt.Fprint(a.out, "\nChoice: ")
}

// renderFooter prints the live state: service states, autostart and
// the panel URL (mother) or the node state (node-only).
func (a *App) renderFooter(ctx context.Context, role Role) {
	if !role.Any() {
		fmt.Fprint(a.out, "\nNo Nexounel services are installed on this box.\n")
		return
	}
	states := a.ServiceStates(ctx, role.Units())
	byUnit := map[string]ServiceState{}
	for _, st := range states {
		byUnit[st.Unit] = st
	}
	fmt.Fprint(a.out, "\n")
	if role.Mother {
		fmt.Fprintf(a.out, "Server state: %s\n", byUnit[ServerUnit].Active)
		fmt.Fprintf(a.out, "Panel state:  %s\n", byUnit[PanelUnit].Active)
	}
	if role.Node {
		fmt.Fprintf(a.out, "Node state:   %s\n", byUnit[NodeUnit].Active)
	}
	autostart := "No"
	allEnabled := true
	for _, st := range states {
		if st.Enabled != "enabled" {
			allEnabled = false
		}
	}
	if allEnabled {
		autostart = "Yes"
	}
	fmt.Fprintf(a.out, "Autostart:    %s\n", autostart)
	if role.Mother {
		if url := a.panelURL(); url != "" {
			fmt.Fprintf(a.out, "Panel URL:    %s\n", url)
		}
	}
}
