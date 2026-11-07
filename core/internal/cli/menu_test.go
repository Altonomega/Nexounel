package cli

import (
	"context"
	"strings"
	"testing"
)

func scriptServiceStates(r *fakeRunner, active, enabled string) {
	for _, unit := range []string{ServerUnit, PanelUnit, NodeUnit} {
		r.script("systemctl", []string{"is-active", unit}, active+"\n", nil)
		r.script("systemctl", []string{"is-enabled", unit}, enabled+"\n", nil)
	}
}

func TestMenuExitsOnZero(t *testing.T) {
	app, r := newTestApp(t, t.TempDir(), t.TempDir())
	scriptRole(r, true, false)
	scriptServiceStates(r, "active", "enabled")
	app.in = strings.NewReader("0\n")

	if err := app.RunMenu(context.Background()); err != nil {
		t.Fatalf("RunMenu: %v", err)
	}
	out := app.stdout()
	if !strings.Contains(out, "Nexounel Management") {
		t.Errorf("menu did not render:\n%s", out)
	}
	if !strings.Contains(out, "Server state: active") {
		t.Errorf("footer missing server state:\n%s", out)
	}
	if !strings.Contains(out, "Panel URL:") {
		// No panel config exists in the temp home: the URL is
		// absent rather than wrong.
		t.Logf("no panel URL in footer (expected: no panel config in temp home)")
	}
}

func TestMenuRejectsUnknownChoice(t *testing.T) {
	app, r := newTestApp(t, t.TempDir(), t.TempDir())
	scriptRole(r, true, false)
	scriptServiceStates(r, "active", "enabled")
	app.in = strings.NewReader("99\n0\n")

	if err := app.RunMenu(context.Background()); err != nil {
		t.Fatalf("RunMenu: %v", err)
	}
	if !strings.Contains(app.stderr(), "unknown choice 99") {
		t.Errorf("unknown choice was not reported: stdout=%q stderr=%q", app.stdout(), app.stderr())
	}
}

func TestMenuHidesPanelActionsOnNode(t *testing.T) {
	app, r := newTestApp(t, t.TempDir(), t.TempDir())
	scriptRole(r, false, true)
	scriptServiceStates(r, "active", "enabled")
	app.in = strings.NewReader("0\n")

	if err := app.RunMenu(context.Background()); err != nil {
		t.Fatalf("RunMenu: %v", err)
	}
	out := app.stdout()
	if strings.Contains(out, "Reset panel username") {
		t.Errorf("panel action shown on a node-only box:\n%s", out)
	}
	if !strings.Contains(out, "Panel actions (4, 5, 6, 15) are available on the mother only.") {
		t.Errorf("mother-only note missing:\n%s", out)
	}
	if !strings.Contains(out, "Node state:   active") {
		t.Errorf("node footer missing:\n%s", out)
	}
}

func TestDispatchRejectsMotherOnlyOnNode(t *testing.T) {
	app, _ := newTestApp(t, t.TempDir(), t.TempDir())
	role := Role{Node: true}
	err := app.dispatch(context.Background(), role, 4)
	if err == nil || !strings.Contains(err.Error(), "only available on the mother") {
		t.Errorf("dispatch(4) on node-only box: err=%v", err)
	}
}

func TestDispatchStatus(t *testing.T) {
	app, r := newTestApp(t, t.TempDir(), t.TempDir())
	scriptRole(r, true, false)
	scriptServiceStates(r, "active", "enabled")
	// checkStatus also fetches server health; the panel config is
	// absent so it uses the default metrics address and fails
	// gracefully (server down is reported, not fabricated).
	role := Role{Mother: true}
	if err := app.dispatch(context.Background(), role, 11); err != nil {
		t.Fatalf("dispatch(11): %v", err)
	}
	if !strings.Contains(app.stdout(), "nexounel.service") {
		t.Errorf("status did not list the service:\n%s", app.stdout())
	}
}
