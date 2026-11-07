package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner scripts command outputs for tests. Any command not
// scripted fails loudly so a test cannot silently pass on a call
// the author forgot to stub.
type fakeRunner struct {
	outputs map[string]fakeOutput
	calls   []string
}

type fakeOutput struct {
	out string
	err error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{outputs: map[string]fakeOutput{}}
}

// script registers an output for "name arg1 arg2 ...".
func (f *fakeRunner) script(name string, args []string, out string, err error) {
	f.outputs[strings.Join(append([]string{name}, args...), " ")] = fakeOutput{out, err}
}

func (f *fakeRunner) Output(ctx context.Context, name string, args ...string) (string, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, key)
	if o, ok := f.outputs[key]; ok {
		return o.out, o.err
	}
	return "", fmt.Errorf("fakeRunner: unexpected command %q (not scripted)", key)
}

func (f *fakeRunner) Attach(ctx context.Context, name string, args ...string) error {
	key := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, key)
	if o, ok := f.outputs[key]; ok {
		return o.err
	}
	return fmt.Errorf("fakeRunner: unexpected command %q (not scripted)", key)
}

func (f *fakeRunner) called(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// newTestApp builds an App over temp dirs with a fake runner.
func newTestApp(t *testing.T, home, unitDir string) (*App, *fakeRunner) {
	t.Helper()
	runner := newFakeRunner()
	cfg := Config{
		Home:      home,
		UnitDir:   unitDir,
		BinLink:   home + "/nexounel-link",
		LogDir:    home + "/logs",
		PanelConf: home + "/nexounel-panel.toml",
	}
	app := NewApp(cfg, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}, runner)
	return app, runner
}

func (a *App) stdout() string {
	if b, ok := a.out.(*bytes.Buffer); ok {
		return b.String()
	}
	return ""
}

func (a *App) stderr() string {
	if b, ok := a.errW.(*bytes.Buffer); ok {
		return b.String()
	}
	return ""
}

// scriptRole scripts DetectRole to return the given role via
// `systemctl list-unit-files`.
func scriptRole(r *fakeRunner, mother, node bool) {
	var lines []string
	if mother {
		lines = append(lines, "nexounel.service enabled enabled", "nexounel-panel.service enabled enabled")
	}
	if node {
		lines = append(lines, "nexounel-node.service enabled enabled")
	}
	r.script("systemctl", []string{"list-unit-files", "nexounel.service", "nexounel-panel.service", "nexounel-node.service"}, strings.Join(lines, "\n")+"\n", nil)
}

func TestListenHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"0.0.0.0:18081", "localhost:18081"},
		{"127.0.0.1:9090", "127.0.0.1:9090"},
		{"192.0.2.10:18081", "192.0.2.10:18081"},
		{"[::]:18081", "localhost:18081"},
		{"not-an-addr", "not-an-addr"},
	}
	for _, c := range cases {
		if got := listenHost(c.in); got != c.want {
			t.Errorf("listenHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDetectRole(t *testing.T) {
	ctx := context.Background()

	app, r := newTestApp(t, "/tmp/nonexistent-home", "/tmp/nonexistent-units")
	scriptRole(r, true, false)
	role := app.DetectRole(ctx)
	if !role.Mother || role.Node {
		t.Errorf("mother-only role = %+v", role)
	}
	if got := role.Units(); len(got) != 2 || got[0] != ServerUnit || got[1] != PanelUnit {
		t.Errorf("mother units = %v", got)
	}

	app, r = newTestApp(t, "/tmp/nonexistent-home", "/tmp/nonexistent-units")
	scriptRole(r, false, true)
	role = app.DetectRole(ctx)
	if role.Mother || !role.Node {
		t.Errorf("node-only role = %+v", role)
	}
	if got := role.Units(); len(got) != 1 || got[0] != NodeUnit {
		t.Errorf("node units = %v", got)
	}

	app, r = newTestApp(t, "/tmp/nonexistent-home", "/tmp/nonexistent-units")
	scriptRole(r, false, false)
	role = app.DetectRole(ctx)
	if role.Any() {
		t.Errorf("empty role = %+v", role)
	}
}

func TestDetectRoleFallbackToUnitFiles(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	unitDir := t.TempDir()
	// systemctl fails: fall back to the unit files.
	app, r := newTestApp(t, home, unitDir)
	r.script("systemctl", []string{"list-unit-files", "nexounel.service", "nexounel-panel.service", "nexounel-node.service"}, "", fmt.Errorf("systemctl not found"))
	// No unit files yet: no role.
	if role := app.DetectRole(ctx); role.Any() {
		t.Errorf("role with no unit files = %+v", role)
	}
	// Add the node unit file: node role.
	if err := writeTestFile(unitDir+"/nexounel-node.service", "[Unit]\n"); err != nil {
		t.Fatal(err)
	}
	if role := app.DetectRole(ctx); !role.Node || role.Mother {
		t.Errorf("role with node unit file = %+v", role)
	}
}

func TestServiceStates(t *testing.T) {
	ctx := context.Background()
	app, r := newTestApp(t, "/tmp/nonexistent-home", "/tmp/nonexistent-units")
	r.script("systemctl", []string{"is-active", "nexounel.service"}, "active\n", nil)
	r.script("systemctl", []string{"is-enabled", "nexounel.service"}, "enabled\n", nil)
	r.script("systemctl", []string{"is-active", "nexounel-panel.service"}, "inactive\n", fmt.Errorf("exit status 3"))
	r.script("systemctl", []string{"is-enabled", "nexounel-panel.service"}, "enabled\n", nil)

	states := app.ServiceStates(ctx, []string{ServerUnit, PanelUnit})
	if len(states) != 2 {
		t.Fatalf("states = %v", states)
	}
	if states[0].Active != "active" || states[0].Enabled != "enabled" {
		t.Errorf("server state = %+v", states[0])
	}
	// is-active exits non-zero for inactive, but the output is
	// still the state: the caller must not lose it.
	if states[1].Active != "inactive" || states[1].Enabled != "enabled" {
		t.Errorf("panel state = %+v", states[1])
	}
}

func writeTestFile(path, content string) error {
	return writeFileMode(path, content, 0o644)
}

func writeFileMode(path, content string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), mode)
}
