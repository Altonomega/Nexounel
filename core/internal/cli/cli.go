// Package cli implements the `nexounel` terminal management menu and its
// non-interactive subcommands. It manages only Nexounel's own units,
// binaries and config files; it never touches x-ui, Xray or WaterWall.
//
// The menu is role-aware: on the mother it manages the server + panel,
// on a node host it manages the node service. Remote nodes are managed
// from the panel web UI, not from this menu.
//
// Safety rules (hard): destructive actions confirm first; every config
// edit is atomic (temp file + rename, 0600) with the previous file
// preserved as .bak; secrets are never printed; an update verifies the
// release tarball's SHA-256 before any binary is replaced.
package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultHome is the install directory the CLI manages.
	DefaultHome = "/opt/nexounel"
	// DefaultUnitDir is the systemd unit directory.
	DefaultUnitDir = "/etc/systemd/system"
	// DefaultBinLink is the symlink the installer creates so the
	// operator runs `nexounel` from any directory.
	DefaultBinLink = "/usr/local/bin/nexounel"
	// DefaultLogDir holds the service logs.
	DefaultLogDir = "/var/log/nexounel"

	// PanelConfigName is the panel config file inside Home.
	PanelConfigName = "nexounel-panel.toml"

	// ServerUnit is the mother server unit.
	ServerUnit = "nexounel.service"
	// PanelUnit is the panel unit.
	PanelUnit = "nexounel-panel.service"
	// NodeUnit is the node unit.
	NodeUnit = "nexounel-node.service"
)

// Runner executes external commands. The production implementation
// shells out; tests substitute a fake with scripted outputs.
type Runner interface {
	// Output runs the command and returns its stdout. A non-zero
	// exit is an error, but the stdout is still returned: callers
	// that need the output of a command whose exit code carries
	// meaning (systemctl is-active / is-enabled) use the returned
	// text and ignore the error.
	Output(ctx context.Context, name string, args ...string) (string, error)
	// Attach runs the command with the process's stdin/stdout/stderr
	// attached (for journalctl -f). It blocks until the command exits.
	Attach(ctx context.Context, name string, args ...string) error
}

// execRunner is the production Runner.
type execRunner struct{}

func (execRunner) Output(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(ee.Stderr)))
		}
		return string(out), err
	}
	return string(out), nil
}

func (execRunner) Attach(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Config carries the install locations the CLI manages.
type Config struct {
	Home      string // install dir, default /opt/nexounel
	UnitDir   string // systemd unit dir, default /etc/systemd/system
	BinLink   string // symlink path, default /usr/local/bin/nexounel
	LogDir    string // log dir, default /var/log/nexounel
	PanelConf string // panel config path; default Home/nexounel-panel.toml
}

// DefaultConfig returns the production locations.
func DefaultConfig() Config {
	return Config{
		Home:      DefaultHome,
		UnitDir:   DefaultUnitDir,
		BinLink:   DefaultBinLink,
		LogDir:    DefaultLogDir,
		PanelConf: filepath.Join(DefaultHome, PanelConfigName),
	}
}

// App is the CLI application: locations, I/O and the command runner.
type App struct {
	cfg    Config
	in     io.Reader
	reader *bufio.Reader // lazy buffered reader over in (one per App)
	out    io.Writer
	errW   io.Writer
	run    Runner
	http   *http.Client
}

// NewApp builds an App. A nil runner uses the production exec runner;
// a nil http client uses a default one with a 30s timeout.
func NewApp(cfg Config, in io.Reader, out, errW io.Writer, run Runner) *App {
	if cfg.Home == "" {
		cfg = DefaultConfig()
	}
	if run == nil {
		run = execRunner{}
	}
	if out == nil {
		out = os.Stdout
	}
	if errW == nil {
		errW = os.Stderr
	}
	return &App{
		cfg:  cfg,
		in:   in,
		out:  out,
		errW: errW,
		run:  run,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// Config returns the App's locations.
func (a *App) Config() Config { return a.cfg }

// Printf writes a formatted line to stdout.
func (a *App) Printf(format string, args ...any) {
	fmt.Fprintf(a.out, format+"\n", args...)
}

// Errorf writes a formatted line to stderr.
func (a *App) Errorf(format string, args ...any) {
	fmt.Fprintf(a.errW, format+"\n", args...)
}

// Role says which Nexounel services are installed on this box.
type Role struct {
	Mother bool // server and/or panel unit installed
	Node   bool // node unit installed
}

// Any reports whether any Nexounel service is installed here.
func (r Role) Any() bool { return r.Mother || r.Node }

// Units returns the units present on this box, in a stable order.
func (r Role) Units() []string {
	var units []string
	if r.Mother {
		units = append(units, ServerUnit, PanelUnit)
	}
	if r.Node {
		units = append(units, NodeUnit)
	}
	return units
}

// DetectRole finds which Nexounel services are installed on this box,
// via `systemctl list-unit-files`. If systemctl is unavailable it
// falls back to checking the unit files in the unit directory.
func (a *App) DetectRole(ctx context.Context) Role {
	out, err := a.run.Output(ctx, "systemctl", "list-unit-files", ServerUnit, PanelUnit, NodeUnit)
	if err == nil {
		var role Role
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			switch fields[0] {
			case ServerUnit, PanelUnit:
				role.Mother = true
			case NodeUnit:
				role.Node = true
			}
		}
		return role
	}
	// systemctl unavailable: fall back to the unit files.
	var role Role
	if fileExists(filepath.Join(a.cfg.UnitDir, ServerUnit)) || fileExists(filepath.Join(a.cfg.UnitDir, PanelUnit)) {
		role.Mother = true
	}
	if fileExists(filepath.Join(a.cfg.UnitDir, NodeUnit)) {
		role.Node = true
	}
	return role
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ServiceState is one unit's live state.
type ServiceState struct {
	Unit    string
	Active  string // active, inactive, failed, ...
	Enabled string // enabled, disabled, ...
}

// ServiceStates reports is-active + is-enabled for each unit. A unit
// that is not installed reports Active "not-installed".
func (a *App) ServiceStates(ctx context.Context, units []string) []ServiceState {
	states := make([]ServiceState, 0, len(units))
	for _, unit := range units {
		st := ServiceState{Unit: unit}
		if out, _ := a.run.Output(ctx, "systemctl", "is-active", unit); strings.TrimSpace(out) != "" {
			st.Active = strings.TrimSpace(out)
		} else {
			st.Active = "unknown"
		}
		if out, _ := a.run.Output(ctx, "systemctl", "is-enabled", unit); strings.TrimSpace(out) != "" {
			st.Enabled = strings.TrimSpace(out)
		} else {
			st.Enabled = "unknown"
		}
		states = append(states, st)
	}
	return states
}

// systemctl runs systemctl and returns its trimmed stdout. The error is
// returned as-is; callers that only need the text ignore it.
func (a *App) systemctl(ctx context.Context, args ...string) (string, error) {
	out, err := a.run.Output(ctx, "systemctl", args...)
	return strings.TrimSpace(out), err
}

// panelURL builds the panel URL from the panel config (host part of
// listen_addr + web_path). It returns "" when the panel config cannot
// be read.
func (a *App) panelURL() string {
	cfg, err := a.loadPanelConfig()
	if err != nil {
		return ""
	}
	host := listenHost(cfg.ListenAddr)
	return "http://" + host + cfg.WebPath + "/"
}

// listenHost extracts the host from a listen address, replacing a
// wildcard bind (0.0.0.0 / [::]) with localhost for display.
func listenHost(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return host + ":" + port
}
