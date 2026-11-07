// Command nexounel is the Nexounel terminal management menu.
//
// Running `nexounel` with no arguments opens the interactive menu
// (see core/internal/cli). Subcommands cover the same actions for
// scripts: status, start, stop, restart, logs, version, update,
// install, uninstall, reset-password, set-webpath, set-port.
//
// Service control and config edits need root, like x-ui: when run as
// a non-root user the command re-execs via sudo when available.
// `nexounel version` works without root.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Altonomega/Nexounel/core/internal/cli"
	"github.com/Altonomega/Nexounel/core/internal/version"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:]))
}

func run(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("nexounel", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage() }
	home := fs.String("home", cli.DefaultHome, "Nexounel install directory")
	unitDir := fs.String("unitdir", cli.DefaultUnitDir, "systemd unit directory")
	panelConf := fs.String("config", "", "Panel config path (default $home/nexounel-panel.toml)")
	yes := fs.Bool("yes", false, "Confirm a destructive action without prompting")
	checkOnly := fs.Bool("check-only", false, "With update: only report whether an update is available")
	follow := fs.Bool("follow", false, "With logs: follow the log live")
	username := fs.String("username", "", "With reset-password: the new admin username")
	webpath := fs.String("webpath", "", "With set-webpath: the new secret path (default: generate one)")
	versionFlag := fs.Bool("version", false, "Print the version and exit")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *versionFlag {
		fmt.Printf("nexounel %s\n", version.GetVersion())
		return 0
	}

	cfg := cli.Config{
		Home:      *home,
		UnitDir:   *unitDir,
		BinLink:   cli.DefaultBinLink,
		LogDir:    cli.DefaultLogDir,
		PanelConf: *panelConf,
	}
	if cfg.PanelConf == "" {
		cfg.PanelConf = filepath.Join(cfg.Home, cli.PanelConfigName)
	}
	rest := fs.Args()
	app := cli.NewApp(cfg, os.Stdin, os.Stdout, os.Stderr, nil)

	// No subcommand: the interactive menu.
	if len(rest) == 0 {
		if code := requireRoot("the management menu"); code >= 0 {
			return code
		}
		if err := app.RunMenu(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return 0
	}

	cmd := rest[0]
	cmdArgs := rest[1:]

	// version works without root.
	if cmd == "version" {
		fmt.Printf("nexounel %s\n", version.GetVersion())
		return 0
	}
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		usage()
		return 0
	}

	if code := requireRoot("nexounel " + cmd); code >= 0 {
		return code
	}
	role := app.DetectRole(ctx)

	switch cmd {
	case "status":
		if err := app.CheckStatus(ctx, role); err != nil {
			return fail(err)
		}
	case "start":
		if err := app.StartServices(ctx, role); err != nil {
			return fail(err)
		}
	case "stop":
		if err := app.StopServices(ctx, role); err != nil {
			return fail(err)
		}
	case "restart":
		if err := app.RestartServices(ctx, role); err != nil {
			return fail(err)
		}
	case "logs":
		if err := app.ViewLogs(ctx, role, *follow); err != nil {
			return fail(err)
		}
	case "update":
		if err := app.Update(ctx, role, *checkOnly); err != nil {
			return fail(err)
		}
	case "install":
		if err := app.Install(ctx, role); err != nil {
			return fail(err)
		}
	case "uninstall":
		if !*yes {
			fmt.Fprintln(os.Stderr, "uninstall requires --yes (destructive: it stops the services and removes the binaries and units)")
			return 2
		}
		if err := app.Uninstall(ctx, role); err != nil {
			return fail(err)
		}
	case "reset-password":
		if !*yes {
			fmt.Fprintln(os.Stderr, "reset-password requires --yes")
			return 2
		}
		if err := app.ResetPassword(ctx, *username); err != nil {
			return fail(err)
		}
	case "set-webpath":
		if !*yes {
			fmt.Fprintln(os.Stderr, "set-webpath requires --yes")
			return 2
		}
		if err := app.SetWebpath(ctx, *webpath); err != nil {
			return fail(err)
		}
	case "set-port":
		if !*yes {
			fmt.Fprintln(os.Stderr, "set-port requires --yes")
			return 2
		}
		if len(cmdArgs) != 1 {
			fmt.Fprintln(os.Stderr, "usage: nexounel set-port PORT --yes")
			return 2
		}
		port, err := strconv.Atoi(cmdArgs[0])
		if err != nil || port < 1 || port > 65535 {
			fmt.Fprintf(os.Stderr, "invalid port %q: must be a number between 1 and 65535\n", cmdArgs[0])
			return 2
		}
		if err := app.SetPort(ctx, port); err != nil {
			return fail(err)
		}
	case "settings":
		if err := app.ViewSettings(ctx, role); err != nil {
			return fail(err)
		}
	case "panel-info":
		if err := app.PanelInfo(ctx); err != nil {
			return fail(err)
		}
	case "tunnel-health":
		if err := app.TunnelHealth(ctx, role); err != nil {
			return fail(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", cmd)
		usage()
		return 2
	}
	return 0
}

// requireRoot re-execs via sudo when the process is not root and
// sudo is available. It returns -1 when root (or when the re-exec
// is disabled for tests via NEXOUNEL_NO_SUDO_REEXEC), and an exit
// code otherwise. The returned code is the exit code the process
// should use; -1 means "continue as root".
func requireRoot(what string) int {
	if os.Geteuid() == 0 {
		return -1
	}
	if os.Getenv("NEXOUNEL_NO_SUDO_REEXEC") != "" {
		return -1
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexounel needs root to manage %s. Run it as root or install sudo.\n", what)
		return 1
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexounel needs root to manage %s: %v\n", what, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Re-running as root via sudo to manage %s...\n", what)
	args := append([]string{self}, os.Args[1:]...)
	if err := syscall.Exec(sudo, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "sudo re-exec failed: %v\n", err)
		return 1
	}
	return 0 // unreachable when Exec succeeds
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	return 1
}

func usage() {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(`
Usage: nexounel [flags] [subcommand]

No subcommand opens the interactive management menu.

Subcommands:
  status          Show service states and server health
  start           Start the Nexounel services on this box
  stop            Stop the Nexounel services on this box
  restart         Restart the Nexounel services on this box
  logs [--follow] Show (or follow) the service logs
  settings        Show the current settings
  panel-info      Show panel version, address and health (mother)
  tunnel-health   Show loss, resolvers and sessions
  update [--check-only]
                  Check for and install the latest release
  install         Install / reinstall from the latest release
  uninstall --yes
                  Remove Nexounel from this box (asks about configs)
  reset-password --username NAME --yes
                  Set a new panel admin username and password
  set-webpath [--webpath /PATH] --yes
                  Change the panel secret path (default: generate one)
  set-port PORT --yes
                  Change the panel port
  version         Print the version and exit

Flags:
  --home DIR      Install directory (default /opt/nexounel)
  --unitdir DIR   systemd unit directory (default /etc/systemd/system)
  --config PATH   Panel config path (default $home/nexounel-panel.toml)

Service control and config edits need root; the command re-execs
via sudo when run as a non-root user. It never touches x-ui, Xray
or WaterWall.
`))
}
