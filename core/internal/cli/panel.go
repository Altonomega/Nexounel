package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Altonomega/Nexounel/core/internal/panel"
)

// loadPanelConfig reads the panel config for this App.
func (a *App) loadPanelConfig() (panel.Config, error) {
	return panel.LoadConfig(a.cfg.PanelConf)
}

// savePanelConfig writes a panel config atomically (0600) after
// preserving the previous file as .bak. The new config is validated
// BEFORE the .bak is written, so a failed edit leaves the working
// config untouched and writes no .bak.
func (a *App) savePanelConfig(cfg panel.Config) error {
	if err := panel.ValidateConfig(cfg); err != nil {
		return err
	}
	path := a.cfg.PanelConf
	if _, err := os.Stat(path); err == nil {
		bak := path + ".bak"
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read current panel config for backup: %w", err)
		}
		if err := os.WriteFile(bak, data, 0o600); err != nil {
			return fmt.Errorf("preserve panel config backup %s: %w", bak, err)
		}
	}
	return panel.SaveConfig(path, cfg)
}

// restartPanel restarts the panel unit and reports the result.
func (a *App) restartPanel(ctx context.Context) error {
	if _, err := a.systemctl(ctx, "restart", PanelUnit); err != nil {
		return fmt.Errorf("restart %s: %w", PanelUnit, err)
	}
	state, _ := a.systemctl(ctx, "is-active", PanelUnit)
	a.Printf("Panel state: %s", state)
	return nil
}

// resetCredentials prompts for a new admin username and password
// (hidden, twice), hashes the password with argon2id, and writes the
// new credentials to the panel config. The password and its hash are
// never printed.
func (a *App) resetCredentials(ctx context.Context) error {
	cfg, err := a.loadPanelConfig()
	if err != nil {
		return fmt.Errorf("load panel config: %w", err)
	}
	username, err := a.prompt("New panel username: ")
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username must not be empty")
	}
	password, err := a.readPassword("New panel password: ")
	if err != nil {
		return err
	}
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	again, err := a.readPassword("New panel password (again): ")
	if err != nil {
		return err
	}
	if password != again {
		return fmt.Errorf("passwords do not match")
	}
	hash, err := panel.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	cfg.Username = username
	cfg.PasswordHash = hash
	if err := a.savePanelConfig(cfg); err != nil {
		return err
	}
	a.Printf("Panel credentials updated for user %q. Restarting the panel...", username)
	return a.restartPanel(ctx)
}

// resetCredentialsNonInteractive is the subcommand form: the username
// comes from a flag, the password is read hidden (or piped). The
// caller must already have confirmed (--yes).
func (a *App) resetCredentialsNonInteractive(ctx context.Context, username string) error {
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("username must not be empty (use --username)")
	}
	cfg, err := a.loadPanelConfig()
	if err != nil {
		return fmt.Errorf("load panel config: %w", err)
	}
	password, err := a.readPassword("New panel password: ")
	if err != nil {
		return err
	}
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	again, err := a.readPassword("New panel password (again): ")
	if err != nil {
		return err
	}
	if password != again {
		return fmt.Errorf("passwords do not match")
	}
	hash, err := panel.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	cfg.Username = strings.TrimSpace(username)
	cfg.PasswordHash = hash
	if err := a.savePanelConfig(cfg); err != nil {
		return err
	}
	a.Printf("Panel credentials updated for user %q. Restarting the panel...", cfg.Username)
	return a.restartPanel(ctx)
}

// changeWebpath generates a new random secret path, writes it to the
// panel config, restarts the panel, and prints the new panel URL.
func (a *App) changeWebpath(ctx context.Context, explicit string) error {
	cfg, err := a.loadPanelConfig()
	if err != nil {
		return fmt.Errorf("load panel config: %w", err)
	}
	var webpath string
	if explicit != "" {
		webpath = explicit
		if err := panel.ValidateWebPath(webpath); err != nil {
			return err
		}
	} else {
		webpath, err = panel.GenerateWebPath()
		if err != nil {
			return err
		}
	}
	if webpath == cfg.WebPath {
		a.Printf("Web path is already %s (no change).", webpath)
		return nil
	}
	cfg.WebPath = webpath
	if err := a.savePanelConfig(cfg); err != nil {
		return err
	}
	a.Printf("Panel web path changed. Restarting the panel...")
	if err := a.restartPanel(ctx); err != nil {
		return err
	}
	a.Printf("New panel URL: %s", a.panelURL())
	return nil
}

// changePort prompts for a new panel port, validates it (1-65535, not
// in use), writes it to the panel config, restarts the panel, and
// prints the new panel URL.
func (a *App) changePort(ctx context.Context, port int) error {
	cfg, err := a.loadPanelConfig()
	if err != nil {
		return fmt.Errorf("load panel config: %w", err)
	}
	host, curPort, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("current listen_addr %q is invalid: %w", cfg.ListenAddr, err)
	}
	if strconv.Itoa(port) == curPort {
		a.Printf("Panel port is already %d (no change).", port)
		return nil
	}
	if err := checkPortFree(port); err != nil {
		return err
	}
	cfg.ListenAddr = net.JoinHostPort(host, strconv.Itoa(port))
	if err := a.savePanelConfig(cfg); err != nil {
		return err
	}
	a.Printf("Panel port changed to %d. Restarting the panel...", port)
	if err := a.restartPanel(ctx); err != nil {
		return err
	}
	a.Printf("New panel URL: %s", a.panelURL())
	return nil
}

// checkPortFree reports an error when something already listens on
// the given TCP port on all interfaces.
func checkPortFree(port int) error {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return fmt.Errorf("port %d is already in use: %w", port, err)
	}
	_ = ln.Close()
	return nil
}

// panelConfigPath returns the panel config path for display.
func (a *App) panelConfigPath() string { return a.cfg.PanelConf }
