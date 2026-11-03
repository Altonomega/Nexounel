// Command nexounel-panel is the Nexounel web panel: status views, the
// setup wizard, registry management and SSH node provisioning, all
// served under one secret path. See internal/panel for the implementation.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/logger"
	"github.com/MNSH-Nexo/Nexounel/core/internal/panel"
	"github.com/MNSH-Nexo/Nexounel/core/internal/runtimepath"
	"github.com/MNSH-Nexo/Nexounel/core/internal/version"
)

func main() {
	configPath := flag.String("config", "nexounel-panel.toml", "Path to panel configuration file")
	initFlag := flag.Bool("init", false, "Interactive first-run setup: set the admin credentials and generate the secret path")
	forceFlag := flag.Bool("force", false, "With -init, allow overwriting an existing panel config")
	checkConfigFlag := flag.Bool("check-config", false, "Validate the panel configuration and exit")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	logPath := flag.String("log", "", "Path to log file (overrides the config log_file)")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Nexounel Panel Version: %s\n", version.GetVersion())
		return
	}

	resolvedConfigPath := runtimepath.Resolve(*configPath)

	if *initFlag {
		if err := runInit(resolvedConfigPath, *forceFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Panel setup failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	cfg, err := panel.LoadConfig(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Panel startup failed: cannot load config %s: %v\n", resolvedConfigPath, err)
		fmt.Fprintln(os.Stderr, "Run nexounel-panel -init to set up admin credentials.")
		os.Exit(1)
	}
	if *checkConfigFlag {
		if err := panel.ValidateConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Panel configuration is invalid: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Panel configuration is valid")
		return
	}
	if !cfg.HasCredentials() {
		fmt.Fprintln(os.Stderr, "Panel has no admin credentials configured.")
		fmt.Fprintln(os.Stderr, "Run nexounel-panel -init to set up admin credentials.")
		os.Exit(1)
	}
	if err := panel.ValidateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Panel configuration is invalid: %v\n", err)
		os.Exit(1)
	}

	logFile := cfg.LogFile
	if *logPath != "" {
		logFile = *logPath
	}
	log := logger.NewWithFile("Nexounel Panel", "INFO", logFile)

	// Fail fast when the listen address is already occupied, with a
	// clear message, instead of starting half-configured.
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Panel startup failed: listen address %s is unavailable: %v\n", cfg.ListenAddr, err)
		os.Exit(1)
	}
	srv := panel.NewServer(cfg, resolvedConfigPath, log)
	log.Infof("Panel listening on %s", cfg.ListenAddr)
	// Loopback enrollment API (§3.4): the endpoint the tunnel
	// server relays bootstrap enrollment to. Empty address =
	// disabled (bootstrap enrollment unavailable; nodes retry
	// transiently). A non-loopback address is refused before any
	// socket is opened: loopback binding is the API's only
	// authentication boundary. A bind failure is fatal, like the
	// main listener: serving the UI while enrollment silently
	// cannot work would mislead the operator.
	if strings.TrimSpace(cfg.EnrollmentAddr) != "" {
		if err := panel.ValidateEnrollmentAddr(cfg.EnrollmentAddr); err != nil {
			fmt.Fprintf(os.Stderr, "Panel startup failed: %v\n", err)
			os.Exit(1)
		}
		enrollListener, err := net.Listen("tcp", cfg.EnrollmentAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Panel startup failed: enrollment listen address %s is unavailable: %v\n", cfg.EnrollmentAddr, err)
			os.Exit(1)
		}
		log.Infof("Enrollment API listening on %s (loopback only)", cfg.EnrollmentAddr)
		go func() {
			if err := serve(enrollListener, srv.EnrollmentHandler()); err != nil {
				log.Errorf("Enrollment API stopped: %v", err)
			}
		}()
	} else {
		log.Infof("Enrollment API disabled: enrollment_addr is not set in the panel config (bootstrap enrollment unavailable)")
	}
	if err := serve(listener, srv); err != nil {
		fmt.Fprintf(os.Stderr, "Panel stopped: %v\n", err)
		os.Exit(1)
	}
}

func serve(listener net.Listener, handler http.Handler) error {
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	return server.Serve(listener)
}

func runInit(configPath string, force bool) error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stdout, "Admin username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read username: %w", err)
	}
	username = strings.TrimSpace(username)
	password, err := panel.ReadPassword("Admin password: ")
	if err != nil {
		return err
	}
	confirm, err := panel.ReadPassword("Admin password (again): ")
	if err != nil {
		return err
	}
	if password != confirm {
		return fmt.Errorf("passwords do not match")
	}
	cfg, err := panel.CreateInitialConfig(configPath, force, username, password)
	if err != nil {
		return err
	}
	// Print the panel URL exactly once, at init completion.
	fmt.Printf("Panel URL: http://%s%s\n", cfg.ListenAddr, cfg.WebPath)
	fmt.Println("Keep the URL and admin credentials private. Restart the panel service to start serving.")
	return nil
}
