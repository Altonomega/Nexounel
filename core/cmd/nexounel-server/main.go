// ==============================================================================
// Nexounel server (mother): DNS tunnel server derived from the CottenDNS
// core (MIT; see NOTICE). Serves tunnel clients over DNS (UDP/TCP, plus
// optional DoT/DoH), with per-node keys from a file-based registry.
// ==============================================================================

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	"github.com/MNSH-Nexo/Nexounel/core/internal/control"
	"github.com/MNSH-Nexo/Nexounel/core/internal/logger"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
	"github.com/MNSH-Nexo/Nexounel/core/internal/runtimepath"
	"github.com/MNSH-Nexo/Nexounel/core/internal/security"
	"github.com/MNSH-Nexo/Nexounel/core/internal/tunnelinfo"
	UDPServer "github.com/MNSH-Nexo/Nexounel/core/internal/udpserver"
	"github.com/MNSH-Nexo/Nexounel/core/internal/version"
)

func main() {
	configPath := flag.String("config", "nexounel-server.toml", "Path to server configuration file")
	logPath := flag.String("log", "", "Path to log file (optional)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	capabilitiesFlag := flag.Bool("capabilities", false, "Print supported tunnel modes and DNS transports, then exit")
	checkConfigFlag := flag.Bool("check-config", false, "Validate configuration without opening listeners or generating keys")
	metricsAddress := flag.String("metrics-address", "", "Optional HTTP health/Prometheus listen address (for example 127.0.0.1:9090)")
	configFlags, err := config.NewServerConfigFlagBinder(flag.CommandLine)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Server flag setup failed: %v\n", err)
		os.Exit(2)
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Nexounel Server Version: %s\n", version.GetVersion())
		return
	}
	if *capabilitiesFlag {
		fmt.Println("nexounel-normal dns-udp dns-tcp shared-key per-node-key")
		return
	}

	resolvedConfigPath := runtimepath.Resolve(*configPath)

	cfg, err := config.LoadServerConfigWithOverrides(resolvedConfigPath, configFlags.Overrides())
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Server startup failed: %v\n", err)
		os.Exit(1)
	}
	if *checkConfigFlag {
		if len(cfg.Domain) == 0 {
			fmt.Fprintln(os.Stderr, "Server configuration has no allowed domains")
			os.Exit(1)
		}
		if cfg.NodeRegistryFile != "" {
			if _, err := multisession.LoadRegistry(cfg.NodeRegistryFile); err != nil {
				fmt.Fprintf(os.Stderr, "Server configuration has an unreadable node registry: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Println("Server configuration is valid")
		return
	}

	var log *logger.Logger
	if *logPath != "" {
		log = logger.NewWithFile("Nexounel Server", cfg.LogLevel, *logPath)
	} else {
		log = logger.New("Nexounel Server", cfg.LogLevel)
	}

	log.Infof("============================================================")
	log.Infof("<cyan>GitHub:</cyan> <yellow>https://github.com/MNSH-Nexo/Nexounel</yellow>")
	log.Infof("<cyan>Build Version:</cyan> <yellow>%s</yellow>", version.GetVersion())
	log.Infof("============================================================")

	log.Infof("\U0001F680 <magenta>Nexounel Server starting ...</magenta>")

	// Registry mode: one codec per node, attributed by the key that
	// decrypts each session. Legacy mode: a single shared key.
	var codec *security.Codec
	var registry *multisession.Registry
	var registryCodecs []*security.Codec
	var registryIDs []string
	var keyInfo security.EncryptionKeyInfo
	if cfg.NodeRegistryFile != "" {
		registry, err = multisession.LoadRegistry(cfg.NodeRegistryFile)
		if err != nil {
			log.Errorf("\u274C <red>Node Registry Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
			os.Exit(1)
		}
		registryCodecs, err = registry.Codecs(cfg.DataEncryptionMethod)
		if err != nil {
			log.Errorf("\u274C <red>Node Codec Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
			os.Exit(1)
		}
		registryIDs = make([]string, 0, len(registry.Nodes))
		for _, node := range registry.Nodes {
			registryIDs = append(registryIDs, node.ID)
		}
		codec = registryCodecs[0]
	} else {
		keyInfo, err = security.EnsureServerEncryptionKey(cfg)
		if err != nil {
			log.Errorf("\u274C <red>Encryption Key Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
			os.Exit(1)
		}
		codec, err = security.NewCodecFromConfig(cfg, keyInfo.Key)
		if err != nil {
			log.Errorf("\u274C <red>Encryption Codec Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
			os.Exit(1)
		}
	}

	srv := UDPServer.New(cfg, log, codec)
	if registry != nil {
		srv.SetNodeCodecs(registryCodecs, registryIDs)
		log.Infof("\U0001F511 <green>Node Registry: <cyan>%d nodes</cyan> <gray>(%s)</gray></green>", len(registryIDs), strings.Join(registryIDs, ", "))
		for _, node := range registry.Nodes {
			// Fingerprints only: raw keys are never logged.
			log.Debugf("Node <cyan>%s</cyan> key fingerprint: <yellow>%s</yellow>", node.ID, security.KeyFingerprint(node.Key))
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *metricsAddress != "" {
		listener, listenErr := net.Listen("tcp", *metricsAddress)
		if listenErr != nil {
			log.Errorf("Metrics listener setup failed: %v", listenErr)
			os.Exit(1)
		}
		log.Infof("Metrics and health listener ready: <cyan>%s</cyan>", listener.Addr())
		go func() {
			if serveErr := srv.ServeMetrics(ctx, listener); serveErr != nil && ctx.Err() == nil {
				log.Errorf("Metrics listener stopped unexpectedly: %v", serveErr)
				stop()
			}
		}()
	}

	// Registry control socket (§4.1): the panel's no-restart path
	// for registry reloads, node add/remove, key rotation, and
	// session listing. It only exists in node-registry mode: with
	// a single shared key there is no registry to reload, and
	// starting a socket that cannot serve would mislead the
	// operator into thinking reloads work.
	if cfg.ControlSocketPath != "" {
		if registry == nil {
			log.Errorf("CONTROL_SOCKET_PATH is set but no NODE_REGISTRY_FILE is configured: the control socket requires node-registry mode")
			os.Exit(1)
		}
		handler, handlerErr := control.NewRegistryHandler(cfg.NodeRegistryFile, cfg.DataEncryptionMethod, srv)
		if handlerErr != nil {
			log.Errorf("Control socket handler setup failed: %v", handlerErr)
			os.Exit(1)
		}
		controlListener, listenErr := control.Listen(cfg.ControlSocketPath)
		if listenErr != nil {
			log.Errorf("Control socket setup failed: %v", listenErr)
			os.Exit(1)
		}
		defer os.Remove(cfg.ControlSocketPath)
		log.Infof("Registry control socket ready: <cyan>%s</cyan>", cfg.ControlSocketPath)
		go func() {
			if serveErr := control.Serve(ctx, controlListener, handler); serveErr != nil && ctx.Err() == nil {
				log.Errorf("Control socket stopped unexpectedly: %v", serveErr)
				stop()
			}
		}()
	}

	log.Infof("\U0001F680 <green>Server Configuration Loaded</green>")
	for _, line := range tunnelinfo.Server(cfg) {
		log.Infof("%s", line)
	}
	if len(cfg.Domain) > 0 {
		log.Infof(
			"\U0001F310 <green>Allowed Domains: <cyan>%s</cyan>, Min Label:<cyan>%d</cyan></green>",
			strings.Join(cfg.Domain, ", "),
			cfg.MinVPNLabelLength,
		)
	} else {
		log.Errorf("\u26A0\uFE0F <yellow>No Allowed Domains Configured!</yellow>")
		os.Exit(1)
	}

	log.Infof(
		"\U0001F510 <green>Encryption Method: <cyan>%s</cyan> <gray>(id=%d)</gray></green>",
		security.EncryptionMethodName(cfg.DataEncryptionMethod),
		cfg.DataEncryptionMethod,
	)
	if cfg.UseExternalSOCKS5 {
		authMode := "OFF"
		if cfg.SOCKS5Auth {
			authMode = "ON"
		}
		log.Infof(
			"\U0001F9E6 <green>External SOCKS5 Upstream: <cyan>%s:%d</cyan> <magenta>|</magenta> Auth: <cyan>%s</cyan></green>",
			cfg.ForwardIP,
			cfg.ForwardPort,
			authMode,
		)
	}

	if registry == nil {
		if keyInfo.Generated {
			log.Warnf(
				"\U0001F5DD\uFE0F <yellow>Encryption Key Generated, Path: <cyan>%s</cyan></yellow>",
				keyInfo.Path,
			)
		} else {
			log.Infof(
				"\U0001F5C2 <green>Encryption Key Loaded, Path: <cyan>%s</cyan></green>",
				keyInfo.Path,
			)
		}
		// SECURITY: never log the raw key — logs may be shipped, cached, or
		// shoulder-surfed. Emit only a non-reversible fingerprint so
		// operators can still confirm client and server share the same key.
		log.Infof(
			"\U0001F511 <green>Active Encryption Key Fingerprint: <yellow>%s</yellow> <gray>(sha256; raw key never logged)</gray></green>",
			security.KeyFingerprint(keyInfo.Key),
		)
	}
	log.Debugf("\u25B6\uFE0F <green>Starting UDP Server...</green>")

	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("\U0001F4A5 <red>Server Stopped Unexpectedly, <cyan>%v</cyan></red>", err)
		os.Exit(1)
	}

	log.Infof("\U0001F6D1 <yellow>Server Stopped</yellow>")
}
