// ==============================================================================
// Nexounel node (Iran side): multi-session DNS tunnel client derived from
// the CottenDNS core (MIT; see NOTICE).
//
// The node probes every configured resolver once, clusters the results
// into capacity classes (see internal/multisession), runs one tunnel
// session per class at that class's margin-adjusted operating point, and
// stripes accepted TCP-forward connections across the ready classes by
// measured capacity, loss and latency.
//
// With MULTISESSION_ENABLED=false the node behaves as a single upstream
// session (one operating point for all resolvers).
// ==============================================================================

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	rand "math/rand/v2"

	"github.com/MNSH-Nexo/Nexounel/core/internal/client"
	"github.com/MNSH-Nexo/Nexounel/core/internal/compression"
	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	"github.com/MNSH-Nexo/Nexounel/core/internal/logger"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
	"github.com/MNSH-Nexo/Nexounel/core/internal/runtimepath"
	"github.com/MNSH-Nexo/Nexounel/core/internal/version"
)

func main() {
	configPath := flag.String("config", "nexounel-node.toml", "Path to node configuration file")
	resolversPath := flag.String("resolvers", "", "Path to resolver file override (optional)")
	scanOnly := flag.Bool("scan-only", false, "Scan resolvers, emit WD_SCAN results, and exit without starting the tunnel")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	enrollFlag := flag.Bool("enroll", false, "Enroll this node with a join token (outbound-only manual join, §3.3) instead of starting the tunnel")
	joinTokenFlag := flag.String("join-token", "", "Join token for --enroll (handled as a secret: never logged)")
	joinTokenFileFlag := flag.String("join-token-file", "", "File containing the join token for --enroll (preferred over --join-token)")
	configFlags, err := config.NewClientConfigFlagBinder(flag.CommandLine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Node flag setup failed: %v\n", err)
		os.Exit(2)
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Nexounel Node Version: %s\n", version.GetVersion())
		return
	}

	resolvedConfigPath := runtimepath.Resolve(*configPath)
	overrides := configFlags.Overrides()
	if *resolversPath != "" {
		resolvedResolversPath := runtimepath.Resolve(*resolversPath)
		overrides.ResolversFilePath = &resolvedResolversPath
	}

	// Load the config once here to enforce node identity and to read the
	// coordinator settings; Bootstrap reloads the same file deterministically.
	cfg, err := config.LoadClientConfigWithOverrides(resolvedConfigPath, overrides)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Node startup failed: %v\n", err)
		os.Exit(1)
	}
	// Throughput pack: apply the zstd dictionary/level/long settings.
	// Defaults reproduce the legacy encoder byte-for-byte; dictionary
	// frames require the same settings on the server.
	compression.Configure(compression.ZSTDOptions{
		DictEnabled: cfg.ZSTDDictEnabled,
		Level:       cfg.ZSTDLevel,
		LongEnabled: cfg.ZSTDLongEnabled,
	})
	if strings.TrimSpace(cfg.NodeID) == "" {
		fmt.Fprintln(os.Stderr, "Node startup failed: NODE_ID is required (per-node identity)")
		os.Exit(1)
	}
	if strings.TrimSpace(cfg.NodeKeyFile) == "" {
		fmt.Fprintln(os.Stderr, "Node startup failed: NODE_KEY_FILE is required (per-node key file)")
		os.Exit(1)
	}

	if *enrollFlag {
		var stdin io.Reader
		if strings.TrimSpace(*joinTokenFlag) == "" && strings.TrimSpace(*joinTokenFileFlag) == "" {
			// Stdin is the last token source. Refuse to block on a
			// terminal: the operator must pipe the token or use a
			// flag/file.
			if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice == 0 {
				stdin = os.Stdin
			} else {
				fmt.Fprintln(os.Stderr, "Enroll mode failed: a join token is required via --join-token, --join-token-file, or stdin")
				os.Exit(1)
			}
		}
		token, err := loadJoinToken(*joinTokenFlag, *joinTokenFileFlag, stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Enroll mode failed: %v\n", err)
			os.Exit(1)
		}
		sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = runEnrollMode(sigCtx, resolvedConfigPath, overrides, cfg, token)
		if errors.Is(err, errEnrolled) {
			fmt.Fprintln(os.Stderr, "Enrollment complete: restarting as a normal node")
			if rerr := restartAsNormalNode(resolvedConfigPath, *resolversPath); rerr != nil {
				fmt.Fprintf(os.Stderr, "Restart after enrollment failed (%v): start the node normally to pick up the issued config\n", rerr)
			}
			return
		}
		fmt.Fprintf(os.Stderr, "Enroll mode failed: %v\n", err)
		os.Exit(1)
	}

	if *scanOnly {
		app, err := client.Bootstrap(resolvedConfigPath, overrides)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Node startup failed: %v\n", err)
			os.Exit(1)
		}
		sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if _, err := app.RunResolverScan(sigCtx); err != nil {
			fmt.Fprintf(os.Stderr, "Resolver scan failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !cfg.MultiSessionEnabled {
		if err := runSingleSession(sigCtx, resolvedConfigPath, overrides, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Node stopped: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := runMultiSession(sigCtx, resolvedConfigPath, overrides, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Node stopped: %v\n", err)
		os.Exit(1)
	}
}

// runSingleSession is the upstream single-session behavior: one client,
// one operating point, its own listeners.
func runSingleSession(ctx context.Context, configPath string, overrides config.ClientConfigOverrides, cfg config.ClientConfig) error {
	app, err := bootstrapNodeClient(configPath, overrides, cfg)
	if err != nil {
		return err
	}
	app.PrintBanner()
	if log := app.Log(); log != nil {
		log.Infof("\U0001F680 <green>Nexounel Node Started (single session)</green>")
	}
	return app.Run(ctx)
}

// bootstrapNodeClient honors STARTUP_MODE (scale-audit fix F1a): "logs"
// (the default) attempts the resolver-cache fast start and falls back to
// the full probe when the cache is empty or yields nothing usable; any
// other mode always runs the full probe. The scan-only path keeps the
// plain Bootstrap: its contract is a full scan.
func bootstrapNodeClient(configPath string, overrides config.ClientConfigOverrides, cfg config.ClientConfig) (*client.Client, error) {
	if strings.EqualFold(strings.TrimSpace(cfg.StartupMode), "logs") {
		if entries := client.ScanResolverCacheLogs(cfg.ResolvedLogDir(), cfg.LogScanMaxDays, cfg.LogScanMaxResolvers); len(entries) > 0 {
			return client.BootstrapFromLogs(configPath, entries, overrides)
		}
	}
	return client.Bootstrap(configPath, overrides)
}

// runMultiSession probes, clusters, starts one session per capacity
// class, and fans accepted forward-range connections out to the classes.
func runMultiSession(ctx context.Context, configPath string, overrides config.ClientConfigOverrides, cfg config.ClientConfig) error {
	lo, hi, ranged, err := cfg.ForwardRangeBounds()
	if err != nil {
		return fmt.Errorf("invalid FORWARD_RANGE: %w", err)
	}
	if !ranged {
		return fmt.Errorf("multi-session mode requires FORWARD_RANGE (the node owns the forward listeners)")
	}
	if cfg.ProtocolType != "TCP" {
		return fmt.Errorf("multi-session mode requires PROTOCOL_TYPE=TCP (got %q)", cfg.ProtocolType)
	}
	margin := cfg.EffectiveCapacityMargin()
	if err := multisession.ValidateMargin(margin); err != nil {
		return fmt.Errorf("invalid CAPACITY_MARGIN: %w", err)
	}

	log := logger.New("Nexounel Node", cfg.LogLevel)
	log.Infof("\U0001F680 <green>Nexounel Node starting (multi-session, node <cyan>%s</cyan>)</green>", cfg.NodeID)

	// Phase 1 — probe pass. A throwaway client measures every resolver;
	// its results feed the clusterer and it is then discarded.
	probeCtx, cancelProbe := context.WithCancel(ctx)
	defer cancelProbe()
	probeClient, err := bootstrapNodeClient(configPath, overrides, cfg)
	if err != nil {
		return fmt.Errorf("probe client: %w", err)
	}
	if err := probeClient.RunInitialMTUTests(probeCtx); err != nil {
		return fmt.Errorf("probe pass failed: %w", err)
	}
	results := probeClient.ProbeResults()
	cancelProbe()
	log.Infof("\U0001F4E1 <cyan>Probe pass: <green>%d resolvers measured</green></cyan>", len(results))

	clustering := multisession.Cluster(results, 0.25, margin)
	classes := clustering.Classes
	reserves := clustering.Reserves
	if len(classes) == 0 {
		return fmt.Errorf("probe pass produced no usable capacity class")
	}
	log.Infof("\U0001F4CA <cyan>Capacity classes: <green>%d</green>, reserves: <green>%d</green></cyan>", len(classes), len(reserves))
	for i, class := range classes {
		log.Infof("  class %d: %d resolvers, operating upload=%d download=%d, score=%d, weight=%.3f",
			i, len(class.Members), class.OperatingUpload, class.OperatingDownload, class.Score, multisession.Weight(class))
	}

	// Phase 2 — one session per class. Per-class configs clamp the operating
	// point ceilings to the class operating point (floors lowered so a small
	// class can still complete a fallback probe) and suppress local
	// listeners: the coordinator owns the forward-range listeners. Each
	// class client starts from the probe pass's measurements (F1c) instead
	// of re-probing its members; only members without a measurement are
	// scanned, by the normal hybrid path.
	coord := &coordinator{
		classes: make([]*classSession, 0, len(classes)),
		log:     log,
	}
	var wg sync.WaitGroup
	for i, class := range classes {
		classOverrides := overrides
		// Preserve flag-passed overrides, then pin the class ceilings.
		values := make(map[string]any, len(overrides.Values)+5)
		for k, v := range overrides.Values {
			values[k] = v
		}
		values["MaxUploadMTU"] = class.OperatingUpload
		values["MaxDownloadMTU"] = class.OperatingDownload
		values["MinUploadMTU"] = min(cfg.MinUploadMTU, class.OperatingUpload)
		values["MinDownloadMTU"] = min(cfg.MinDownloadMTU, class.OperatingDownload)
		values["DisableLocalListeners"] = true
		classOverrides.Values = values
		classOverrides.Resolvers = make([]config.ResolverAddress, 0, len(class.Members))
		for _, member := range class.Members {
			classOverrides.Resolvers = append(classOverrides.Resolvers, config.ResolverAddress{
				IP:   member.Resolver,
				Port: member.Port,
			})
		}
		// Scale-audit fix F1c: the probe pass just measured every member.
		// Pass the measurements through (capped at the class operating
		// point, reproducing what a clamped re-probe would find) instead
		// of re-running the binary search once per class. Members the
		// probe pass rejected are never class members; a member missing
		// from the measurements is fully scanned by the hybrid path.
		measured := make([]multisession.ProbeResult, 0, len(class.Members))
		for _, member := range class.Members {
			member.UploadMTU = min(member.UploadMTU, class.OperatingUpload)
			member.DownloadMTU = min(member.DownloadMTU, class.OperatingDownload)
			measured = append(measured, member)
		}
		classClient, err := client.BootstrapWithMeasuredMTUs(configPath, classOverrides, measured)
		if err != nil {
			return fmt.Errorf("class %d client: %w", i, err)
		}
		session := &classSession{client: classClient, weight: multisession.Weight(class), index: i}
		coord.classes = append(coord.classes, session)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := classClient.Run(ctx); err != nil {
				log.Errorf("Class %d session ended with error: %v", i, err)
				session.markDead()
			}
		}()
	}

	// Phase 3 — fan-out listeners over the forward range.
	listeners, err := coord.listen(ctx, cfg.ListenIP, lo, hi)
	if err != nil {
		return err
	}
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	log.Infof("\U0001F680 <green>Nexounel Node running: forward range <cyan>%s:%d-%d</cyan> across <cyan>%d</cyan> sessions</green>",
		cfg.ListenIP, lo, hi, len(classes))

	// Block until shutdown; class sessions end with the context.
	<-ctx.Done()
	wg.Wait()
	return nil
}

// classSession is one capacity class's live session.
type classSession struct {
	client *client.Client
	weight float64
	index  int
	mu     sync.Mutex
	dead   bool
}

func (s *classSession) markDead() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dead = true
}

func (s *classSession) ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.dead && s.client.SessionReady()
}

// coordinator owns the forward-range listeners and stripes connections
// across ready class sessions by weight.
type coordinator struct {
	classes []*classSession
	log     *logger.Logger
}

func (c *coordinator) listen(ctx context.Context, ip string, lo, hi int) ([]net.Listener, error) {
	var listeners []net.Listener
	for port := lo; port <= hi; port++ {
		l, err := net.Listen("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
		if err != nil {
			for _, open := range listeners {
				_ = open.Close()
			}
			return nil, fmt.Errorf("bind forward listener %s:%d: %w", ip, port, err)
		}
		listeners = append(listeners, l)
		go c.serve(ctx, l)
	}
	return listeners, nil
}

func (c *coordinator) serve(ctx context.Context, l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
		}
		go c.handle(ctx, conn)
	}
}

func (c *coordinator) handle(ctx context.Context, conn net.Conn) {
	session := c.pick()
	if session == nil {
		if c.log != nil {
			c.log.Warnf("<yellow>No ready session for connection from %s; closing</yellow>", conn.RemoteAddr())
		}
		_ = conn.Close()
		return
	}
	session.client.HandleTCPConnect(ctx, conn)
}

// pick returns a ready class session by weighted random choice over the
// classes' probe-derived weights. Classes that are dead or whose session
// is not ready are excluded; nil means no session can take traffic.
func (c *coordinator) pick() *classSession {
	weights := make([]float64, 0, len(c.classes))
	ready := make([]*classSession, 0, len(c.classes))
	for _, session := range c.classes {
		if !session.ready() {
			continue
		}
		weights = append(weights, session.weight)
		ready = append(ready, session)
	}
	if len(ready) == 0 {
		return nil
	}
	idx := multisession.Choose(weights, weightedRandom(weights))
	if idx < 0 {
		return nil
	}
	return ready[idx]
}

// weightedRandom draws r in [0, total) for multisession.Choose.
// Exact fairness is not a correctness property here; the global
// math/rand/v2 source is auto-seeded and safe for concurrent use.
func weightedRandom(weights []float64) float64 {
	total := 0.0
	for _, w := range weights {
		total += w
	}
	if total <= 0 {
		return 0
	}
	return rand.Float64() * total
}
