package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/panel"
	"github.com/Altonomega/Nexounel/core/internal/version"
)

// startServices starts the units present on this box and reports each
// unit's state after.
func (a *App) startServices(ctx context.Context, role Role) error {
	return a.controlServices(ctx, role, "start")
}

// stopServices stops the units present on this box and reports each
// unit's state after.
func (a *App) stopServices(ctx context.Context, role Role) error {
	return a.controlServices(ctx, role, "stop")
}

// restartServices restarts the units present on this box and reports
// each unit's state after.
func (a *App) restartServices(ctx context.Context, role Role) error {
	return a.controlServices(ctx, role, "restart")
}

func (a *App) controlServices(ctx context.Context, role Role, verb string) error {
	units := role.Units()
	if len(units) == 0 {
		return fmt.Errorf("no Nexounel services are installed on this box")
	}
	var failed []string
	for _, unit := range units {
		if _, err := a.systemctl(ctx, verb, unit); err != nil {
			a.Errorf("systemctl %s %s failed: %v", verb, unit, err)
			failed = append(failed, unit)
			continue
		}
		state, _ := a.systemctl(ctx, "is-active", unit)
		a.Printf("%s: %s", unit, state)
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed to %s: %s", verb, strings.Join(failed, ", "))
	}
	return nil
}

// setAutostart enables or disables the units present on this box.
func (a *App) setAutostart(ctx context.Context, role Role, enable bool) error {
	units := role.Units()
	if len(units) == 0 {
		return fmt.Errorf("no Nexounel services are installed on this box")
	}
	verb := "disable"
	if enable {
		verb = "enable"
	}
	var failed []string
	for _, unit := range units {
		if _, err := a.systemctl(ctx, verb, unit); err != nil {
			a.Errorf("systemctl %s %s failed: %v", verb, unit, err)
			failed = append(failed, unit)
			continue
		}
		enabled, _ := a.systemctl(ctx, "is-enabled", unit)
		a.Printf("%s: %s", unit, enabled)
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed to %s: %s", verb, strings.Join(failed, ", "))
	}
	return nil
}

// checkStatus prints is-active + is-enabled for each unit, plus the
// server health (mother) or the node listener check (node).
func (a *App) checkStatus(ctx context.Context, role Role) error {
	units := role.Units()
	if len(units) == 0 {
		return fmt.Errorf("no Nexounel services are installed on this box")
	}
	a.Printf("Nexounel %s", version.GetVersion())
	for _, st := range a.ServiceStates(ctx, units) {
		a.Printf("%-24s active=%-10s enabled=%s", st.Unit, st.Active, st.Enabled)
	}
	if role.Mother {
		a.printServerHealth(ctx)
	} else if role.Node {
		a.printNodeHealth(ctx)
	}
	return nil
}

// viewLogs shows the last 100 journal lines for each unit, or follows
// the log live when follow is true.
func (a *App) viewLogs(ctx context.Context, role Role, follow bool) error {
	units := role.Units()
	if len(units) == 0 {
		return fmt.Errorf("no Nexounel services are installed on this box")
	}
	for _, unit := range units {
		if follow {
			a.Printf("Following %s (Ctrl-C to stop)...", unit)
			if err := a.run.Attach(ctx, "journalctl", "-u", unit, "-f", "--no-pager"); err != nil {
				return fmt.Errorf("journalctl -f %s: %w", unit, err)
			}
			continue
		}
		out, err := a.run.Output(ctx, "journalctl", "-u", unit, "-n", "100", "--no-pager")
		if err != nil {
			a.Errorf("journalctl %s failed: %v", unit, err)
			continue
		}
		a.Printf("--- %s (last 100 lines) ---", unit)
		fmt.Fprint(a.out, out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Fprint(a.out, "\n")
		}
	}
	return nil
}

// viewSettings prints the panel port, webpath URL, username, autostart
// state and service states (mother), or the node service state and
// config path (node-only box).
func (a *App) viewSettings(ctx context.Context, role Role) error {
	if role.Mother {
		cfg, err := a.loadPanelConfig()
		if err != nil {
			return fmt.Errorf("load panel config: %w", err)
		}
		a.Printf("Panel version:  %s", version.GetVersion())
		a.Printf("Panel address:  %s", cfg.ListenAddr)
		a.Printf("Panel URL:      %s", a.panelURL())
		a.Printf("Panel username: %s", cfg.Username)
		a.Printf("Panel config:   %s", a.cfg.PanelConf)
	}
	if role.Node {
		a.Printf("Node config:    %s", nodeConfigPath(a.cfg.Home))
	}
	for _, st := range a.ServiceStates(ctx, role.Units()) {
		a.Printf("%-24s active=%-10s enabled=%s", st.Unit, st.Active, st.Enabled)
	}
	return nil
}

func nodeConfigPath(home string) string { return home + "/nexounel-node.toml" }

// panelInfo prints the panel version, listening address, webpath URL,
// uptime and server health. Mother only.
func (a *App) panelInfo(ctx context.Context) error {
	cfg, err := a.loadPanelConfig()
	if err != nil {
		return fmt.Errorf("load panel config: %w", err)
	}
	a.Printf("Panel version: %s", version.GetVersion())
	a.Printf("Listen address: %s", cfg.ListenAddr)
	a.Printf("Panel URL:      %s", a.panelURL())
	a.Printf("Username:       %s", cfg.Username)
	a.printServerHealth(ctx)
	return nil
}

// printServerHealth fetches the server healthz/details and the
// /metrics session counters and prints them. Failures are reported,
// never fabricated.
func (a *App) printServerHealth(ctx context.Context) {
	metricsAddr := "127.0.0.1:9090"
	if cfg, err := a.loadPanelConfig(); err == nil && strings.TrimSpace(cfg.MetricsAddr) != "" {
		metricsAddr = cfg.MetricsAddr
	}
	health := panel.FetchServerHealth(ctx, metricsAddr, a.http)
	if !health.Up {
		a.Printf("Server: down (%s)", health.Error)
		return
	}
	a.Printf("Server: up")
	if health.Details != nil {
		a.Printf("Server uptime: %s", formatDuration(time.Duration(health.Details.UptimeSeconds)*time.Second))
	}
	if sessions, streams, err := a.fetchSessionCounts(ctx, metricsAddr); err == nil {
		a.Printf("Active sessions: %d, active streams: %d", sessions, streams)
	} else {
		a.Printf("Active sessions: unavailable (%v)", err)
	}
}

// fetchSessionCounts parses cottendns_active_sessions and
// cottendns_active_streams from the server /metrics endpoint.
func (a *App) fetchSessionCounts(ctx context.Context, metricsAddr string) (sessions, streams int64, err error) {
	body, err := a.httpGet(ctx, "http://"+metricsAddr+"/metrics")
	if err != nil {
		return 0, 0, err
	}
	sessions, _ = parseMetricValue(body, "cottendns_active_sessions")
	streams, _ = parseMetricValue(body, "cottendns_active_streams")
	return sessions, streams, nil
}

func (a *App) httpGet(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// parseMetricValue extracts the value of a Prometheus gauge line
// ("name value") from a /metrics body. The second return value
// reports whether the metric was found.
func parseMetricValue(body, name string) (int64, bool) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == name {
			if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// tunnelHealth prints loss, usable resolvers, active sessions/streams
// and queue depths: from the server metrics on the mother, from the
// node log tail on a node host.
func (a *App) tunnelHealth(ctx context.Context, role Role) error {
	if role.Mother {
		a.printServerHealth(ctx)
		return nil
	}
	if role.Node {
		a.printNodeHealth(ctx)
		return nil
	}
	return fmt.Errorf("no Nexounel services are installed on this box")
}

// printNodeHealth parses the last node traffic line from the journal
// and prints loss, resolvers, queues and offered rate.
func (a *App) printNodeHealth(ctx context.Context) {
	out, err := a.run.Output(ctx, "journalctl", "-u", NodeUnit, "-n", "200", "--no-pager")
	if err != nil {
		a.Printf("Node log unavailable: %v", err)
		return
	}
	line := lastTrafficLine(out)
	if line == "" {
		a.Printf("No node traffic line in the recent log.")
		return
	}
	traffic := parseTrafficLine(line)
	a.Printf("Node loss:      %.1f%%", traffic.Loss)
	a.Printf("Resolvers:      %d usable", traffic.Resolvers)
	a.Printf("Queues:         %d/%d/%d", traffic.Queue0, traffic.Queue1, traffic.Queue2)
	a.Printf("Offered:        %.0f q/s (governor cap %.0f)", traffic.Offered, traffic.GovernorCap)
}

// trafficSample is one parsed node traffic line.
type trafficSample struct {
	Loss        float64
	Resolvers   int
	Queue0      int
	Queue1      int
	Queue2      int
	Offered     float64
	GovernorCap float64
}

var trafficLineRe = regexp.MustCompile(`loss ([0-9.]+)% \| resolvers (\d+) \| transport \S+ \| queues (\d+)/(\d+)/(\d+) \| drops rx=\d+ tx=\d+ \| recoveries \d+ \| stream-fail dial=\d+ write=\d+ \| offered ([0-9.]+) q/s \| governor cap=([0-9.]+) throttled=\d+`)

// lastTrafficLine returns the last line containing a loss/resolvers
// sample, or "" when there is none.
func lastTrafficLine(log string) string {
	var last string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "loss ") && strings.Contains(line, "resolvers ") {
			last = line
		}
	}
	return last
}

// parseTrafficLine extracts the loss/resolvers/queues/offered fields
// from one node traffic line. Unmatched fields stay zero.
func parseTrafficLine(line string) trafficSample {
	var sample trafficSample
	m := trafficLineRe.FindStringSubmatch(line)
	if m == nil {
		// Fallback: the loose fields, for lines whose tail differs.
		lossRe := regexp.MustCompile(`loss ([0-9.]+)%`)
		resRe := regexp.MustCompile(`resolvers (\d+)`)
		if lm := lossRe.FindStringSubmatch(line); lm != nil {
			sample.Loss, _ = strconv.ParseFloat(lm[1], 64)
		}
		if rm := resRe.FindStringSubmatch(line); rm != nil {
			sample.Resolvers, _ = strconv.Atoi(rm[1])
		}
		return sample
	}
	sample.Loss, _ = strconv.ParseFloat(m[1], 64)
	sample.Resolvers, _ = strconv.Atoi(m[2])
	sample.Queue0, _ = strconv.Atoi(m[3])
	sample.Queue1, _ = strconv.Atoi(m[4])
	sample.Queue2, _ = strconv.Atoi(m[5])
	sample.Offered, _ = strconv.ParseFloat(m[6], 64)
	sample.GovernorCap, _ = strconv.ParseFloat(m[7], 64)
	return sample
}

// formatDuration renders a duration as "2h3m4s" (or "45s").
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}
