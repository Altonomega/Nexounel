package panel

import (
	"context"
	"fmt"
	"time"
)

// formatDuration renders a duration compactly ("12s", "3m 4s",
// "2h 5m", "3d 2h") so the admin reads ages and uptimes at a
// glance instead of parsing a full timestamp.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Second {
		return "0s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
}

// agoString renders a timestamp as a relative age ("just now",
// "12s", "3m 4s", "2h 5m", "3d 2h"), x-ui style: the admin sees at
// a glance how old a session is or how recently it was active,
// instead of parsing a full timestamp. A zero time renders "—".
func agoString(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	if d < time.Second {
		return "just now"
	}
	return formatDuration(d)
}

// formatBytes renders a byte count with a unit ("845 B", "12.3 KB",
// "1.2 MB", "3.4 GB") so the admin reads magnitudes at a glance
// instead of counting digits in a raw counter.
func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for n >= div*unit && exp < 3 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

// formatRate renders bytes-per-second with a unit ("845 B/s",
// "12.3 KB/s", "1.2 MB/s"). A negative or NaN rate renders "—".
func formatRate(bps float64) string {
	if bps < 0 || bps != bps {
		return "—"
	}
	if bps < 1024 {
		return fmt.Sprintf("%.0f B/s", bps)
	}
	return formatBytes(uint64(bps)) + "/s"
}

// metricValue looks one counter up by name in a /healthz/details
// monitoring list. The panel never assumes a metric exists: a
// missing metric is reported unavailable, not zero.
func metricValue(details *HealthDetails, name string) (uint64, bool) {
	if details == nil {
		return 0, false
	}
	for _, m := range details.Monitoring {
		if m.Name == name {
			return m.Value, true
		}
	}
	return 0, false
}

// ThroughputView is the live throughput of the generic-UDP relay:
// the payload bytes the server relays to/from UDP endpoints
// (QUIC, calls, games, UDP forwarded through a forward port),
// derived from the metrics endpoint's cumulative generic-UDP byte
// counters between two page loads. It is NOT total tunnel
// throughput: the server exposes no byte counter for TCP stream
// traffic (the usual VLESS traffic), so that traffic is not
// included. OK is false on the first load (nothing to compare
// with yet), when the counters are unavailable, or when the
// counters reset (server restart) — the page then shows "—"
// and says to refresh, instead of showing a fabricated rate.
// Per-connection live throughput is NOT available: the control
// socket reports session membership only, and the metrics endpoint
// reports these aggregate counters only.
type ThroughputView struct {
	OK       bool    `json:"ok"`
	UpBps    float64 `json:"up_bps"`
	DownBps  float64 `json:"down_bps"`
	UpRate   string  `json:"up_rate"`
	DownRate string  `json:"down_rate"`
}

// throughputSample is one snapshot of the server's cumulative
// generic-UDP byte counters (from /healthz/details).
type throughputSample struct {
	at   time.Time
	up   uint64
	down uint64
}

// throughputRate derives a live bytes-per-second rate from two
// samples. ok is false on a non-positive interval or a counter
// reset (counters went backwards after a server restart) — the
// caller renders "—" and re-baselines instead of dividing by a
// bogus interval.
func throughputRate(prev, cur throughputSample) (upBps, downBps float64, ok bool) {
	dt := cur.at.Sub(prev.at).Seconds()
	if dt <= 0 {
		return 0, 0, false
	}
	if cur.up < prev.up || cur.down < prev.down {
		return 0, 0, false
	}
	return float64(cur.up-prev.up) / dt, float64(cur.down-prev.down) / dt, true
}

// sampleThroughput records the current counters and returns the
// live UDP-relay rate since the previous sample. The first call
// (no previous sample) returns OK=false and only baselines: a rate
// needs two page loads to exist.
func (s *Server) sampleThroughput(details *HealthDetails) ThroughputView {
	view := ThroughputView{}
	if details == nil {
		return view
	}
	up, okUp := metricValue(details, "generic_udp_upstream_bytes_total")
	down, okDown := metricValue(details, "generic_udp_downstream_bytes_total")
	if !okUp || !okDown {
		return view
	}
	cur := throughputSample{at: time.Now(), up: up, down: down}
	s.throughputMu.Lock()
	defer s.throughputMu.Unlock()
	if s.lastThroughput != nil {
		if upBps, downBps, ok := throughputRate(*s.lastThroughput, cur); ok {
			view = ThroughputView{
				OK: true, UpBps: upBps, DownBps: downBps,
				UpRate: formatRate(upBps), DownRate: formatRate(downBps),
			}
		}
	}
	cp := cur
	s.lastThroughput = &cp
	return view
}

// counterView is one cumulative server counter with an
// availability flag, so a missing metric renders as unavailable,
// not zero. Text is the human-formatted value ("1.2 MB" for
// bytes, plain digits for counts).
type counterView struct {
	Value uint64 `json:"value"`
	OK    bool   `json:"ok"`
	Text  string `json:"text"`
}

// bytesCounter looks a byte counter up by name and formats it.
func bytesCounter(details *HealthDetails, name string) counterView {
	v, ok := metricValue(details, name)
	if !ok {
		return counterView{}
	}
	return counterView{Value: v, OK: true, Text: formatBytes(v)}
}

// countCounter looks a plain counter up by name.
func countCounter(details *HealthDetails, name string) counterView {
	v, ok := metricValue(details, name)
	if !ok {
		return counterView{}
	}
	return counterView{Value: v, OK: true, Text: fmt.Sprintf("%d", v)}
}

// connectionsContent is the Connections page: live connection
// information for the admin — tunnel sessions with ages, nodes
// with loss and bound forward ports, UDP-relay throughput and
// cumulative counters. It is built only from data the panel
// already loads (health/metrics, control-socket sessions, mesh
// heartbeats) — nothing is invented, and what the backend cannot
// provide (per-connection live throughput, TCP stream bytes, the
// nodes' configured port ranges) is said plainly on the page.
type connectionsContent struct {
	Health     ServerHealth
	Throughput ThroughputView
	Sessions   []SessionView
	// TotalStreams is the sum of ActiveStreams over the live sessions.
	TotalStreams int
	// Uptime is the server uptime, human-formatted ("2d 3h"); empty
	// when the metrics endpoint did not report it.
	Uptime       string
	SessionsNote string
	Mesh         MeshView
	Control      ControlSocketState
	// Cumulative counters since the server started (from the
	// metrics list); each carries its own availability flag.
	UpBytes          counterView
	DownBytes        counterView
	UpDatagrams      counterView
	DownDatagrams    counterView
	DroppedPackets   counterView
	UpstreamQueries  counterView
	UpstreamFailures counterView
	Associations     counterView
	Endpoints        counterView
}

// loadConnections gathers every Connections section from the
// shared service functions. It never fails: every unobservable
// section degrades to an explicit unavailable state in its own
// field.
func (s *Server) loadConnections(ctx context.Context) connectionsContent {
	health := FetchServerHealth(ctx, s.cfg.MetricsAddr, s.httpClient)
	throughput := s.sampleThroughput(health.Details)
	sessions, ctrl := s.liveSessions(ctx)
	meshView := s.liveMesh(ctx)
	content := connectionsContent{
		Health: health, Throughput: throughput, Sessions: sessions,
		Control: ctrl, Mesh: meshView,
		UpBytes:          bytesCounter(health.Details, "generic_udp_upstream_bytes_total"),
		DownBytes:        bytesCounter(health.Details, "generic_udp_downstream_bytes_total"),
		UpDatagrams:      countCounter(health.Details, "generic_udp_upstream_datagrams_total"),
		DownDatagrams:    countCounter(health.Details, "generic_udp_downstream_datagrams_total"),
		DroppedPackets:   countCounter(health.Details, "dropped_packets_total"),
		UpstreamQueries:  countCounter(health.Details, "dns_upstream_queries_total"),
		UpstreamFailures: countCounter(health.Details, "dns_upstream_failures_total"),
		Associations:     countCounter(health.Details, "generic_udp_associations_active"),
		Endpoints:        countCounter(health.Details, "generic_udp_endpoints_active"),
	}
	for _, sess := range sessions {
		content.TotalStreams += sess.ActiveStreams
	}
	if health.Details != nil && health.Details.UptimeSeconds > 0 {
		content.Uptime = formatDuration(time.Duration(health.Details.UptimeSeconds) * time.Second)
	}
	if !ctrl.Configured {
		content.SessionsNote = controlSocketNotConfiguredNote
	} else if !ctrl.Available {
		content.SessionsNote = ctrl.Error
	}
	return content
}
