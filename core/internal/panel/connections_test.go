package panel

import (
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/control"
	"github.com/Altonomega/Nexounel/core/internal/mesh"
)

// TestThroughputRate guards the live-rate derivation: a rate is
// bytes over elapsed seconds, and it must refuse a non-positive
// interval or a counter reset (server restart) instead of
// dividing by a bogus interval.
func TestThroughputRate(t *testing.T) {
	base := time.Now()
	prev := throughputSample{at: base, up: 1000, down: 2000}
	cur := throughputSample{at: base.Add(10 * time.Second), up: 11000, down: 22000}
	up, down, ok := throughputRate(prev, cur)
	if !ok {
		t.Fatal("throughputRate refused a valid pair of samples")
	}
	if up != 1000 || down != 2000 {
		t.Errorf("rate = %.0f/%.0f B/s, want 1000/2000", up, down)
	}
	// Equal counters: zero rate, still OK.
	if _, _, ok := throughputRate(prev, throughputSample{at: base.Add(10 * time.Second), up: 1000, down: 2000}); !ok {
		t.Error("throughputRate refused equal counters (zero rate is valid)")
	}
	// Zero interval: refuse.
	if _, _, ok := throughputRate(prev, throughputSample{at: base, up: 2000, down: 3000}); ok {
		t.Error("throughputRate accepted a zero interval")
	}
	// Counter reset (server restart): refuse and let the caller re-baseline.
	if _, _, ok := throughputRate(prev, throughputSample{at: base.Add(10 * time.Second), up: 500, down: 3000}); ok {
		t.Error("throughputRate accepted a reset upstream counter")
	}
	if _, _, ok := throughputRate(prev, throughputSample{at: base.Add(10 * time.Second), up: 2000, down: 1000}); ok {
		t.Error("throughputRate accepted a reset downstream counter")
	}
}

// TestSampleThroughput guards the sampler state: the first call
// only baselines (OK=false — a rate needs two page loads), the
// second call with higher counters reports a rate, and a counter
// reset re-baselines instead of reporting a bogus rate.
func TestSampleThroughput(t *testing.T) {
	s := &Server{}
	details := func(up, down uint64) *HealthDetails {
		return &HealthDetails{Monitoring: []Metric{
			{Name: "generic_udp_upstream_bytes_total", Value: up},
			{Name: "generic_udp_downstream_bytes_total", Value: down},
		}}
	}
	if got := s.sampleThroughput(nil); got.OK {
		t.Error("sampleThroughput(nil details) reported OK")
	}
	if got := s.sampleThroughput(details(1000, 2000)); got.OK {
		t.Error("first sampleThroughput call reported OK (nothing to compare with)")
	}
	got := s.sampleThroughput(details(2000, 4000))
	if !got.OK {
		t.Fatal("second sampleThroughput call did not report OK")
	}
	if got.UpRate == "" || got.DownRate == "" {
		t.Errorf("second sample rates = %q/%q, want formatted rates", got.UpRate, got.DownRate)
	}
	if got := s.sampleThroughput(details(500, 4000)); got.OK {
		t.Error("sampleThroughput reported OK across a counter reset")
	}
}

// TestAgoString guards the relative-age rendering used for session
// ages and last-activity times.
func TestAgoString(t *testing.T) {
	if got := agoString(time.Time{}); got != "—" {
		t.Errorf("agoString(zero) = %q, want —", got)
	}
	now := time.Now()
	cases := []struct {
		at   time.Time
		want string
	}{
		{now.Add(-500 * time.Millisecond), "just now"},
		{now.Add(-12 * time.Second), "12s"},
		{now.Add(-3*time.Minute - 4*time.Second), "3m 4s"},
		{now.Add(-2*time.Hour - 5*time.Minute), "2h 5m"},
		{now.Add(-3*24*time.Hour - 2*time.Hour), "3d 2h"},
	}
	for _, tc := range cases {
		if got := agoString(tc.at); got != tc.want {
			t.Errorf("agoString(%v) = %q, want %q", tc.at, got, tc.want)
		}
	}
}

// TestFormatBytesAndRate guards the human-formatted numbers the
// panel shows for counters and live rates.
func TestFormatBytesAndRate(t *testing.T) {
	for _, tc := range []struct {
		n    uint64
		want string
	}{
		{0, "0 B"}, {845, "845 B"}, {1023, "1023 B"},
		{1024, "1.0 KB"}, {12345, "12.1 KB"},
		{1234567, "1.2 MB"}, {1234567890, "1.1 GB"},
	} {
		if got := formatBytes(tc.n); got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
	for _, tc := range []struct {
		bps  float64
		want string
	}{
		{0, "0 B/s"}, {845, "845 B/s"}, {12345, "12.1 KB/s"},
		{-1, "—"}, {math.NaN(), "—"},
	} {
		if got := formatRate(tc.bps); got != tc.want {
			t.Errorf("formatRate(%v) = %q, want %q", tc.bps, got, tc.want)
		}
	}
}

// TestSessionViewsAges guards that session views carry relative
// ages computed at view time.
func TestSessionViewsAges(t *testing.T) {
	now := time.Now()
	views := sessionViews([]control.SessionSummary{
		{SessionID: 7, NodeID: "node-1", UploadMTU: 103, DownloadMTU: 879,
			CreatedAt: now.Add(-65 * time.Second), LastActivity: now.Add(-5 * time.Second),
			ActiveStreams: 2},
	})
	if len(views) != 1 {
		t.Fatalf("views = %d, want 1", len(views))
	}
	if views[0].Age != "1m 5s" {
		t.Errorf("Age = %q, want 1m 5s", views[0].Age)
	}
	if views[0].LastActivityAgo != "5s" {
		t.Errorf("LastActivityAgo = %q, want 5s", views[0].LastActivityAgo)
	}
}

// TestMeshViewsDerivedFields guards the display derivations
// computed once in meshViews: loss as a percent and capacity as a
// formatted rate, so every template shows the same numbers.
func TestMeshViewsDerivedFields(t *testing.T) {
	snap := control.MeshSnapshot{
		Table: mesh.Table{
			Term:    mesh.Term{Number: 1},
			Version: 7,
			ChiefID: "node-1",
			Members: []mesh.Member{{ID: "node-1", State: mesh.StateActive}},
			Weights: map[string]float64{"node-1": 1},
		},
		Heartbeats: []control.MeshHeartbeatSummary{
			{NodeID: "node-1", State: mesh.StateActive, CapacityBps: 1100, Loss: 0.01, LegOK: true, LastSeen: time.Now()},
		},
	}
	view := meshViews(snap, ControlSocketState{Configured: true, Reachable: true, Available: true})
	if len(view.Members) != 1 {
		t.Fatalf("members = %d, want 1", len(view.Members))
	}
	m := view.Members[0]
	if m.LossPercent != 1 {
		t.Errorf("LossPercent = %v, want 1", m.LossPercent)
	}
	if m.CapacityRate != "1.1 KB/s" {
		t.Errorf("CapacityRate = %q, want 1.1 KB/s", m.CapacityRate)
	}
}

func connectionsTestContent() connectionsContent {
	now := time.Now()
	return connectionsContent{
		Health: ServerHealth{Up: true, Details: &HealthDetails{
			UptimeSeconds: 7320,
			Monitoring: []Metric{
				{Name: "generic_udp_upstream_bytes_total", Value: 1234567890},
				{Name: "generic_udp_downstream_bytes_total", Value: 3456789012},
			},
		}},
		Throughput:   ThroughputView{OK: true, UpBps: 12345, DownBps: 1234567, UpRate: "12.1 KB/s", DownRate: "1.2 MB/s"},
		Sessions:     []SessionView{{SessionID: 266, NodeID: "node-1", UploadMTU: 103, DownloadMTU: 879, ActiveStreams: 2, Age: "12m 3s", LastActivityAgo: "4s ago", CreatedAt: now.Add(-12 * time.Minute), LastActivity: now.Add(-4 * time.Second)}},
		TotalStreams: 2,
		Uptime:       "2h 2m",
		Mesh: MeshView{
			Available: true, ChiefID: "node-1",
			Members: []MeshMemberView{
				{ID: "node-1", State: mesh.StateActive, CapacityBps: 992345, CapacityRate: "969.1 KB/s", Loss: 0.01, LossPercent: 1, LegOK: true, ActiveStreams: 2, ForwardPortsBound: 10, StreamConnected: true, LastSeen: now, LastSeenAgoSeconds: 5, ResolverUsable: 862, ResolverRejected: 1},
			},
		},
		UpBytes:          counterView{Value: 1234567890, OK: true, Text: "1.1 GB"},
		DownBytes:        counterView{Value: 3456789012, OK: true, Text: "3.2 GB"},
		UpDatagrams:      counterView{Value: 12400, OK: true, Text: "12400"},
		DownDatagrams:    counterView{Value: 45600, OK: true, Text: "45600"},
		DroppedPackets:   counterView{Value: 12, OK: true, Text: "12"},
		UpstreamQueries:  counterView{Value: 987654, OK: true, Text: "987654"},
		UpstreamFailures: counterView{Value: 3, OK: true, Text: "3"},
		Associations:     counterView{Value: 4, OK: true, Text: "4"},
		Endpoints:        counterView{Value: 9, OK: true, Text: "9"},
	}
}

// TestConnectionsPageRenders guards the Connections page: live
// sessions with ages, nodes with loss/capacity/forward ports,
// server-wide throughput, cumulative totals, and the honest note
// that per-connection live throughput is not exposed — with no
// inline <style> or <script> (the CSP blocks both).
func TestConnectionsPageRenders(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x/connections", nil)
	s.render(w, req, "connections", PageData{Title: "Connections", WebPath: "/x", Authenticated: true, Username: "admin", CSRFToken: "t", Content: connectionsTestContent()})
	body := w.Body.String()
	for _, want := range []string{
		"Connections",
		"Live throughput",
		"12.1 KB/s", "1.2 MB/s",
		"server-wide",
		"Active sessions", "2 active streams", "server up 2h 2m",
		"UDP associations", "9 endpoints",
		// The honest limitation note.
		"Per-connection live throughput",
		"not exposed by the server",
		"control socket reports session membership only",
		// Sessions table with ages.
		"Live sessions", "#266", "node-1", "103 B", "879 B",
		"Age", "12m 3s", "4s ago",
		// Nodes table with loss/capacity/forward ports.
		"Nodes", "node-1 (chief)", "1.0%", "969.1 KB/s",
		"862", "Forward ports bound",
		// Forward ports card.
		"Forward ports", "FORWARD_RANGE",
		// Cumulative totals.
		"Totals since server start",
		"Data sent (upstream)", "1.1 GB",
		"Data received (downstream)", "3.2 GB",
		"Datagrams sent", "12400",
		"Dropped packets", "DNS upstream queries",
		// Sidebar link to the page.
		`href="/x/connections"`,
		`<link rel="stylesheet" href="/x/panel.css">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("connections page missing %q", want)
		}
	}
	for _, not := range []string{"ZgotmplZ", "<style>", "<script>"} {
		if strings.Contains(body, not) {
			t.Errorf("connections page must not contain %q", not)
		}
	}
}

// TestConnectionsPageDegraded guards the unavailable states: a
// down server and an unreachable control socket render explicit
// notes, never empty tables or zeroes.
func TestConnectionsPageDegraded(t *testing.T) {
	s := &Server{}
	content := connectionsContent{
		Health:       ServerHealth{Up: false, Error: "connection refused"},
		SessionsNote: controlSocketNotConfiguredNote,
		Mesh:         MeshView{Note: "control socket unreachable"},
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x/connections", nil)
	s.render(w, req, "connections", PageData{Title: "Connections", WebPath: "/x", Authenticated: true, Username: "admin", CSRFToken: "t", Content: content})
	body := w.Body.String()
	for _, want := range []string{
		"Connections",
		"refresh the page to measure",
		"No live sessions reported by the control socket.",
		"Node status unavailable: control socket unreachable",
		"Forward-port use is unavailable: control socket unreachable",
		"Server totals unavailable",
		controlSocketNotConfiguredNote,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("degraded connections page missing %q", want)
		}
	}
}

// TestConnectionsRouteEndToEnd guards the route itself: an
// authenticated GET serves the page (200), and the dashboard
// links to it.
func TestConnectionsRouteEndToEnd(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.authed(t)
	rec := env.do(http.MethodGet, env.cfg.WebPath+"/connections", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /connections: status %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Connections", "Live throughput", "Per-connection live throughput", "No live sessions reported"} {
		if !strings.Contains(body, want) {
			t.Errorf("GET /connections missing %q", want)
		}
	}
}

// TestDashboardSessionsTableAges guards the dashboard session
// table improvements: an Age column, relative last-activity ages,
// and the live-throughput tile.
func TestDashboardSessionsTableAges(t *testing.T) {
	s := &Server{}
	now := time.Now()
	content := statusContent{
		Health:     ServerHealth{Up: true, Details: &HealthDetails{UptimeSeconds: 3600}},
		Throughput: ThroughputView{OK: true, UpBps: 12345, DownBps: 1234567, UpRate: "12.1 KB/s", DownRate: "1.2 MB/s"},
		Sessions: []SessionView{
			{SessionID: 266, NodeID: "node-1", UploadMTU: 103, DownloadMTU: 879, ActiveStreams: 2, Age: "12m 3s", LastActivityAgo: "4s ago", CreatedAt: now.Add(-12 * time.Minute), LastActivity: now.Add(-4 * time.Second)},
		},
		Mesh: MeshView{
			Available: true, Term: "T1", Version: 9, ChiefID: "node-1", GeneratedAt: now,
			Members: []MeshMemberView{
				{ID: "node-1", State: mesh.StateActive, CapacityBps: 992345, CapacityRate: "969.1 KB/s", Loss: 0.01, LossPercent: 1, LegOK: true, ActiveStreams: 2, ForwardPortsBound: 10, StreamConnected: true, LastSeen: now, LastSeenAgoSeconds: 5},
			},
		},
	}
	content.Topology = topologyView(content.Health, content.Sessions, content.Mesh)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x/status", nil)
	s.render(w, req, "status", PageData{Title: "Dashboard", WebPath: "/x", Authenticated: true, Username: "admin", CSRFToken: "t", Content: content})
	body := w.Body.String()
	for _, want := range []string{
		"Live throughput", "&uarr; 12.1 KB/s", "&darr; 1.2 MB/s",
		"<th>Age</th>", "12m 3s", "4s ago",
		"969.1 KB/s", "1.0%",
		"All connection details",
		`href="/x/connections"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}

// TestWizardCopy guards the rewritten Cloudflare/setup guidance:
// the three-step overview, the exact records with their purpose,
// the credential scope, and the verification failure guidance
// (propagation first, then what to check).
func TestWizardCopy(t *testing.T) {
	s := &Server{}
	render := func(content wizardContent) string {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/x/wizard", nil)
		s.render(w, req, "wizard", PageData{Title: "Setup wizard", WebPath: "/x", Authenticated: true, Username: "admin", CSRFToken: "t", Content: content})
		return w.Body.String()
	}
	body := render(wizardContent{})
	for _, want := range []string{
		"This wizard does three things",
		"DNS records", "Verification", "Node registration",
		"8.8.8.8 and 1.1.1.1",
		// Manual records: exact records, purpose, DNS-only.
		"ns1.&lt;domain&gt;", "&lt;subdomain&gt;.&lt;domain&gt;",
		"DNS-only", "never proxied",
		"Points the nameserver name at this server",
		"Delegates the tunnel subdomain to this server",
		"never deletes or changes any existing record",
		// Automatic Cloudflare path.
		"Zone:DNS:Edit on this single zone",
		"used only for this run and is never stored",
		"wait a few minutes and press Verify again",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("wizard page missing %q", want)
		}
	}
	// Failed verification: propagation guidance, not just "check the records".
	failed := render(wizardContent{
		Results: []RecordVerification{
			{Record: "A", Name: "ns1.example.invalid", Expected: "203.0.113.10", Resolver: "8.8.8.8", OK: false, Error: "no answer"},
		},
		Passed: false,
	})
	for _, want := range []string{
		"Verification did not pass",
		"Most often this is propagation",
		"grey cloud, not proxied",
		"another record with the same name already exists",
	} {
		if !strings.Contains(failed, want) {
			t.Errorf("failed-verification wizard missing %q", want)
		}
	}
	// Passed verification: the next step is named.
	passed := render(wizardContent{
		Results: []RecordVerification{
			{Record: "A", Name: "ns1.example.invalid", Expected: "203.0.113.10", Resolver: "8.8.8.8", Got: []string{"203.0.113.10"}, OK: true},
		},
		Passed: true,
	})
	if !strings.Contains(passed, "you can register the node") {
		t.Error("passed-verification wizard missing the next-step line")
	}
}
