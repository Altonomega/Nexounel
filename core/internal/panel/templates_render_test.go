package panel

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/control"
	"github.com/Altonomega/Nexounel/core/internal/mesh"
)

// TestDashboardRendersTheme guards the panel redesign: the CSS must reach
// the browser as an external same-origin stylesheet (the CSP is
// `default-src 'self'`, which blocks inline <style> elements — an inline
// block renders as plain unstyled HTML), the health wording must stay
// honest about the metrics endpoint, the status badges must render, and
// every dashboard section must still be present. The x-ui-modelled app
// shell must also render: the sidebar, top bar, stat tiles, and entrance
// animations — so a plain-HTML look is caught. The simplified dashboard
// must also render the health banner, the 3D topology (mother + nodes +
// connection lines), and the Advanced area, with no inline <script>
// (the CSP blocks inline scripts too).
func TestDashboardRendersTheme(t *testing.T) {
	s := &Server{}
	content := statusContent{
		Health: ServerHealth{Up: false, Error: `Get "http://127.0.0.1:9090/healthz": dial tcp 127.0.0.1:9090: connect: connection refused`},
		Sessions: []SessionView{
			{SessionID: 266, NodeID: "node-1", UploadMTU: 103, DownloadMTU: 879, ActiveStreams: 2, LastActivity: time.Now()},
		},
		Mesh: MeshView{
			Available: true, Term: "T1", Version: 521315, ChiefID: "node-1", GeneratedAt: time.Now(),
			Members: []MeshMemberView{
				{ID: "node-1", State: mesh.StateDown, CapacityBps: 992345, LegOK: true, ActiveStreams: 3, ForwardPortsBound: 10, StreamConnected: true, LastSeen: time.Now()},
			},
		},
	}
	content.Topology = topologyView(content.Health, content.Sessions, content.Mesh)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x/status", nil)
	s.render(w, req, "status", PageData{Title: "Dashboard", WebPath: "/x", Authenticated: true, Username: "admin", CSRFToken: "t", Content: content})
	body := w.Body.String()
	for _, want := range []string{
		"Metrics/health endpoint unreachable",
		"badge-down",
		"badge-up",
		"Live sessions",
		"Mesh",
		"Compression",
		"Resolver fleet",
		"node-1",
		// The stylesheet is an external same-origin <link>, not an
		// inline <style> (the CSP blocks inline styles).
		`<link rel="stylesheet" href="/x/panel.css">`,
		// x-ui-modelled app shell (not a plain HTML dump).
		"class=\"sider\"",
		"class=\"topbar\"",
		"class=\"stats\"",
		"stat-value",
		"brand-mark",
		// The Dashboard menu item is the active one on the status page.
		"menu",
		"active",
		// Simplified dashboard: health banner, 3D topology, Advanced.
		"health-banner",
		"Mother server is down",
		"Network topology",
		"topo-scene",
		"topo-mother",
		"topo-node",
		"topo-link",
		"topo-pos-0",
		"topo-legend",
		"Chief",
		"Advanced",
		"Join tokens",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	for _, not := range []string{"ZgotmplZ", "Server: <strong>down</strong>", "<style>", "<script>"} {
		if strings.Contains(body, not) {
			t.Errorf("dashboard must not contain %q", not)
		}
	}
	w2 := httptest.NewRecorder()
	s.render(w2, req, "login", PageData{Title: "Log in", WebPath: "/x", CSRFToken: "t"})
	loginBody := w2.Body.String()
	for _, want := range []string{"login-card", "login-wrap", "brand-mark", `<link rel="stylesheet" href="/x/panel.css">`} {
		if !strings.Contains(loginBody, want) {
			t.Errorf("login page missing %q", want)
		}
	}
	if strings.Contains(loginBody, "<style>") {
		t.Errorf("login page must not contain an inline <style> block (CSP blocks it)")
	}
}

// TestStylesheetHandler guards the external stylesheet route: the CSS
// must be served as a same-origin file (so `default-src 'self'` allows
// it), reachable without a session (the login page needs it before
// authentication), and unreachable outside the secret web path.
func TestStylesheetHandler(t *testing.T) {
	s := &Server{cfg: Config{WebPath: "/x"}}
	// Unauthenticated GET under the web path: 200, text/css, full CSS.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x/panel.css", nil)
	s.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("panel.css status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/css") {
		t.Errorf("panel.css Content-Type = %q, want text/css", ct)
	}
	if csp := w.Header().Get("Content-Security-Policy"); csp != "default-src 'self'" {
		t.Errorf("panel.css CSP = %q, want default-src 'self'", csp)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("panel.css Cache-Control = %q, want no-store", cc)
	}
	css := w.Body.String()
	for _, want := range []string{
		"#0b0f14", "login-card", ".sider", ".topbar", ".stat-value",
		"@keyframes pulse", "@keyframes popIn", "@keyframes menuGlow",
		"@keyframes cardIn", "@keyframes fadeUp",
		// Simplified dashboard + 3D topology (pure CSS, no JS).
		"health-banner", "topo-scene", "topo-stage", "@keyframes topoSway",
		"topo-node", "topo-link", "topo-pos-0", "topo-legend",
		"details.advanced",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("panel.css missing %q", want)
		}
	}
	// Outside the secret web path: 404.
	w404 := httptest.NewRecorder()
	s.ServeHTTP(w404, httptest.NewRequest("GET", "/panel.css", nil))
	if w404.Code != 404 {
		t.Errorf("panel.css outside web path status = %d, want 404", w404.Code)
	}
	// POST is not allowed.
	w405 := httptest.NewRecorder()
	s.ServeHTTP(w405, httptest.NewRequest("POST", "/x/panel.css", nil))
	if w405.Code != 405 {
		t.Errorf("panel.css POST status = %d, want 405", w405.Code)
	}
	// HEAD is allowed (same headers as GET, no body).
	wHead := httptest.NewRecorder()
	s.ServeHTTP(wHead, httptest.NewRequest("HEAD", "/x/panel.css", nil))
	if wHead.Code != 200 {
		t.Errorf("panel.css HEAD status = %d, want 200", wHead.Code)
	}
	if ct := wHead.Header().Get("Content-Type"); !strings.Contains(ct, "text/css") {
		t.Errorf("panel.css HEAD Content-Type = %q, want text/css", ct)
	}
}

// TestMeshViewsCopiesResolverCounts guards the per-node resolver facts
// the 3D topology shows: the panel already fetches ResolverUsable /
// ResolverRejected on every heartbeat via the control socket, and
// meshViews must surface them on the member view (no new endpoint).
func TestMeshViewsCopiesResolverCounts(t *testing.T) {
	snap := control.MeshSnapshot{
		Table: mesh.Table{
			Term:    mesh.Term{Number: 1},
			Version: 7,
			ChiefID: "node-1",
			Members: []mesh.Member{{ID: "node-1", State: mesh.StateActive}},
			Weights: map[string]float64{"node-1": 1},
		},
		Heartbeats: []control.MeshHeartbeatSummary{
			{NodeID: "node-1", State: mesh.StateActive, ResolverUsable: 862, ResolverRejected: 3, LegOK: true, LastSeen: time.Now()},
		},
	}
	view := meshViews(snap, ControlSocketState{Configured: true, Reachable: true, Available: true})
	if len(view.Members) != 1 {
		t.Fatalf("members = %d, want 1", len(view.Members))
	}
	if got := view.Members[0].ResolverUsable; got != 862 {
		t.Errorf("ResolverUsable = %d, want 862", got)
	}
	if got := view.Members[0].ResolverRejected; got != 3 {
		t.Errorf("ResolverRejected = %d, want 3", got)
	}
}

// TestTopologyView guards the 3D topology derivation: status mapping
// (healthy only when ACTIVE + live leg + fresh heartbeat + low loss),
// the chief marker, the fixed scene positions (6 slots, the rest
// listed below the scene), and the plain-language summary.
func TestTopologyView(t *testing.T) {
	healthy := func(id string) MeshMemberView {
		return MeshMemberView{ID: id, State: mesh.StateActive, CapacityBps: 850000, Loss: 0.01, LegOK: true, ActiveStreams: 2, ForwardPortsBound: 10, StreamConnected: true, LastSeen: time.Now(), LastSeenAgoSeconds: 5, ResolverUsable: 862, ResolverRejected: 1}
	}
	health := ServerHealth{Up: true, Details: &HealthDetails{UptimeSeconds: 3600}}
	sessions := []SessionView{{SessionID: 257, NodeID: "node-1", ActiveStreams: 2}}

	// All healthy: one chief node, summary healthy.
	meshView := MeshView{Available: true, Term: "T1", Version: 9, ChiefID: "node-1", GeneratedAt: time.Now(), Members: []MeshMemberView{healthy("node-1")}}
	topo := topologyView(health, sessions, meshView)
	if topo.SummaryClass != "healthy" {
		t.Errorf("SummaryClass = %q, want healthy", topo.SummaryClass)
	}
	if !strings.Contains(topo.SummaryText, "All systems healthy") {
		t.Errorf("SummaryText = %q, want the healthy line", topo.SummaryText)
	}
	if topo.NodesUp != 1 || topo.NodesTotal != 1 {
		t.Errorf("NodesUp/NodesTotal = %d/%d, want 1/1", topo.NodesUp, topo.NodesTotal)
	}
	n := topo.Nodes[0]
	if n.StatusClass != "healthy" || n.StatusLabel != "Healthy" {
		t.Errorf("node status = %q/%q, want healthy/Healthy", n.StatusClass, n.StatusLabel)
	}
	if !n.IsChief {
		t.Error("node-1 should be marked chief")
	}
	if n.PosClass != "topo-pos-0" || n.X != 86 || n.Y != 50 || !n.InScene {
		t.Errorf("node position = %q (%d,%d) inScene=%v, want topo-pos-0 (86,50) true", n.PosClass, n.X, n.Y, n.InScene)
	}
	if n.ResolverUsable != 862 || n.LossPercent != 1 {
		t.Errorf("node facts = resolvers %d loss %.1f%%, want 862 and 1.0%%", n.ResolverUsable, n.LossPercent)
	}
	if topo.MotherSessions != 1 || topo.MotherUptime != 3600 {
		t.Errorf("mother sessions/uptime = %d/%d, want 1/3600", topo.MotherSessions, topo.MotherUptime)
	}

	// Status mapping table.
	cases := []struct {
		name      string
		mutate    func(*MeshMemberView)
		wantClass string
		wantLabel string
	}{
		{"suspect", func(m *MeshMemberView) { m.State = mesh.StateSuspect }, "degraded", "Degraded"},
		{"down", func(m *MeshMemberView) { m.State = mesh.StateDown }, "down", "Down"},
		{"revoked", func(m *MeshMemberView) { m.State = mesh.StateRevoked }, "down", "Down"},
		{"pending", func(m *MeshMemberView) { m.State = mesh.StatePending }, "degraded", "Joining"},
		{"leg down", func(m *MeshMemberView) { m.LegOK = false }, "degraded", "Degraded"},
		{"stale heartbeat", func(m *MeshMemberView) { m.LastSeenAgoSeconds = 300 }, "degraded", "Degraded"},
		{"high loss", func(m *MeshMemberView) { m.Loss = 0.6 }, "degraded", "Degraded"},
		{"no heartbeat", func(m *MeshMemberView) { m.LastSeen = time.Time{} }, "degraded", "Degraded"},
	}
	for _, tc := range cases {
		m := healthy("node-1")
		tc.mutate(&m)
		mv := MeshView{Available: true, ChiefID: "node-1", Members: []MeshMemberView{m}}
		got := topologyView(health, sessions, mv)
		if got.Nodes[0].StatusClass != tc.wantClass || got.Nodes[0].StatusLabel != tc.wantLabel {
			t.Errorf("%s: status = %q/%q, want %q/%q", tc.name, got.Nodes[0].StatusClass, got.Nodes[0].StatusLabel, tc.wantClass, tc.wantLabel)
		}
	}

	// One degraded node -> summary degraded; one down node -> summary down.
	degraded := healthy("node-1")
	degraded.State = mesh.StateSuspect
	if got := topologyView(health, sessions, MeshView{Available: true, Members: []MeshMemberView{degraded}}); got.SummaryClass != "degraded" {
		t.Errorf("degraded summary = %q, want degraded", got.SummaryClass)
	}
	down := healthy("node-1")
	down.State = mesh.StateDown
	if got := topologyView(health, sessions, MeshView{Available: true, Members: []MeshMemberView{down}}); got.SummaryClass != "down" {
		t.Errorf("down summary = %q, want down", got.SummaryClass)
	}

	// Mother down -> summary down regardless of nodes.
	if got := topologyView(ServerHealth{Up: false}, sessions, meshView); got.SummaryClass != "down" || !strings.Contains(got.SummaryText, "Mother server is down") {
		t.Errorf("mother-down summary = %q/%q, want down/Mother server is down", got.SummaryClass, got.SummaryText)
	}

	// No nodes, mesh available -> degraded with the wizard hint.
	if got := topologyView(health, sessions, MeshView{Available: true, Members: []MeshMemberView{}}); got.SummaryClass != "degraded" || !strings.Contains(got.SummaryText, "no nodes") {
		t.Errorf("empty summary = %q/%q, want degraded/no nodes", got.SummaryClass, got.SummaryText)
	}

	// Mesh unavailable -> degraded, note carried.
	if got := topologyView(health, sessions, MeshView{Note: "control socket unreachable"}); got.SummaryClass != "degraded" || got.MeshNote != "control socket unreachable" {
		t.Errorf("mesh-unavailable summary = %q note %q, want degraded/control socket unreachable", got.SummaryClass, got.MeshNote)
	}

	// 7 nodes: the 7th is listed below the scene, not in it.
	var many []MeshMemberView
	for i := 0; i < 7; i++ {
		m := healthy("node-" + string(rune('1'+i)))
		many = append(many, m)
	}
	got := topologyView(health, sessions, MeshView{Available: true, Members: many})
	if got.BeyondScene != 1 {
		t.Errorf("BeyondScene = %d, want 1", got.BeyondScene)
	}
	if got.Nodes[6].InScene || got.Nodes[6].PosClass != "topo-pos-more" {
		t.Errorf("7th node inScene=%v pos=%q, want false/topo-pos-more", got.Nodes[6].InScene, got.Nodes[6].PosClass)
	}
	if got.Nodes[5].PosClass != "topo-pos-5" || !got.Nodes[5].InScene {
		t.Errorf("6th node pos=%q inScene=%v, want topo-pos-5/true", got.Nodes[5].PosClass, got.Nodes[5].InScene)
	}
}

// TestFooterShowsBuildVersion proves the panel footer identifies the
// running binary (short VCS revision), so the operator can tell
// whether they are looking at the new panel or a cached old one.
// The login page carries it too — the login page is what the operator
// sees before authenticating, so it must prove the build as well.
func TestFooterShowsBuildVersion(t *testing.T) {
	v := buildVersion()
	if v == "" {
		t.Fatal("buildVersion() returned empty")
	}
	s := &Server{}
	// Login page (unauthenticated footer).
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x/login", nil)
	s.render(w, req, "login", PageData{Title: "Log in", WebPath: "/x", CSRFToken: "t"})
	body := w.Body.String()
	if !strings.Contains(body, "Build "+v) {
		t.Fatalf("login page lacks the build version %q in its footer", v)
	}
	// Authenticated dashboard footer.
	s2 := &Server{}
	content := statusContent{Health: ServerHealth{Up: true}}
	content.Topology = topologyView(content.Health, content.Sessions, content.Mesh)
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/x/status", nil)
	s2.render(w2, req2, "status", PageData{Title: "Dashboard", WebPath: "/x", Authenticated: true, Username: "admin", CSRFToken: "t", Content: content})
	body2 := w2.Body.String()
	if !strings.Contains(body2, "Build "+v) {
		t.Fatalf("dashboard lacks the build version %q in its footer", v)
	}
}

// TestBuildVersionNonEmpty pins that buildVersion() always returns a
// usable identifier ("dev" when no VCS revision is stamped).
func TestBuildVersionNonEmpty(t *testing.T) {
	if v := buildVersion(); v == "" {
		t.Fatal("buildVersion() returned empty")
	}
}
