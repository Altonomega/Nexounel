package panel

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/mesh"
)

// TestDashboardRendersTheme guards the panel redesign: the dark theme CSS
// must actually reach the browser (no ZgotmplZ sanitisation), the health
// wording must stay honest about the metrics endpoint, the status badges
// must render, and every dashboard section must still be present.
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
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x/status", nil)
	s.render(w, req, "status", PageData{Title: "Dashboard", WebPath: "/x", Authenticated: true, Username: "admin", CSRFToken: "t", Content: content})
	body := w.Body.String()
	for _, want := range []string{
		"Metrics/health endpoint unreachable",
		"badge-down",
		"badge-up",
		"#0b0f14",
		"@keyframes pulse",
		"Live sessions",
		"Mesh",
		"Compression",
		"Resolver fleet",
		"node-1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	for _, not := range []string{"ZgotmplZ", "Server: <strong>down</strong>"} {
		if strings.Contains(body, not) {
			t.Errorf("dashboard must not contain %q", not)
		}
	}
	w2 := httptest.NewRecorder()
	s.render(w2, req, "login", PageData{Title: "Log in", WebPath: "/x", CSRFToken: "t"})
	if !strings.Contains(w2.Body.String(), "#0b0f14") {
		t.Errorf("login page missing new CSS")
	}
}
