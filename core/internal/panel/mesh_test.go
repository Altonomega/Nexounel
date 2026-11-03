package panel

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/control"
	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
	"github.com/MNSH-Nexo/Nexounel/core/internal/mesh"
)

func meshSnapshotFixture() *control.MeshSnapshot {
	now := time.Now()
	return &control.MeshSnapshot{
		Table: mesh.Table{
			Term:    mesh.Term{Number: 2},
			Version: 5,
			ChiefID: "node-1",
			Members: []mesh.Member{
				{ID: "node-1", State: mesh.StateActive, CapacityBps: 1000, Loss: 0.01, LegRTTMs: 12, LegOK: true, TenureSeq: 1},
				{ID: "node-2", State: mesh.StateSuspect, CapacityBps: 500, Loss: 0.2, LegRTTMs: 0, LegOK: false, TenureSeq: 2},
			},
			Weights: map[string]float64{"node-1": 0.6, "node-2": 0.4},
		},
		Heartbeats: []control.MeshHeartbeatSummary{
			{NodeID: "node-1", State: mesh.StateActive, LastSeen: now.Add(-5 * time.Second), CapacityBps: 1100, Loss: 0.01, LegRTTMs: 12, LegOK: true, ActiveStreams: 3, ForwardPortsBound: 10, ConfigVersion: 7, StreamConnected: true, LastAckFor: "config"},
			{NodeID: "node-2", State: mesh.StateSuspect, LastSeen: now.Add(-70 * time.Second), CapacityBps: 500, Loss: 0.2, LegOK: false, ActiveStreams: 0, ForwardPortsBound: 0, ConfigVersion: 6, StreamConnected: false, LastAckFor: "rotation", LastAckError: "key file unwritable"},
			{NodeID: "node-3", State: mesh.StatePending, LastSeen: now.Add(-2 * time.Second), CapacityBps: 800, Loss: 0, LegOK: true, ActiveStreams: 1, ForwardPortsBound: 10, ConfigVersion: 7, StreamConnected: true},
		},
		SnapshotSigning: false,
		GeneratedAt:     now,
	}
}

func TestLiveMeshViaFakeSocket(t *testing.T) {
	env := newTestEnv(t)
	stub := &stubControlHandler{registry: env.registry, mesh: meshSnapshotFixture()}
	startFakeControlSocket(t, env, stub)

	view := env.server.liveMesh(context.Background())
	if !view.Available || view.Term != "T2" || view.TermNumber != 2 || view.Version != 5 || view.ChiefID != "node-1" {
		t.Fatalf("mesh view: %+v", view)
	}
	if view.SnapshotSigning {
		t.Fatal("fixture is unsigned; view claims signing")
	}
	if len(view.Members) != 3 {
		t.Fatalf("members: %+v", view.Members)
	}
	// Sorted by ID; the heartbeat-only member is PENDING, zero weight.
	if view.Members[0].ID != "node-1" || view.Members[1].ID != "node-2" || view.Members[2].ID != "node-3" {
		t.Fatalf("member order/ids: %+v", view.Members)
	}
	m1 := view.Members[0]
	if m1.Weight != 0.6 || m1.CapacityBps != 1100 || !m1.StreamConnected || m1.LastAckFor != "config" || m1.ConfigVersion != 7 {
		t.Fatalf("node-1 member: %+v", m1)
	}
	m2 := view.Members[1]
	if m2.State != mesh.StateSuspect || m2.LastAckError != "key file unwritable" || m2.StreamConnected {
		t.Fatalf("node-2 member: %+v", m2)
	}
	m3 := view.Members[2]
	if m3.State != mesh.StatePending || m3.Weight != 0 || m3.TenureSeq != 0 {
		t.Fatalf("node-3 member: %+v", m3)
	}
	if m1.LastSeenAgoSeconds < 0 || m1.LastSeenAgoSeconds > 30 {
		t.Fatalf("node-1 heartbeat age %ds", m1.LastSeenAgoSeconds)
	}
}

func TestLiveMeshSocketAbsentDegradesHonestly(t *testing.T) {
	env := newTestEnv(t)
	empty := ""
	env.server.controlSocketPathOverride = &empty

	view := env.server.liveMesh(context.Background())
	if view.Available || view.Note != controlSocketNotConfiguredNote || len(view.Members) != 0 {
		t.Fatalf("absent-socket mesh view: %+v", view)
	}
	content := env.server.loadDashboard(context.Background())
	if content.Mesh.Available || content.Mesh.Note != controlSocketNotConfiguredNote {
		t.Fatalf("dashboard mesh with absent socket: %+v", content.Mesh)
	}
	if content.PendingJoins == nil {
		t.Fatal("pending joins must serialise as [], not null")
	}
}

func TestDashboardRendersMeshAndJoinTokens(t *testing.T) {
	env := newTestEnv(t)
	stub := &stubControlHandler{registry: env.registry, mesh: meshSnapshotFixture()}
	startFakeControlSocket(t, env, stub)
	cookie := env.authed(t)

	rec := env.do(http.MethodGet, env.cfg.WebPath+"/status", nil, cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard: %d", rec.Code)
	}
	for _, want := range []string{
		"Mesh", "T2", "node-1", "node-2", "node-3", "SUSPECT",
		"Join tokens", "Issue join token", "Snapshot signing",
		"0.600", "1100",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard missing %q", want)
		}
	}

	// Socket absent: the mesh note renders, the page still loads.
	env2 := newTestEnv(t)
	empty := ""
	env2.server.controlSocketPathOverride = &empty
	cookie2 := env2.authed(t)
	rec = env2.do(http.MethodGet, env2.cfg.WebPath+"/status", nil, cookie2)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), controlSocketNotConfiguredNote) {
		t.Fatalf("dashboard socket absent: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Join tokens") {
		t.Fatal("join-token card missing when the socket is absent")
	}
}

func TestAPIMeshGet(t *testing.T) {
	env := newTestEnv(t)
	stub := &stubControlHandler{registry: env.registry, mesh: meshSnapshotFixture()}
	startFakeControlSocket(t, env, stub)
	cookie, csrf := env.loginCookie(t)

	rec := env.doJSON(http.MethodGet, env.cfg.WebPath+"/api/mesh", "", cookie, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("API mesh: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Mesh struct {
			Available bool   `json:"available"`
			Term      string `json:"term"`
			ChiefID   string `json:"chief_id"`
			Members   []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"members"`
		} `json:"mesh"`
		PendingJoins []any `json:"pending_joins"`
	}
	decodeJSON(t, rec, &body)
	if !body.Mesh.Available || body.Mesh.Term != "T2" || body.Mesh.ChiefID != "node-1" || len(body.Mesh.Members) != 3 {
		t.Fatalf("API mesh body: %+v", body)
	}
	if body.PendingJoins == nil {
		t.Fatal("pending_joins must serialise as [], not null")
	}
	_ = csrf

	// /api/status carries the same mesh view.
	rec = env.doJSON(http.MethodGet, env.cfg.WebPath+"/api/status", "", cookie, "")
	var status struct {
		Mesh struct {
			Term    string `json:"term"`
			ChiefID string `json:"chief_id"`
		} `json:"mesh"`
		PendingJoins []any `json:"pending_joins"`
	}
	decodeJSON(t, rec, &status)
	if status.Mesh.Term != "T2" || status.Mesh.ChiefID != "node-1" || status.PendingJoins == nil {
		t.Fatalf("API status mesh: %+v", status)
	}
}

func TestAPIMeshAuthAndCSRF(t *testing.T) {
	env := newTestEnv(t)
	rec := env.doJSON(http.MethodGet, env.cfg.WebPath+"/api/mesh", "", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API mesh: %d, want 401", rec.Code)
	}
	cookie, _ := env.loginCookie(t)
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/mesh", `{"action":"revoke","node_id":"node-2","confirm":true}`, cookie, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("API mesh POST without CSRF: %d, want 403", rec.Code)
	}
}

func TestAPIMeshIssueRevokeFlow(t *testing.T) {
	env := newTestEnv(t)
	stub := &stubControlHandler{registry: env.registry}
	startFakeControlSocket(t, env, stub)
	cookie, csrf := env.loginCookie(t)

	issueBody := `{"action":"issue","node_id":"node-2","connect_address":"v.example.invalid","listen_port":18000,"forward_range":"20000-20010","ttl_hours":24}`
	rec := env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/mesh", issueBody, cookie, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body.String())
	}
	var issued struct {
		TokenShownOnce   string `json:"token_shown_once"`
		TokenFingerprint string `json:"token_fingerprint"`
		NodeID           string `json:"node_id"`
		ExpiresAt        string `json:"expires_at"`
	}
	decodeJSON(t, rec, &issued)
	if len(issued.TokenShownOnce) != 43 || issued.NodeID != "node-2" || issued.TokenFingerprint != enroll.DisplayFingerprint(issued.TokenShownOnce) {
		t.Fatalf("issued: %+v", issued)
	}
	if !stub.hasBootstrapKey(enroll.TokenFingerprint(issued.TokenShownOnce)) {
		t.Fatal("bootstrap key not pushed")
	}

	// Listed once, fingerprints only.
	rec = env.doJSON(http.MethodGet, env.cfg.WebPath+"/api/mesh", "", cookie, "")
	var listed struct {
		PendingJoins []PendingJoinView `json:"pending_joins"`
	}
	decodeJSON(t, rec, &listed)
	if len(listed.PendingJoins) != 1 || listed.PendingJoins[0].NodeID != "node-2" {
		t.Fatalf("pending joins: %+v", listed)
	}
	// A fresh listing's raw body must not contain the token value.
	rec = env.doJSON(http.MethodGet, env.cfg.WebPath+"/api/mesh", "", cookie, "")
	if strings.Contains(rec.Body.String(), issued.TokenShownOnce) {
		t.Fatal("token leaked into a later listing")
	}

	// Revoke requires confirmation; then it removes the key.
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/mesh", `{"action":"revoke","node_id":"node-2"}`, cookie, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("revoke without confirm: %d, want 400", rec.Code)
	}
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/mesh", `{"action":"revoke","node_id":"node-2","confirm":true}`, cookie, csrf)
	var revoked struct {
		Revoked bool `json:"revoked"`
	}
	decodeJSON(t, rec, &revoked)
	if rec.Code != http.StatusOK || !revoked.Revoked {
		t.Fatalf("revoke: %d %+v %s", rec.Code, revoked, rec.Body.String())
	}
	if stub.hasBootstrapKey(enroll.TokenFingerprint(issued.TokenShownOnce)) {
		t.Fatal("bootstrap key not removed on revoke")
	}
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/mesh", `{"action":"revoke","node_id":"node-2","confirm":true}`, cookie, csrf)
	decodeJSON(t, rec, &revoked)
	if revoked.Revoked {
		t.Fatal("second revoke reported a removal")
	}

	// Validation failures are 400 and issue nothing.
	for _, bad := range []string{
		`{"action":"issue","node_id":"bad id!","connect_address":"v.example.invalid","forward_range":"20000-20010"}`,
		`{"action":"issue","node_id":"node-2","connect_address":"localhost","forward_range":"20000-20010"}`,
		`{"action":"issue","node_id":"node-2","connect_address":"v.example.invalid","forward_range":"bogus"}`,
		`{"action":"explode"}`,
		`{"action":"issue","node_id":"node-2","connect_address":"v.example.invalid","forward_range":"20000-20010","surprise":1}`,
	} {
		rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/mesh", bad, cookie, csrf)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("bad mesh request %s: %d, want 400", bad, rec.Code)
		}
	}
	if len(env.server.joinStore().List()) != 0 {
		t.Fatal("failed issues left pending joins behind")
	}
}

func TestAPIMeshIssueSocketAbsentIs422(t *testing.T) {
	env := newTestEnv(t)
	empty := ""
	env.server.controlSocketPathOverride = &empty
	cookie, csrf := env.loginCookie(t)

	rec := env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/mesh",
		`{"action":"issue","node_id":"node-2","connect_address":"v.example.invalid","forward_range":"20000-20010"}`, cookie, csrf)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("issue with absent socket: %d, want 422: %s", rec.Code, rec.Body.String())
	}
	if len(env.server.joinStore().List()) != 0 {
		t.Fatal("failed issuance left a pending join behind")
	}
}

var shownTokenPattern = regexp.MustCompile(`id="showntoken"[^>]*value="([^"]+)"`)

func TestMeshIssueUIShowsTokenOnce(t *testing.T) {
	env := newTestEnv(t)
	stub := &stubControlHandler{registry: env.registry}
	startFakeControlSocket(t, env, stub)
	cookie := env.authed(t)
	csrf := env.csrfFor(t, cookie, env.cfg.WebPath+"/status")

	form := url.Values{
		"node_id": {"node-2"}, "connect_address": {"v.example.invalid"},
		"listen_port": {"18000"}, "forward_range": {"20000-20010"},
		"ttl_hours": {"24"}, "csrf_token": {csrf},
	}
	rec := env.do(http.MethodPost, env.cfg.WebPath+"/mesh/issue", form, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("UI issue: %d\n%s", rec.Code, rec.Body.String())
	}
	m := shownTokenPattern.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("issued token not rendered:\n%s", rec.Body.String())
	}
	token := m[1]
	if len(token) != 43 {
		t.Fatalf("rendered token length %d", len(token))
	}
	if !strings.Contains(rec.Body.String(), "Join token issued for node node-2") {
		t.Fatal("issue confirmation message missing")
	}
	// A fresh dashboard load must not show the token again.
	rec = env.do(http.MethodGet, env.cfg.WebPath+"/status", nil, cookie)
	if strings.Contains(rec.Body.String(), token) {
		t.Fatal("token shown on a second render")
	}
	if !stub.hasBootstrapKey(enroll.TokenFingerprint(token)) {
		t.Fatal("bootstrap key not pushed by the UI flow")
	}

	// UI issue without CSRF is rejected.
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/mesh/issue", url.Values{
		"node_id": {"node-3"}, "connect_address": {"v.example.invalid"}, "forward_range": {"20000-20010"},
	}, cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("UI issue without CSRF: %d, want 403", rec.Code)
	}
}

func TestMeshRevokeUI(t *testing.T) {
	env := newTestEnv(t)
	stub := &stubControlHandler{registry: env.registry}
	startFakeControlSocket(t, env, stub)
	token, _, err := env.server.issueJoinToken(context.Background(), issueTestParams("node-2"))
	if err != nil {
		t.Fatal(err)
	}
	fp := enroll.TokenFingerprint(token)
	cookie := env.authed(t)
	csrf := env.csrfFor(t, cookie, env.cfg.WebPath+"/status")

	rec := env.do(http.MethodPost, env.cfg.WebPath+"/mesh/revoke", url.Values{
		"node_id": {"node-2"}, "confirm": {"yes"}, "csrf_token": {csrf},
	}, cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "was revoked") {
		t.Fatalf("UI revoke: %d\n%s", rec.Code, rec.Body.String())
	}
	if stub.hasBootstrapKey(fp) {
		t.Fatal("bootstrap key not removed by UI revoke")
	}
}
