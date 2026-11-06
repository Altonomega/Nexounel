package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/config"
	"github.com/Altonomega/Nexounel/core/internal/control"
)

func (e *testEnv) doJSON(method, path, body string, cookie *http.Cookie, csrfHeader string) *httptest.ResponseRecorder {
	var reader strings.Reader
	if body != "" {
		reader = *strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, &reader)
	req.Header.Set("Content-Type", "application/json")
	if csrfHeader != "" {
		req.Header.Set("X-CSRF-Token", csrfHeader)
	}
	req.RemoteAddr = "203.0.113.99:12345"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	e.server.ServeHTTP(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content type %q, want JSON; body %s", ct, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode JSON: %v; body %s", err, rec.Body.String())
	}
}

func TestAPIAuthRequiredJSON(t *testing.T) {
	env := newTestEnv(t)
	for _, path := range []string{"/api/health", "/api/status", "/api/sessions", "/api/compression", "/api/registry"} {
		rec := env.doJSON(http.MethodGet, env.cfg.WebPath+path, "", nil, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s unauthenticated: %d, want 401", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Fatalf("GET %s unauthenticated redirected to %q", path, loc)
		}
		var body map[string]any
		decodeJSON(t, rec, &body)
		if body["error"] == nil {
			t.Fatalf("GET %s unauthenticated body has no error: %v", path, body)
		}
	}
	rec := env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/registry", `{"action":"reload"}`, nil, "bogus")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /api/registry unauthenticated: %d, want 401", rec.Code)
	}
}

func TestAPIUnknownPathsJSON404(t *testing.T) {
	env := newTestEnv(t)
	cookie, csrf := env.loginCookie(t)
	for _, path := range []string{"/api/nope", "/api"} {
		for _, c := range []*http.Cookie{nil, cookie} {
			rec := env.doJSON(http.MethodGet, env.cfg.WebPath+path, "", c, csrf)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s (authed=%v): %d, want 404 JSON", path, c != nil, rec.Code)
			}
			var body map[string]any
			decodeJSON(t, rec, &body)
			if body["error"] == nil {
				t.Fatalf("GET %s body has no error: %v", path, body)
			}
		}
	}
	// Unknown UI path under the web path stays the plain 404, not JSON.
	rec := env.do(http.MethodGet, env.cfg.WebPath+"/nope", nil, cookie)
	if rec.Code != http.StatusNotFound || rec.Body.String() != "404 page not found\n" {
		t.Fatalf("unknown UI path: %d %q", rec.Code, rec.Body.String())
	}
}

func TestAPICSRFEnforcedOnMutations(t *testing.T) {
	env := newTestEnv(t)
	_, serverPath, nodePath := writeCompressionFixtures(t)
	env.cfg.ServerConfig, env.cfg.NodeConfig = serverPath, nodePath
	env.server.cfg.ServerConfig, env.server.cfg.NodeConfig = serverPath, nodePath
	cookie, _ := env.loginCookie(t)

	// No header.
	rec := env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/compression", `{"level":9}`, cookie, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("API POST without CSRF header: %d, want 403", rec.Code)
	}
	// Bad header.
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/compression", `{"level":9}`, cookie, "bogus-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("API POST with bad CSRF header: %d, want 403", rec.Code)
	}
	// GET with no header is fine.
	rec = env.doJSON(http.MethodGet, env.cfg.WebPath+"/api/compression", "", cookie, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("API GET without CSRF header: %d, want 200", rec.Code)
	}
	// A rejected mutation must not change either config file.
	before, _ := os.ReadFile(serverPath)
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/compression", `{"level":9}`, cookie, "")
	if rec.Code != http.StatusForbidden {
		t.Fatal("expected 403")
	}
	after, _ := os.ReadFile(serverPath)
	if string(before) != string(after) {
		t.Fatal("rejected API mutation changed a config file")
	}
}

func TestAPIStatusSocketAbsent(t *testing.T) {
	env := newTestEnv(t)
	empty := ""
	env.server.controlSocketPathOverride = &empty
	cookie, _ := env.loginCookie(t)
	rec := env.doJSON(http.MethodGet, env.cfg.WebPath+"/api/status", "", cookie, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("API status: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Nodes        []struct{ ID string } `json:"nodes"`
		Sessions     []any                 `json:"sessions"`
		SessionsNote string                `json:"sessions_note"`
		Control      ControlSocketState    `json:"control"`
		Compression  CompressionStatus     `json:"compression"`
	}
	decodeJSON(t, rec, &body)
	if body.Control.Configured || body.SessionsNote != controlSocketNotConfiguredNote {
		t.Fatalf("status with absent socket: %+v", body)
	}
	if body.Sessions == nil {
		t.Fatal("sessions must serialise as [], not null")
	}
	if len(body.Nodes) != 1 || body.Nodes[0].ID != "node-1" {
		t.Fatalf("nodes: %+v", body.Nodes)
	}
	if body.Compression.DictionaryVersion != "v1" || body.Compression.UploadDictionaryID != 1 || body.Compression.DownloadDictionaryID != 2 {
		t.Fatalf("dictionary identity: %+v", body.Compression)
	}
}

func TestAPICompressionRoundTripAndMismatchWarning(t *testing.T) {
	env := newTestEnv(t)
	_, serverPath, nodePath := writeCompressionFixtures(t)
	env.cfg.ServerConfig, env.cfg.NodeConfig = serverPath, nodePath
	env.server.cfg.ServerConfig, env.server.cfg.NodeConfig = serverPath, nodePath
	cookie, csrf := env.loginCookie(t)

	rec := env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/compression",
		`{"dict_enabled":true,"level":9,"long_enabled":false}`, cookie, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("compression POST: %d %s", rec.Code, rec.Body.String())
	}
	var applied struct {
		Applied       bool              `json:"applied"`
		Compression   CompressionStatus `json:"compression"`
		RestartNeeded bool              `json:"restart_needed"`
	}
	decodeJSON(t, rec, &applied)
	if !applied.Applied || !applied.RestartNeeded || !applied.Compression.Symmetric || applied.Compression.Warning != "" {
		t.Fatalf("applied response: %+v", applied)
	}
	if _, err := os.Stat(serverPath + ".bak"); err != nil {
		t.Fatalf("server .bak missing: %v", err)
	}
	sc, _ := config.LoadServerConfig(serverPath)
	if !sc.ZSTDDictEnabled || sc.ZSTDLevel != 9 {
		t.Fatalf("server file after API apply: dict=%v level=%d", sc.ZSTDDictEnabled, sc.ZSTDLevel)
	}

	// Mismatch: turn the node side off directly in its file; the API
	// must report the symmetric-enablement warning on both sides.
	nodeData, _ := os.ReadFile(nodePath)
	nodeData = []byte(strings.Replace(string(nodeData), "ZSTD_DICT_ENABLED = true", "ZSTD_DICT_ENABLED = false", 1))
	if err := os.WriteFile(nodePath, nodeData, 0o600); err != nil {
		t.Fatal(err)
	}
	rec = env.doJSON(http.MethodGet, env.cfg.WebPath+"/api/compression", "", cookie, "")
	var status CompressionStatus
	decodeJSON(t, rec, &status)
	if status.Symmetric || status.Warning == "" || !strings.Contains(status.Warning, "packets will be dropped") {
		t.Fatalf("mismatch warning missing: %+v", status)
	}
	// Invalid level is a 400 and changes nothing.
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/compression", `{"level":99}`, cookie, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("level 99: %d, want 400", rec.Code)
	}
}

func TestAPIRegistryFlowViaFakeSocket(t *testing.T) {
	env := newTestEnv(t)
	stub := &stubControlHandler{registry: env.registry}
	startFakeControlSocket(t, env, stub)
	cookie, csrf := env.loginCookie(t)

	// Reload applies live.
	rec := env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/registry", `{"action":"reload"}`, cookie, csrf)
	var reload struct {
		LiveApplied bool `json:"live_applied"`
	}
	decodeJSON(t, rec, &reload)
	if rec.Code != http.StatusOK || !reload.LiveApplied {
		t.Fatalf("reload: %d %s", rec.Code, rec.Body.String())
	}

	// Add with a generated key: shown once, never echoed when supplied.
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/registry", `{"action":"add","node_id":"node-2"}`, cookie, csrf)
	var added struct {
		KeyShownOnce   string `json:"key_shown_once"`
		KeyFingerprint string `json:"key_fingerprint"`
		FileWritten    bool   `json:"file_written"`
		LiveApplied    bool   `json:"live_applied"`
	}
	decodeJSON(t, rec, &added)
	if rec.Code != http.StatusOK || added.KeyShownOnce == "" || added.KeyFingerprint == "" || !added.FileWritten || !added.LiveApplied {
		t.Fatalf("add generated: %d %+v %s", rec.Code, added, rec.Body.String())
	}
	reg, _ := multisessionLoad(env.registry)
	if reg["node-2"] != added.KeyShownOnce {
		t.Fatal("generated key in the response is not the registry key")
	}
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/registry",
		`{"action":"add","node_id":"node-3","key":"`+validTestKey(3)+`"}`, cookie, csrf)
	var addedSupplied struct {
		KeyShownOnce string `json:"key_shown_once"`
	}
	decodeJSON(t, rec, &addedSupplied)
	if addedSupplied.KeyShownOnce != "" {
		t.Fatal("a caller-supplied key was echoed back")
	}
	if strings.Contains(rec.Body.String(), validTestKey(3)) {
		t.Fatal("a caller-supplied key was echoed back")
	}

	// Remove requires confirmation.
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/registry", `{"action":"remove","node_id":"node-3"}`, cookie, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("remove without confirm: %d, want 400", rec.Code)
	}
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/registry", `{"action":"remove","node_id":"node-3","confirm":true}`, cookie, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
	}

	// Rotate: shown once, and the registry holds exactly that key.
	oldKey := validTestKey(1)
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/registry", `{"action":"rotate","node_id":"node-1"}`, cookie, csrf)
	var rotated struct {
		KeyShownOnce string `json:"key_shown_once"`
		LiveApplied  bool   `json:"live_applied"`
	}
	decodeJSON(t, rec, &rotated)
	if rotated.KeyShownOnce == "" || rotated.KeyShownOnce == oldKey || !rotated.LiveApplied {
		t.Fatalf("rotate: %d %+v", rec.Code, rotated)
	}
	reg, _ = multisessionLoad(env.registry)
	if reg["node-1"] != rotated.KeyShownOnce {
		t.Fatal("rotated key in the response is not the registry key")
	}
	if strings.Contains(rec.Body.String(), oldKey) {
		t.Fatal("old key leaked into the rotate response")
	}

	// Unknown action.
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/registry", `{"action":"explode"}`, cookie, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown action: %d, want 400", rec.Code)
	}
	// Unknown field rejected (closed JSON shape).
	rec = env.doJSON(http.MethodPost, env.cfg.WebPath+"/api/registry", `{"action":"reload","surprise":1}`, cookie, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown JSON field: %d, want 400", rec.Code)
	}
}

func TestDashboardRendersSocketAbsentAndFake(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.authed(t)

	// Socket absent: exact unavailable note, compression + links present.
	empty := ""
	env.server.controlSocketPathOverride = &empty
	rec := env.do(http.MethodGet, env.cfg.WebPath+"/status", nil, cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard socket absent: %d", rec.Code)
	}
	for _, want := range []string{
		controlSocketNotConfiguredNote, "Live sessions", "Compression",
		"Dashboard", "Setup wizard", "Nodes", "Logs", "Jobs",
		"Dictionary version", "node-1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard missing %q:\n%s", want, body)
		}
	}

	// Fake socket: sessions listed, note gone.
	env2 := newTestEnv(t)
	stub := &stubControlHandler{
		registry: env2.registry,
		sessions: []control.SessionSummary{{
			SessionID: 7, NodeID: "node-1", UploadMTU: 110, DownloadMTU: 1015,
			CreatedAt: time.Now().Add(-time.Minute), LastActivity: time.Now(), ActiveStreams: 2,
		}},
	}
	startFakeControlSocket(t, env2, stub)
	cookie2 := env2.authed(t)
	rec = env2.do(http.MethodGet, env2.cfg.WebPath+"/status", nil, cookie2)
	body = rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard fake socket: %d", rec.Code)
	}
	if strings.Contains(body, controlSocketNotConfiguredNote) {
		t.Fatal("dashboard with a live socket still shows the not-configured note")
	}
	for _, want := range []string{"node-1", "110", "1015"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard with fake socket missing %q:\n%s", want, body)
		}
	}
}

func TestDashboardUIRegistryAndCompressionPosts(t *testing.T) {
	env := newTestEnv(t)
	_, serverPath, nodePath := writeCompressionFixtures(t)
	env.cfg.ServerConfig, env.cfg.NodeConfig = serverPath, nodePath
	env.server.cfg.ServerConfig, env.server.cfg.NodeConfig = serverPath, nodePath
	cookie := env.authed(t)
	csrf := env.csrfFor(t, cookie, env.cfg.WebPath+"/status")

	// UI registry reload without CSRF is rejected by requireAuth.
	rec := env.do(http.MethodPost, env.cfg.WebPath+"/registry/reload", url.Values{}, cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("UI reload without CSRF: %d, want 403", rec.Code)
	}
	// With CSRF and no socket: 200 with restart guidance, registry unchanged.
	empty := ""
	env.server.controlSocketPathOverride = &empty
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/registry/reload", url.Values{"csrf_token": {csrf}}, cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Restart the server to apply registry changes") {
		t.Fatalf("UI reload socket absent: %d\n%s", rec.Code, rec.Body.String())
	}
	entries, _ := ReadRegistryEntries(env.registry)
	if len(entries) != 1 {
		t.Fatalf("reload changed the registry: %+v", entries)
	}

	// UI compression POST without confirmation: rejected, files unchanged.
	serverBefore, _ := os.ReadFile(serverPath)
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/compression", url.Values{
		"dict_enabled": {"yes"}, "zstd_level": {"9"}, "long_enabled": {"yes"}, "csrf_token": {csrf},
	}, cookie)
	if !strings.Contains(rec.Body.String(), "requires confirmation") {
		t.Fatalf("compression without confirm not rejected:\n%s", rec.Body.String())
	}
	serverAfter, _ := os.ReadFile(serverPath)
	if string(serverBefore) != string(serverAfter) {
		t.Fatal("unconfirmed compression POST changed a config file")
	}
	// With confirmation: applied, restart banner present.
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/compression", url.Values{
		"dict_enabled": {"yes"}, "zstd_level": {"9"}, "confirm": {"yes"}, "csrf_token": {csrf},
	}, cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Compression settings written") {
		t.Fatalf("compression UI POST: %d\n%s", rec.Code, rec.Body.String())
	}
	sc, _ := config.LoadServerConfig(serverPath)
	nc, _ := config.LoadClientConfig(nodePath)
	if !sc.ZSTDDictEnabled || sc.ZSTDLevel != 9 || !nc.ZSTDDictEnabled || nc.ZSTDLevel != 9 {
		t.Fatalf("UI compression apply: server %+v node %+v", sc.ZSTDDictEnabled, nc.ZSTDDictEnabled)
	}
	if !strings.Contains(rec.Body.String(), "registry changed") {
		t.Fatalf("restart banner missing after compression apply:\n%s", rec.Body.String())
	}
}
