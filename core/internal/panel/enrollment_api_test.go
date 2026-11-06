package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/control"
	"github.com/Altonomega/Nexounel/core/internal/enroll"
)

// enrollTestEnv wires a fake control socket and a temp mesh-secret
// file, so enrollment tests run the full panel-side transaction
// against the stub server.
func enrollTestEnv(t *testing.T) (*testEnv, *stubControlHandler) {
	t.Helper()
	env := newTestEnv(t)
	stub := &stubControlHandler{registry: env.registry}
	startFakeControlSocket(t, env, stub)
	env.server.cfg.MeshSecretFile = filepath.Join(t.TempDir(), "mesh-control-secret.key")
	return env, stub
}

func issueTokenFor(t *testing.T, env *testEnv, nodeID string) string {
	t.Helper()
	token, _, err := env.server.issueJoinToken(context.Background(), issueTestParams(nodeID))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// postEnroll posts one wire envelope to the loopback handler with
// the given remote address and returns the recorder.
func postEnroll(t *testing.T, env *testEnv, body string, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	env.server.EnrollmentHandler().ServeHTTP(rec, req)
	return rec
}

func enrollEnvelope(token, nodeID string) string {
	req, err := enroll.MarshalRequest(enroll.EnrollmentRequest{NodeID: nodeID, Token: token})
	if err != nil {
		panic(err)
	}
	wire, err := json.Marshal(map[string]any{
		"fingerprint": enroll.TokenFingerprint(token),
		"request":     json.RawMessage(req),
	})
	if err != nil {
		panic(err)
	}
	return string(wire)
}

func decodeEnrollResponse(t *testing.T, rec *httptest.ResponseRecorder) enroll.EnrollmentResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll HTTP %d: %s", rec.Code, rec.Body.String())
	}
	resp, err := enroll.ParseResponse(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("decode enrollment response: %v; body %s", err, rec.Body.String())
	}
	return resp
}

func TestEnrollmentIssueSuccess(t *testing.T) {
	env, stub := enrollTestEnv(t)
	token := issueTokenFor(t, env, "node-2")
	fp := enroll.TokenFingerprint(token)
	if !stub.hasBootstrapKey(fp) {
		t.Fatal("bootstrap key not pushed at issuance")
	}

	resp := decodeEnrollResponse(t, postEnroll(t, env, enrollEnvelope(token, "node-2"), "127.0.0.1:1234"))
	if resp.ErrorCode != "" {
		t.Fatalf("enrollment refused: %+v", resp)
	}
	if resp.NodeID != "node-2" || len(resp.NodeKey) != 32 {
		t.Fatalf("enrollment response: %+v", resp)
	}
	if !strings.Contains(resp.NodeConfig, `NODE_ID = "node-2"`) ||
		!strings.Contains(resp.NodeConfig, `DOMAINS = ["v.example.invalid"]`) ||
		!strings.Contains(resp.NodeConfig, "MESH_CONTROL_SECRET_FILE") ||
		!strings.Contains(resp.NodeConfig, `FORWARD_RANGE = "20000-20010"`) {
		t.Fatalf("issued config:\n%s", resp.NodeConfig)
	}
	if strings.Contains(resp.NodeConfig, resp.NodeKey) {
		t.Fatal("issued config embeds the node key")
	}
	secretData, err := os.ReadFile(env.server.cfg.MeshSecretFile)
	if err != nil {
		t.Fatal(err)
	}
	if resp.MeshControlSecret != strings.TrimSpace(string(secretData)) {
		t.Fatal("issued mesh secret differs from the panel's stored secret")
	}
	// Registry written, token consumed, bootstrap key dropped.
	entries, err := ReadRegistryEntries(env.registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[1].ID != "node-2" || entries[1].Key != resp.NodeKey {
		t.Fatalf("registry after enrollment: %+v", entries)
	}
	if _, err := env.server.joinStore().Verify(token); err != enroll.ErrTokenUsed {
		t.Fatalf("token after enrollment: %v, want used", err)
	}
	if stub.hasBootstrapKey(fp) {
		t.Fatal("bootstrap key not dropped after consume")
	}
	// A replayed token is refused permanently.
	resp = decodeEnrollResponse(t, postEnroll(t, env, enrollEnvelope(token, "node-2"), "127.0.0.1:1234"))
	if resp.ErrorCode != enroll.ErrCodeUsedToken || !enroll.PermanentErrorCode(resp.ErrorCode) {
		t.Fatalf("replay: %+v", resp)
	}
}

func TestEnrollmentIssueIdempotentReissue(t *testing.T) {
	env, _ := enrollTestEnv(t)
	token := issueTokenFor(t, env, "node-1")
	resp := decodeEnrollResponse(t, postEnroll(t, env, enrollEnvelope(token, "node-1"), "127.0.0.1:1234"))
	if resp.ErrorCode != "" {
		t.Fatalf("re-enrollment refused: %+v", resp)
	}
	if resp.NodeKey != validTestKey(1) {
		t.Fatalf("re-issue returned a new key %q, want the registry key", resp.NodeKey)
	}
	entries, _ := ReadRegistryEntries(env.registry)
	if len(entries) != 1 {
		t.Fatalf("re-issue duplicated the registry entry: %+v", entries)
	}
}

func TestEnrollmentIssueKeyFileRefusedWithoutConsuming(t *testing.T) {
	env, _ := enrollTestEnv(t)
	keyFile := filepath.Join(t.TempDir(), "node-9.key")
	if err := os.WriteFile(keyFile, []byte(validTestKey(9)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	regPath := filepath.Join(t.TempDir(), "nodes.toml")
	if err := os.WriteFile(regPath, []byte("[[nodes]]\nid = \"node-9\"\nkey_file = \""+keyFile+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.server.cfg.RegistryFile = regPath
	token := issueTokenFor(t, env, "node-9")
	resp := decodeEnrollResponse(t, postEnroll(t, env, enrollEnvelope(token, "node-9"), "127.0.0.1:1234"))
	if resp.ErrorCode != enroll.ErrCodeFailed {
		t.Fatalf("key_file enrollment: %+v", resp)
	}
	if _, err := env.server.joinStore().Verify(token); err != nil {
		t.Fatalf("refused token must stay usable: %v", err)
	}
}

func TestEnrollmentIssueRegistryFailureDoesNotConsume(t *testing.T) {
	env, _ := enrollTestEnv(t)
	// Point the registry at a directory: every registry read/write fails.
	broken := t.TempDir()
	env.server.cfg.RegistryFile = broken
	token := issueTokenFor(t, env, "node-2")
	resp := decodeEnrollResponse(t, postEnroll(t, env, enrollEnvelope(token, "node-2"), "127.0.0.1:1234"))
	if resp.ErrorCode != enroll.ErrCodeFailed {
		t.Fatalf("broken-registry enrollment: %+v", resp)
	}
	if _, err := env.server.joinStore().Verify(token); err != nil {
		t.Fatalf("token burned by a registry failure: %v", err)
	}
	// Fix the registry: the same token retries successfully.
	env.server.cfg.RegistryFile = env.registry
	resp = decodeEnrollResponse(t, postEnroll(t, env, enrollEnvelope(token, "node-2"), "127.0.0.1:1234"))
	if resp.ErrorCode != "" {
		t.Fatalf("retry after registry fix: %+v", resp)
	}
}

func TestEnrollmentIssueReloadFailureStillSucceedsWithRestartFlag(t *testing.T) {
	env, stub := enrollTestEnv(t)
	stub.failCommands = map[string]bool{control.CmdReloadRegistry: true}
	token := issueTokenFor(t, env, "node-2")
	resp := decodeEnrollResponse(t, postEnroll(t, env, enrollEnvelope(token, "node-2"), "127.0.0.1:1234"))
	if resp.ErrorCode != "" {
		t.Fatalf("enrollment with dead reload: %+v", resp)
	}
	env.server.restartMu.Lock()
	needed := env.server.restartNeeded
	env.server.restartMu.Unlock()
	if !needed {
		t.Fatal("reload failure did not flag a restart")
	}
}

func TestEnrollmentIssueTokenRefusals(t *testing.T) {
	env, _ := enrollTestEnv(t)

	// Unknown token: permanent.
	unknown, err := enroll.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	resp := decodeEnrollResponse(t, postEnroll(t, env, enrollEnvelope(unknown, "node-2"), "127.0.0.1:1234"))
	if resp.ErrorCode != enroll.ErrCodeUnknownToken || !enroll.PermanentErrorCode(resp.ErrorCode) {
		t.Fatalf("unknown token: %+v", resp)
	}

	// Fingerprint mismatch: permanent unknown.
	token := issueTokenFor(t, env, "node-2")
	other, err := enroll.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	req, _ := enroll.MarshalRequest(enroll.EnrollmentRequest{NodeID: "node-2", Token: other})
	wire, _ := json.Marshal(map[string]any{"fingerprint": enroll.TokenFingerprint(token), "request": json.RawMessage(req)})
	resp = decodeEnrollResponse(t, postEnroll(t, env, string(wire), "127.0.0.1:1234"))
	if resp.ErrorCode != enroll.ErrCodeUnknownToken {
		t.Fatalf("fingerprint mismatch: %+v", resp)
	}

	// Token bound to another node ID: permanent unknown.
	resp = decodeEnrollResponse(t, postEnroll(t, env, enrollEnvelope(token, "node-3"), "127.0.0.1:1234"))
	if resp.ErrorCode != enroll.ErrCodeUnknownToken {
		t.Fatalf("node id mismatch: %+v", resp)
	}
	// The mismatches must not burn the token.
	if _, err := env.server.joinStore().Verify(token); err != nil {
		t.Fatalf("token burned by refused presentations: %v", err)
	}
}

func TestEnrollmentIssueMalformedEnvelopesAre400(t *testing.T) {
	env, _ := enrollTestEnv(t)
	token := issueTokenFor(t, env, "node-2")

	cases := map[string]string{
		"bad version": func() string {
			wire, _ := json.Marshal(map[string]any{
				"fingerprint": enroll.TokenFingerprint(token),
				"request":     json.RawMessage(`{"version":2,"node_id":"node-2","token":"` + token + `","capability":"nexounel-bootstrap-v1"}`),
			})
			return string(wire)
		}(),
		"bad capability": func() string {
			wire, _ := json.Marshal(map[string]any{
				"fingerprint": enroll.TokenFingerprint(token),
				"request":     json.RawMessage(`{"version":1,"node_id":"node-2","token":"` + token + `","capability":"wrong"}`),
			})
			return string(wire)
		}(),
		"unknown field": func() string {
			wire, _ := json.Marshal(map[string]any{
				"fingerprint": enroll.TokenFingerprint(token),
				"request":     json.RawMessage(`{"version":1,"node_id":"node-2","token":"` + token + `","capability":"nexounel-bootstrap-v1"}`),
				"surprise":    1,
			})
			return string(wire)
		}(),
		"not json": "{nope",
	}
	for name, body := range cases {
		rec := postEnroll(t, env, body, "127.0.0.1:1234")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: HTTP %d, want 400: %s", name, rec.Code, rec.Body.String())
		}
	}
	if _, err := env.server.joinStore().Verify(token); err != nil {
		t.Fatalf("malformed envelopes burned the token: %v", err)
	}
}

func TestEnrollmentHandlerLoopbackOnly(t *testing.T) {
	env, _ := enrollTestEnv(t)
	token := issueTokenFor(t, env, "node-2")
	body := enrollEnvelope(token, "node-2")

	for _, addr := range []string{"203.0.113.1:1234", "", "192.0.2.1:1234"} {
		rec := postEnroll(t, env, body, addr)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("remote %q: HTTP %d, want 403", addr, rec.Code)
		}
	}
	// IPv6 loopback is local.
	rec := postEnroll(t, env, body, "[::1]:1234")
	if rec.Code != http.StatusOK {
		t.Fatalf("::1: HTTP %d, want 200", rec.Code)
	}
	// Wrong method / path.
	req := httptest.NewRequest(http.MethodGet, "/enroll", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec = httptest.NewRecorder()
	env.server.EnrollmentHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /enroll: %d, want 405", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/other", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	rec = httptest.NewRecorder()
	env.server.EnrollmentHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /other: %d, want 404", rec.Code)
	}
}

func TestEnrollmentIssueMeshSecretShortFile(t *testing.T) {
	env, _ := enrollTestEnv(t)
	secretPath := env.server.cfg.MeshSecretFile
	if err := os.WriteFile(secretPath, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := issueTokenFor(t, env, "node-2")
	resp := decodeEnrollResponse(t, postEnroll(t, env, enrollEnvelope(token, "node-2"), "127.0.0.1:1234"))
	if resp.ErrorCode != enroll.ErrCodeFailed {
		t.Fatalf("short secret file: %+v", resp)
	}
	if _, err := env.server.joinStore().Verify(token); err != nil {
		t.Fatalf("token burned by a secret-file failure: %v", err)
	}
}

func TestHTTPIssuerRoundTripToPanelAPI(t *testing.T) {
	env, _ := enrollTestEnv(t)
	token := issueTokenFor(t, env, "node-2")

	// Serve the panel's enrollment handler on a real loopback
	// listener, exactly as the tunnel server's HTTPIssuer calls it.
	srv := httptest.NewServer(env.server.EnrollmentHandler())
	defer srv.Close()
	issuer := enroll.HTTPIssuer{Endpoint: srv.URL + "/enroll"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := issuer.Issue(ctx, enroll.TokenFingerprint(token), enroll.EnrollmentRequest{NodeID: "node-2", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ErrorCode != "" || resp.NodeKey == "" || resp.NodeConfig == "" || resp.MeshControlSecret == "" {
		t.Fatalf("issuer round trip: %+v", resp)
	}

	// A non-loopback endpoint is refused by the issuer itself.
	issuer = enroll.HTTPIssuer{Endpoint: "http://203.0.113.10:18082/enroll"}
	_, err = issuer.Issue(ctx, enroll.TokenFingerprint(token), enroll.EnrollmentRequest{NodeID: "node-2", Token: token})
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("non-loopback issuer endpoint: %v", err)
	}
}
