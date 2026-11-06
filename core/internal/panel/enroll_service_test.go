package panel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/control"
	"github.com/Altonomega/Nexounel/core/internal/enroll"
)

func issueTestParams(nodeID string) joinParams {
	return joinParams{
		NodeID: nodeID, ConnectAddress: "v.example.invalid",
		ListenPort: 18000, ForwardRange: "20000-20010", TTLHours: 24,
	}
}

func TestNormalizeJoinParams(t *testing.T) {
	got, err := normalizeJoinParams(joinParams{
		NodeID: "node-2", ConnectAddress: "V.Example.Invalid",
		ForwardRange: "20000-20010",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ListenPort != 18000 || got.TTLHours != 24 || got.ConnectAddress != "v.example.invalid" {
		t.Fatalf("defaults not applied: %+v", got)
	}
	for _, tc := range []struct {
		name string
		p    joinParams
	}{
		{"bad node id", joinParams{NodeID: "bad id!", ConnectAddress: "v.example.invalid", ForwardRange: "20000-20010"}},
		{"no dot", joinParams{NodeID: "node-2", ConnectAddress: "localhost", ForwardRange: "20000-20010"}},
		{"bad label", joinParams{NodeID: "node-2", ConnectAddress: "v.-bad-.invalid", ForwardRange: "20000-20010"}},
		{"bad range", joinParams{NodeID: "node-2", ConnectAddress: "v.example.invalid", ForwardRange: "not-a-range"}},
		{"bad port", joinParams{NodeID: "node-2", ConnectAddress: "v.example.invalid", ForwardRange: "20000-20010", ListenPort: 70000}},
		{"ttl zero is default", joinParams{NodeID: "node-2", ConnectAddress: "v.example.invalid", ForwardRange: "20000-20010", TTLHours: 0}},
	} {
		if _, err := normalizeJoinParams(tc.p); err != nil {
			if tc.name == "ttl zero is default" {
				t.Fatalf("%s: unexpected error %v", tc.name, err)
			}
			if !errors.Is(err, errJoinValidation) {
				t.Fatalf("%s: error %v is not a validation error", tc.name, err)
			}
		} else if tc.name != "ttl zero is default" {
			t.Fatalf("%s: invalid input accepted", tc.name)
		}
	}
	if _, err := normalizeJoinParams(joinParams{NodeID: "node-2", ConnectAddress: "v.example.invalid", ForwardRange: "20000-20010", TTLHours: 25}); err == nil {
		t.Fatal("TTL 25 accepted")
	}
}

func TestLoadMeshSecretGeneratesAndReuses(t *testing.T) {
	env := newTestEnv(t)
	secretPath := filepath.Join(t.TempDir(), "mesh-control-secret.key")
	env.server.cfg.MeshSecretFile = secretPath

	secret, err := env.server.loadMeshSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 64 {
		t.Fatalf("generated secret length %d, want 64 hex chars", len(secret))
	}
	info, err := os.Stat(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode %o, want 0600", info.Mode().Perm())
	}
	again, err := env.server.loadMeshSecret()
	if err != nil {
		t.Fatal(err)
	}
	if again != secret {
		t.Fatal("second load did not reuse the generated secret")
	}
	if strings.Contains(secret, "\n") {
		t.Fatal("secret contains a newline")
	}
}

func TestLoadMeshSecretRejectsShortFile(t *testing.T) {
	env := newTestEnv(t)
	secretPath := filepath.Join(t.TempDir(), "mesh-control-secret.key")
	if err := os.WriteFile(secretPath, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.server.cfg.MeshSecretFile = secretPath
	if _, err := env.server.loadMeshSecret(); err == nil {
		t.Fatal("short mesh secret file accepted")
	}
	data, _ := os.ReadFile(secretPath)
	if string(data) != "short\n" {
		t.Fatal("short secret file was overwritten instead of failing closed")
	}
}

func TestBuildNodeConfigWithMeshSecret(t *testing.T) {
	pending := PendingNode{ID: "node-2", ConnectAddress: "v.example.invalid", ListenPort: 18000, ForwardRange: "20000-20010"}
	plain := BuildNodeConfig(pending, "/opt/nexounel/node.key", "/opt/nexounel/client_resolvers.txt")
	withSecret := BuildNodeConfigWithMeshSecret(pending, "/opt/nexounel/node.key", "/opt/nexounel/client_resolvers.txt", "/opt/nexounel/mesh-control-secret.key")
	if strings.Contains(plain, "MESH_CONTROL_SECRET_FILE") {
		t.Fatal("plain config must not carry a mesh secret line")
	}
	if !strings.Contains(withSecret, "MESH_CONTROL_SECRET_FILE = \"/opt/nexounel/mesh-control-secret.key\"") {
		t.Fatalf("config with secret missing the line:\n%s", withSecret)
	}
	if strings.Contains(withSecret, "node.key") && !strings.Contains(withSecret, "NODE_KEY_FILE") {
		t.Fatal("config lost the key file line")
	}
	// The secret variant differs from the plain one by exactly one line.
	if strings.Replace(withSecret, "MESH_CONTROL_SECRET_FILE = \"/opt/nexounel/mesh-control-secret.key\"\n", "", 1) != plain {
		t.Fatal("secret variant differs from the plain config by more than the one line")
	}
	// The issued config must never embed the node key itself.
	if strings.Contains(withSecret, validTestKey(1)) {
		t.Fatal("issued config embeds key material")
	}
}

func TestIssueJoinTokenPushesKeyAndRevokeRemovesIt(t *testing.T) {
	env := newTestEnv(t)
	stub := &stubControlHandler{registry: env.registry}
	startFakeControlSocket(t, env, stub)

	token, view, err := env.server.issueJoinToken(context.Background(), issueTestParams("node-2"))
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 43 {
		t.Fatalf("token length %d, want 43", len(token))
	}
	fp := enroll.TokenFingerprint(token)
	if view.Fingerprint != enroll.DisplayFingerprint(token) {
		t.Fatalf("view fingerprint %q", view.Fingerprint)
	}
	if !stub.hasBootstrapKey(fp) {
		t.Fatal("bootstrap key was not pushed to the server at issuance")
	}
	if params, ok := env.server.joinParams[fp]; !ok || params.ConnectAddress != "v.example.invalid" {
		t.Fatalf("issuance record missing or wrong: %+v %v", params, ok)
	}
	// The token is never recoverable from the listing.
	for _, v := range env.server.pendingJoinViews(context.Background()) {
		if strings.Contains(v.Fingerprint, token) {
			t.Fatal("listing exposes token material")
		}
	}
	if len(env.server.pendingJoinViews(context.Background())) != 1 {
		t.Fatal("pending join not listed")
	}

	revoked, err := env.server.revokeJoinToken(context.Background(), "node-2")
	if err != nil || !revoked {
		t.Fatalf("revoke = (%v, %v)", revoked, err)
	}
	if stub.hasBootstrapKey(fp) {
		t.Fatal("bootstrap key was not removed on revoke")
	}
	if _, err := env.server.joinStore().Verify(token); err != enroll.ErrUnknownToken {
		t.Fatalf("revoked token verifies: %v", err)
	}
	revoked, err = env.server.revokeJoinToken(context.Background(), "node-2")
	if err != nil || revoked {
		t.Fatalf("second revoke = (%v, %v)", revoked, err)
	}
}

func TestIssueJoinTokenRollsBackWhenSocketAbsent(t *testing.T) {
	env := newTestEnv(t)
	empty := ""
	env.server.controlSocketPathOverride = &empty

	_, _, err := env.server.issueJoinToken(context.Background(), issueTestParams("node-2"))
	if err == nil {
		t.Fatal("issuance succeeded with no control socket")
	}
	if len(env.server.joinStore().List()) != 0 {
		t.Fatal("failed issuance left a pending join behind")
	}
	if len(env.server.joinParams) != 0 {
		t.Fatal("failed issuance left an issuance record behind")
	}
}

func TestIssueJoinTokenRollsBackWhenSocketDead(t *testing.T) {
	env := newTestEnv(t)
	dead := filepath.Join(t.TempDir(), "no-such.sock")
	env.server.controlSocketPathOverride = &dead
	env.server.controlClientFactory = func(path string) controlClient {
		return realControlClient{client: control.Client{SocketPath: path, Timeout: 500 * time.Millisecond}}
	}
	_, _, err := env.server.issueJoinToken(context.Background(), issueTestParams("node-2"))
	if err == nil {
		t.Fatal("issuance succeeded with a dead control socket")
	}
	if len(env.server.joinStore().List()) != 0 {
		t.Fatal("failed issuance left a pending join behind")
	}
}

func TestSweepJoinTokensRemovesExpiredKeys(t *testing.T) {
	env := newTestEnv(t)
	stub := &stubControlHandler{registry: env.registry}
	startFakeControlSocket(t, env, stub)

	now := time.Now()
	clock := func() time.Time { return now }
	env.server.pendingStore = enroll.NewPendingStore(clock)
	token, _, err := env.server.issueJoinToken(context.Background(), joinParams{
		NodeID: "node-2", ConnectAddress: "v.example.invalid",
		ListenPort: 18000, ForwardRange: "20000-20010", TTLHours: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	fp := enroll.TokenFingerprint(token)
	if !stub.hasBootstrapKey(fp) {
		t.Fatal("key not pushed")
	}
	now = now.Add(2 * time.Hour)
	views := env.server.pendingJoinViews(context.Background())
	if len(views) != 0 {
		t.Fatalf("expired join still listed: %+v", views)
	}
	if stub.hasBootstrapKey(fp) {
		t.Fatal("expired bootstrap key was not removed by the sweep")
	}
	if len(env.server.joinParams) != 0 {
		t.Fatal("sweep left an issuance record behind")
	}
}

func TestValidateEnrollmentAddr(t *testing.T) {
	for _, ok := range []string{"", "127.0.0.1:18082", "127.0.0.2:18082", "[::1]:18082", "localhost:18082", "LOCALHOST:18082"} {
		if err := ValidateEnrollmentAddr(ok); err != nil {
			t.Fatalf("enrollment addr %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:18082", "203.0.113.10:18082", "not-an-address", "127.0.0.1", "example.invalid:18082"} {
		if err := ValidateEnrollmentAddr(bad); err == nil {
			t.Fatalf("enrollment addr %q accepted", bad)
		}
	}
	cfg := DefaultConfig()
	cfg.EnrollmentAddr = "0.0.0.0:18082"
	cfg.WebPath = "/test-path-example"
	cfg.Username = "admin"
	hash, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	cfg.PasswordHash = hash
	cfg.SessionKey, _ = GenerateSessionKey()
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("non-loopback enrollment_addr passed ValidateConfig")
	}
}
