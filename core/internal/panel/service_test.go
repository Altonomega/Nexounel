package panel

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/control"
	"github.com/Altonomega/Nexounel/core/internal/multisession"
)

// stubControlHandler records commands and, for add/rotate, proves the
// ordering contract: at command time the registry file must already
// reflect the change the panel claimed to write first.
type stubControlHandler struct {
	mu       sync.Mutex
	commands []string
	registry string
	sessions []control.SessionSummary
	mesh     *control.MeshSnapshot
	// bootstrapKeys records fingerprints pushed via
	// add-bootstrap-key and still present (remove drops them).
	bootstrapKeys map[string]bool
	// failCommands makes the named commands fail, to prove
	// best-effort paths (reload failure during enrollment).
	failCommands map[string]bool
}

func (h *stubControlHandler) Handle(ctx context.Context, req control.Request) control.Response {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.commands = append(h.commands, req.Command)
	if h.failCommands != nil && h.failCommands[req.Command] {
		return control.Response{Version: control.ProtocolVersion, Error: "stub forced failure for " + req.Command}
	}
	switch req.Command {
	case control.CmdPing:
		return control.Response{Version: control.ProtocolVersion, OK: true}
	case control.CmdReloadRegistry:
		return control.Response{Version: control.ProtocolVersion, OK: true, Data: map[string]any{"nodes": 1}}
	case control.CmdAddNode:
		reg, err := multisession.LoadRegistry(h.registry)
		if err != nil {
			return control.Response{Version: control.ProtocolVersion, Error: "registry unreadable: " + err.Error()}
		}
		if _, ok := reg.Lookup(req.Args["node_id"]); !ok {
			return control.Response{Version: control.ProtocolVersion, Error: "ordering violated: node not in registry file yet"}
		}
		return control.Response{Version: control.ProtocolVersion, OK: true}
	case control.CmdRemoveNode:
		reg, err := multisession.LoadRegistry(h.registry)
		if err != nil {
			return control.Response{Version: control.ProtocolVersion, Error: "registry unreadable: " + err.Error()}
		}
		if _, ok := reg.Lookup(req.Args["node_id"]); ok {
			return control.Response{Version: control.ProtocolVersion, Error: "ordering violated: node still in registry file"}
		}
		return control.Response{Version: control.ProtocolVersion, OK: true}
	case control.CmdRotateKey:
		entries, err := ReadRegistryEntries(h.registry)
		if err != nil {
			return control.Response{Version: control.ProtocolVersion, Error: "registry unreadable: " + err.Error()}
		}
		for _, e := range entries {
			if e.ID == req.Args["node_id"] && e.Key == req.Args["key"] {
				return control.Response{Version: control.ProtocolVersion, OK: true}
			}
		}
		return control.Response{Version: control.ProtocolVersion, Error: "ordering violated: rotated key not in registry file yet"}
	case control.CmdListSessions:
		sessions := make([]any, 0, len(h.sessions))
		for _, s := range h.sessions {
			sessions = append(sessions, map[string]any{
				"session_id": s.SessionID, "node_id": s.NodeID,
				"upload_mtu": s.UploadMTU, "download_mtu": s.DownloadMTU,
				"created_at":     s.CreatedAt.UTC().Format(time.RFC3339Nano),
				"last_activity":  s.LastActivity.UTC().Format(time.RFC3339Nano),
				"active_streams": s.ActiveStreams,
			})
		}
		return control.Response{Version: control.ProtocolVersion, OK: true, Data: map[string]any{"sessions": sessions}}
	case control.CmdListMesh:
		if h.mesh == nil {
			return control.Response{Version: control.ProtocolVersion, Error: "mesh state is not available on this server"}
		}
		return control.Response{Version: control.ProtocolVersion, OK: true, Data: map[string]any{"mesh": h.mesh}}
	case control.CmdAddBootstrapKey:
		if h.bootstrapKeys == nil {
			h.bootstrapKeys = map[string]bool{}
		}
		h.bootstrapKeys[req.Args["fingerprint"]] = true
		return control.Response{Version: control.ProtocolVersion, OK: true}
	case control.CmdRemoveBootstrapKey:
		delete(h.bootstrapKeys, req.Args["fingerprint"])
		return control.Response{Version: control.ProtocolVersion, OK: true}
	default:
		return control.Response{Version: control.ProtocolVersion, Error: "unknown command"}
	}
}

func (h *stubControlHandler) hasBootstrapKey(fingerprint string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.bootstrapKeys[fingerprint]
}

func (h *stubControlHandler) seen() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.commands...)
}

// startFakeControlSocket serves stub on a temp Unix socket and wires
// env's server to it via the override + factory seams.
func startFakeControlSocket(t *testing.T, env *testEnv, stub *stubControlHandler) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = control.Serve(ctx, listener, stub) }()
	env.server.controlSocketPathOverride = &socketPath
	env.server.controlClientFactory = func(path string) controlClient {
		return realControlClient{client: control.Client{SocketPath: path, Timeout: 2 * time.Second}}
	}
	return socketPath
}

func TestControlSocketStateAndSessionsViaFakeSocket(t *testing.T) {
	env := newTestEnv(t)
	stub := &stubControlHandler{
		registry: env.registry,
		sessions: []control.SessionSummary{{
			SessionID: 7, NodeID: "node-1", UploadMTU: 110, DownloadMTU: 1015,
			CreatedAt: time.Now().Add(-time.Minute), LastActivity: time.Now(), ActiveStreams: 2,
		}},
	}
	startFakeControlSocket(t, env, stub)

	state := env.server.controlSocketState(context.Background())
	if !state.Configured || !state.Reachable || !state.Available {
		t.Fatalf("socket state: %+v", state)
	}
	sessions, state := env.server.liveSessions(context.Background())
	if len(sessions) != 1 || sessions[0].NodeID != "node-1" || sessions[0].SessionID != 7 {
		t.Fatalf("sessions: %+v state %+v", sessions, state)
	}
	if got := stub.seen(); len(got) < 2 || got[0] != control.CmdPing {
		t.Fatalf("expected ping first, saw %v", got)
	}
}

func TestControlSocketAbsentDegradesHonestly(t *testing.T) {
	env := newTestEnv(t)
	empty := ""
	env.server.controlSocketPathOverride = &empty // force "not configured"

	state := env.server.controlSocketState(context.Background())
	if state.Configured || state.Available || state.Error != controlSocketNotConfiguredNote {
		t.Fatalf("absent socket state: %+v", state)
	}
	sessions, state := env.server.liveSessions(context.Background())
	if len(sessions) != 0 || state.Error != controlSocketNotConfiguredNote {
		t.Fatalf("absent socket sessions: %+v %+v", sessions, state)
	}
	// The dashboard still loads fully.
	content := env.server.loadDashboard(context.Background())
	if content.SessionsNote != controlSocketNotConfiguredNote || content.Control.Configured {
		t.Fatalf("dashboard with absent socket: %+v", content)
	}
	// Reload with no socket: file untouched, restart flagged.
	result := env.server.registryReload(context.Background())
	if result.LiveApplied || !result.RestartNeeded || result.Control.Configured {
		t.Fatalf("reload with absent socket: %+v", result)
	}
}

func TestControlSocketDownDegradesWithoutError(t *testing.T) {
	env := newTestEnv(t)
	dead := filepath.Join(t.TempDir(), "no-such.sock")
	env.server.controlSocketPathOverride = &dead
	env.server.controlClientFactory = func(path string) controlClient {
		return realControlClient{client: control.Client{SocketPath: path, Timeout: 500 * time.Millisecond}}
	}
	state := env.server.controlSocketState(context.Background())
	if !state.Configured || state.Available {
		t.Fatalf("dead socket state: %+v", state)
	}
	sessions, _ := env.server.liveSessions(context.Background())
	if len(sessions) != 0 {
		t.Fatalf("dead socket returned sessions: %+v", sessions)
	}
	content := env.server.loadDashboard(context.Background())
	if content.Control.Available || len(content.Sessions) != 0 {
		t.Fatalf("dashboard with dead socket: %+v", content)
	}
}

func TestRegistryOpsFollowOrderingContract(t *testing.T) {
	env := newTestEnv(t)
	stub := &stubControlHandler{registry: env.registry}
	startFakeControlSocket(t, env, stub)
	ctx := context.Background()

	// Add: file first (stub verifies), then socket.
	result, generated, err := env.server.registryAdd(ctx, "node-2", validTestKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if generated != "" {
		t.Fatal("a caller-supplied key must not be reported as generated")
	}
	if !result.FileWritten || !result.LiveApplied {
		t.Fatalf("add result: %+v", result)
	}
	entries, _ := ReadRegistryEntries(env.registry)
	if len(entries) != 2 {
		t.Fatalf("registry after add: %+v", entries)
	}

	// Rotate: file first (stub verifies the new key is in the file),
	// then socket. The new key must differ from the old one.
	oldKey := validTestKey(1)
	result, newKey, err := env.server.registryRotate(ctx, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if newKey == "" || newKey == oldKey {
		t.Fatal("rotation did not issue a fresh key")
	}
	if !result.FileWritten || !result.LiveApplied {
		t.Fatalf("rotate result: %+v", result)
	}

	// Remove: file first (stub verifies absence), then socket.
	result, err = env.server.registryRemove(ctx, "node-2")
	if err != nil {
		t.Fatal(err)
	}
	if !result.FileWritten || !result.LiveApplied {
		t.Fatalf("remove result: %+v", result)
	}
	entries, _ = ReadRegistryEntries(env.registry)
	if len(entries) != 1 || entries[0].ID != "node-1" {
		t.Fatalf("registry after remove: %+v", entries)
	}
	seen := strings.Join(stub.seen(), ",")
	for _, cmd := range []string{control.CmdAddNode, control.CmdRotateKey, control.CmdRemoveNode} {
		if !strings.Contains(seen, cmd) {
			t.Fatalf("socket never saw %s; saw %s", cmd, seen)
		}
	}
}

func TestRegistryAddWithSocketDownKeepsFileAndFlagsRestart(t *testing.T) {
	env := newTestEnv(t)
	dead := filepath.Join(t.TempDir(), "no-such.sock")
	env.server.controlSocketPathOverride = &dead
	env.server.controlClientFactory = func(path string) controlClient {
		return realControlClient{client: control.Client{SocketPath: path, Timeout: 500 * time.Millisecond}}
	}
	result, _, err := env.server.registryAdd(context.Background(), "node-9", validTestKey(9))
	if err != nil {
		t.Fatal(err)
	}
	if !result.FileWritten || result.LiveApplied || !result.RestartNeeded || result.Error == "" {
		t.Fatalf("add with dead socket: %+v", result)
	}
	entries, _ := ReadRegistryEntries(env.registry)
	if len(entries) != 2 {
		t.Fatalf("file write lost when socket was down: %+v", entries)
	}
}
