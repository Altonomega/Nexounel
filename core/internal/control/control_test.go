package control

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/security"
)

type fakeSwapper struct {
	mu        sync.Mutex
	codecs    []*security.Codec
	ids       []string
	swaps     int
	summaries []SessionSummary
	failSwap  bool
}

func (f *fakeSwapper) SwapCodecs(codecs []*security.Codec, ids []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSwap {
		return errFakeSwap
	}
	if len(codecs) == 0 || len(codecs) != len(ids) {
		return errFakeSwap
	}
	f.codecs = codecs
	f.ids = append([]string(nil), ids...)
	f.swaps++
	return nil
}

func (f *fakeSwapper) SessionSummaries() []SessionSummary {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]SessionSummary(nil), f.summaries...)
}

func (f *fakeSwapper) currentIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ids...)
}

type fakeSwapError string

func (e fakeSwapError) Error() string { return string(e) }

const errFakeSwap = fakeSwapError("fake swap failure")

const (
	testKeyA = "00112233445566778899aabbccddeeff"
	testKeyB = "ffeeddccbbaa99887766554433221100"
	testKeyC = "0123456789abcdeffedcba9876543210"
)

func writeTestRegistry(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write registry: %v", err)
	}
}

func registryContent(entries ...string) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString("[[nodes]]\n")
		b.WriteString(e)
		b.WriteString("\n")
	}
	return b.String()
}

func TestRegistryHandlerReloadAddRemoveRotate(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	writeTestRegistry(t, regPath, registryContent(
		"id = \"node-a\"\nkey = \""+testKeyA+"\"",
		"id = \"node-b\"\nkey = \""+testKeyB+"\"",
	))
	swapper := &fakeSwapper{}
	h, err := NewRegistryHandler(regPath, 5, swapper)
	if err != nil {
		t.Fatalf("NewRegistryHandler: %v", err)
	}
	ctx := context.Background()

	// Reload loads the file and swaps the codec set.
	resp := h.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdReloadRegistry})
	if !resp.OK {
		t.Fatalf("reload: %v", resp.Error)
	}
	if got := swapper.currentIDs(); len(got) != 2 || got[0] != "node-a" || got[1] != "node-b" {
		t.Fatalf("ids after reload = %v", got)
	}

	// Add a node: in-memory set grows, codec set swaps.
	resp = h.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdAddNode, Args: map[string]string{"node_id": "node-c", "key": testKeyC}})
	if !resp.OK {
		t.Fatalf("add: %v", resp.Error)
	}
	if got := swapper.currentIDs(); len(got) != 3 || got[2] != "node-c" {
		t.Fatalf("ids after add = %v", got)
	}
	// Duplicate add refused, state untouched.
	resp = h.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdAddNode, Args: map[string]string{"node_id": "node-c", "key": testKeyC}})
	if resp.OK {
		t.Error("duplicate add must be refused")
	}
	if got := swapper.currentIDs(); len(got) != 3 {
		t.Fatalf("ids after refused duplicate = %v", got)
	}
	// Rotate: same ids, new codec for node-b (swap count grows).
	swapsBefore := swapper.swaps
	resp = h.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdRotateKey, Args: map[string]string{"node_id": "node-b", "key": testKeyC}})
	if !resp.OK {
		t.Fatalf("rotate: %v", resp.Error)
	}
	if swapper.swaps != swapsBefore+1 {
		t.Error("rotate must swap the codec set")
	}
	if got := swapper.currentIDs(); len(got) != 3 {
		t.Fatalf("ids after rotate = %v", got)
	}
	// Rotate unknown node refused.
	resp = h.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdRotateKey, Args: map[string]string{"node_id": "node-zzz", "key": testKeyC}})
	if resp.OK {
		t.Error("rotate of an unknown node must be refused")
	}
	// Remove node-a; removing the last two down to one is fine,
	// removing the final node is refused.
	resp = h.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdRemoveNode, Args: map[string]string{"node_id": "node-a"}})
	if !resp.OK {
		t.Fatalf("remove: %v", resp.Error)
	}
	resp = h.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdRemoveNode, Args: map[string]string{"node_id": "node-b"}})
	if !resp.OK {
		t.Fatalf("remove: %v", resp.Error)
	}
	resp = h.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdRemoveNode, Args: map[string]string{"node_id": "node-c"}})
	if resp.OK {
		t.Error("removing the last node must be refused")
	}
	if got := swapper.currentIDs(); len(got) != 1 || got[0] != "node-c" {
		t.Fatalf("ids after refused last-remove = %v", got)
	}
	// Reload re-reads the file: the file still lists node-a/node-b,
	// so memory reconciles back to the file (file is durable truth).
	resp = h.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdReloadRegistry})
	if !resp.OK {
		t.Fatalf("reload: %v", resp.Error)
	}
	if got := swapper.currentIDs(); len(got) != 2 || got[0] != "node-a" {
		t.Fatalf("ids after re-reload = %v, want file contents", got)
	}
}

func TestRegistryHandlerRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	writeTestRegistry(t, regPath, registryContent("id = \"node-a\"\nkey = \""+testKeyA+"\""))
	swapper := &fakeSwapper{}
	h, _ := NewRegistryHandler(regPath, 5, swapper)
	ctx := context.Background()

	cases := []struct {
		name string
		req  Request
	}{
		{"bad version", Request{Version: 99, Command: CmdPing}},
		{"unknown command", Request{Version: ProtocolVersion, Command: "explode"}},
		{"add missing key", Request{Version: ProtocolVersion, Command: CmdAddNode, Args: map[string]string{"node_id": "x"}}},
		{"add bad id", Request{Version: ProtocolVersion, Command: CmdAddNode, Args: map[string]string{"node_id": "bad id!", "key": testKeyA}}},
		{"remove missing id", Request{Version: ProtocolVersion, Command: CmdRemoveNode}},
		{"rotate missing key", Request{Version: ProtocolVersion, Command: CmdRotateKey, Args: map[string]string{"node_id": "node-a"}}},
	}
	for _, tc := range cases {
		if resp := h.Handle(ctx, tc.req); resp.OK {
			t.Errorf("%s: must be refused", tc.name)
		}
	}
	// A failed swap rolls the in-memory mutation back.
	h2, _ := NewRegistryHandler(regPath, 5, swapper)
	swapper.failSwap = true
	resp := h2.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdAddNode, Args: map[string]string{"node_id": "node-b", "key": testKeyB}})
	if resp.OK {
		t.Error("add must fail when the swap fails")
	}
	swapper.failSwap = false
	resp = h2.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdReloadRegistry})
	if !resp.OK {
		t.Fatalf("reload after failed add: %v", resp.Error)
	}
	// The rolled-back add must not have persisted in memory: the
	// reload shows only the file's node.
	if got := swapper.currentIDs(); len(got) != 1 || got[0] != "node-a" {
		t.Fatalf("ids after rollback+reload = %v", got)
	}
	// Missing registry file: reload fails, state untouched.
	h3, _ := NewRegistryHandler(filepath.Join(dir, "missing.toml"), 5, swapper)
	if resp := h3.Handle(ctx, Request{Version: ProtocolVersion, Command: CmdReloadRegistry}); resp.OK {
		t.Error("reload of a missing registry must fail")
	}
	// Constructor validation.
	if _, err := NewRegistryHandler("", 5, swapper); err == nil {
		t.Error("empty registry path must be refused")
	}
	if _, err := NewRegistryHandler(regPath, 2, swapper); err == nil {
		t.Error("legacy method must be refused")
	}
	if _, err := NewRegistryHandler(regPath, 5, nil); err == nil {
		t.Error("nil swapper must be refused")
	}
}

func TestRegistryHandlerListSessions(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	writeTestRegistry(t, regPath, registryContent("id = \"node-a\"\nkey = \""+testKeyA+"\""))
	created := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	swapper := &fakeSwapper{summaries: []SessionSummary{
		{SessionID: 7, NodeID: "node-a", UploadMTU: 104, DownloadMTU: 964, CreatedAt: created, LastActivity: created.Add(time.Minute), ActiveStreams: 2},
	}}
	h, _ := NewRegistryHandler(regPath, 5, swapper)
	resp := h.Handle(context.Background(), Request{Version: ProtocolVersion, Command: CmdListSessions})
	if !resp.OK {
		t.Fatalf("list-sessions: %v", resp.Error)
	}
	sessions, ok := resp.Data["sessions"].([]any)
	if !ok || len(sessions) != 1 {
		t.Fatalf("sessions = %#v", resp.Data["sessions"])
	}
	entry, _ := sessions[0].(map[string]any)
	if entry["node_id"] != "node-a" || entry["session_id"] != uint16(7) {
		t.Errorf("session entry = %v", entry)
	}
}

func startTestSocket(t *testing.T, handler Handler) (string, context.CancelFunc) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, handler) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = os.Remove(path)
	})
	return path, cancel
}

func TestControlSocketRoundTrip(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	writeTestRegistry(t, regPath, registryContent("id = \"node-a\"\nkey = \""+testKeyA+"\""))
	swapper := &fakeSwapper{}
	h, _ := NewRegistryHandler(regPath, 5, swapper)
	path, _ := startTestSocket(t, h)

	// Socket file is root-only.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %o, want 0600", info.Mode().Perm())
	}

	client := Client{SocketPath: path}
	ctx := context.Background()
	if err := client.ReloadRegistry(ctx); err != nil {
		t.Fatalf("ReloadRegistry: %v", err)
	}
	if got := swapper.currentIDs(); len(got) != 1 || got[0] != "node-a" {
		t.Fatalf("ids = %v", got)
	}
	if err := client.AddNode(ctx, "node-b", testKeyB); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if err := client.RotateKey(ctx, "node-a", testKeyC); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if err := client.RemoveNode(ctx, "node-b"); err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	// Server-side errors surface as client errors without key material.
	if err := client.AddNode(ctx, "node-a", testKeyB); err == nil {
		t.Error("duplicate add over the socket must fail")
	} else if strings.Contains(err.Error(), testKeyB) {
		t.Error("client error must never contain key material")
	}
	sessions, err := client.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("sessions = %v, want none", sessions)
	}
}

func TestControlSocketRejectsMalformed(t *testing.T) {
	swapper := &fakeSwapper{}
	h, _ := NewRegistryHandler(filepath.Join(t.TempDir(), "nodes.toml"), 5, swapper)
	path, _ := startTestSocket(t, h)

	dial := func(t *testing.T) net.Conn {
		t.Helper()
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return conn
	}
	readResp := func(t *testing.T, conn net.Conn) Response {
		t.Helper()
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var resp Response
		if err := json.Unmarshal(buf[:n], &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp
	}

	// Not JSON.
	conn := dial(t)
	_, _ = conn.Write([]byte("this is not json\n"))
	if resp := readResp(t, conn); resp.OK {
		t.Error("non-JSON request must fail")
	}
	_ = conn.Close()

	// Unknown field: closed protocol, fail loudly.
	conn = dial(t)
	_, _ = conn.Write([]byte(`{"version":1,"command":"ping","surprise":true}` + "\n"))
	if resp := readResp(t, conn); resp.OK {
		t.Error("unknown field must be rejected")
	}
	_ = conn.Close()

	// Wrong version over the wire.
	conn = dial(t)
	_, _ = conn.Write([]byte(`{"version":7,"command":"ping"}` + "\n"))
	if resp := readResp(t, conn); resp.OK {
		t.Error("wrong version must be rejected")
	}
	_ = conn.Close()

	// Unknown command over the wire.
	conn = dial(t)
	_, _ = conn.Write([]byte(`{"version":1,"command":"explode"}` + "\n"))
	if resp := readResp(t, conn); resp.OK {
		t.Error("unknown command must be rejected")
	}
	_ = conn.Close()
}

func TestControlSocketConcurrentClients(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	writeTestRegistry(t, regPath, registryContent("id = \"node-a\"\nkey = \""+testKeyA+"\""))
	swapper := &fakeSwapper{}
	h, _ := NewRegistryHandler(regPath, 5, swapper)
	path, _ := startTestSocket(t, h)
	client := Client{SocketPath: path}

	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := client.ReloadRegistry(context.Background()); err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := client.Call(context.Background(), Request{Command: CmdPing}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent client: %v", err)
	}
}

func TestListenRemovesStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale file: %v", err)
	}
	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen over a stale file: %v", err)
	}
	_ = listener.Close()
	if _, err := Listen(""); err == nil {
		t.Error("empty socket path must be refused")
	}
	// Dialing a missing socket fails cleanly.
	client := Client{SocketPath: filepath.Join(t.TempDir(), "missing.sock")}
	if err := client.ReloadRegistry(context.Background()); err == nil {
		t.Error("dialing a missing socket must fail")
	}
}
