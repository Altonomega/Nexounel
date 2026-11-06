package udpserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/control"
	"github.com/Altonomega/Nexounel/core/internal/security"
)

// TestControlSocketReloadsRegistryWithoutRestart is the end-to-end
// proof for D6 at the server level: the registry file is rewritten,
// the control socket reloads the codec set, new sessions attribute
// to the new keys, and a pre-existing session keeps the codec it
// was created with. No server restart, no dropped session state.
func TestControlSocketReloadsRegistryWithoutRestart(t *testing.T) {
	const (
		keyA = "00112233445566778899aabbccddeeff"
		keyB = "ffeeddccbbaa99887766554433221100"
		keyC = "0123456789abcdeffedcba9876543210"
	)
	codecA := mustTestCodec(t, keyA)

	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	write := func(content string) {
		if err := os.WriteFile(regPath, []byte(content), 0o600); err != nil {
			t.Fatalf("write registry: %v", err)
		}
	}
	write("[[nodes]]\nid = \"node-a\"\nkey = \"" + keyA + "\"\n")

	// Server with one live session under the old key.
	srv := &Server{sessions: newSessionStore(8, 32)}
	srv.installed.Store(&codecSet{codecs: []*security.Codec{codecA}})
	created := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	record := &sessionRecord{ID: 1, NodeID: "node-a", Codec: codecA, UploadMTU: 104, DownloadMTU: 964, CreatedAt: created}
	srv.sessions.mu.Lock()
	srv.sessions.byID[1] = record
	srv.sessions.activeIDs[1] = struct{}{}
	srv.sessions.liveByID[1].Store(record)
	srv.sessions.mu.Unlock()

	handler, err := control.NewRegistryHandler(regPath, 5, srv)
	if err != nil {
		t.Fatalf("NewRegistryHandler: %v", err)
	}
	socketPath := filepath.Join(dir, "control.sock")
	listener, err := control.Listen(socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- control.Serve(ctx, listener, handler) }()
	defer func() {
		cancel()
		<-serveErr
		_ = os.Remove(socketPath)
	}()

	client := control.Client{SocketPath: socketPath}
	// Baseline: the live session is visible with its node and MTUs.
	sessions, err := client.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].NodeID != "node-a" || sessions[0].UploadMTU != 104 || sessions[0].DownloadMTU != 964 {
		t.Fatalf("sessions = %+v", sessions)
	}

	// Rewrite the registry (node-b joins, node-a's key rotates) and
	// reload without restart.
	write("[[nodes]]\nid = \"node-a\"\nkey = \"" + keyC + "\"\n[[nodes]]\nid = \"node-b\"\nkey = \"" + keyB + "\"\n")
	if err := client.ReloadRegistry(ctx); err != nil {
		t.Fatalf("ReloadRegistry: %v", err)
	}
	// Attribution is by pointer identity on installed codecs, so
	// verify through the installed snapshot: order follows the
	// registry file, and each codec must decrypt what a codec built
	// from the same key encrypts (same derived AES key).
	codecB := mustTestCodec(t, keyB)
	codecC := mustTestCodec(t, keyC)
	snap := srv.codecSnapshot()
	if len(snap) != 2 {
		t.Fatalf("installed codecs = %d, want 2", len(snap))
	}
	if got := srv.nodeIDForCodec(snap[0]); got != "node-a" {
		t.Fatalf("snap[0] attribution: got %q, want node-a", got)
	}
	if got := srv.nodeIDForCodec(snap[1]); got != "node-b" {
		t.Fatalf("snap[1] attribution: got %q, want node-b", got)
	}
	decrypts := func(installed, peer *security.Codec) bool {
		ciphertext, err := peer.Encrypt([]byte("ping"))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		_, err = installed.Decrypt(ciphertext)
		return err == nil
	}
	if !decrypts(snap[0], codecC) || decrypts(snap[0], codecB) {
		t.Error("snap[0] must carry node-a's new key (keyC), not node-b's")
	}
	if !decrypts(snap[1], codecB) || decrypts(snap[1], codecC) {
		t.Error("snap[1] must carry node-b's key (keyB), not node-a's")
	}
	if got := srv.nodeIDForCodec(codecA); got != "" {
		t.Fatalf("old key after reload: got %q, want empty", got)
	}
	// The pre-existing session is untouched: same record, same codec.
	if record.Codec != codecA {
		t.Error("reload must not rewrite in-flight session codecs")
	}
	sessions, err = client.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions after reload: %v", err)
	}
	if len(sessions) != 1 || sessions[0].NodeID != "node-a" {
		t.Fatalf("sessions after reload = %+v", sessions)
	}

	// Socket-driven rotation: the panel's key-rotation path.
	if err := client.RotateKey(ctx, "node-b", keyC); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	snap = srv.codecSnapshot()
	if len(snap) != 2 {
		t.Fatalf("installed codecs after rotation = %d, want 2", len(snap))
	}
	if got := srv.nodeIDForCodec(snap[1]); got != "node-b" {
		t.Fatalf("snap[1] attribution after rotation: got %q, want node-b", got)
	}
	if !decrypts(snap[1], codecC) || decrypts(snap[1], codecB) {
		t.Error("snap[1] must carry node-b's rotated key (keyC) after rotation")
	}
}
