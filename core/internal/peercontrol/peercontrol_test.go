package peercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/mesh"
)

var testSecret = []byte("test-mesh-control-secret-32-bytes!")

type stubHandler struct {
	pings     []string
	announces []mesh.Snapshot
	accept    bool
	reason    string
}

func (h *stubHandler) HandlePing(_ context.Context, from string) error {
	h.pings = append(h.pings, from)
	return nil
}

func (h *stubHandler) HandleAnnounce(_ context.Context, from string, snap mesh.Snapshot) (bool, string) {
	h.announces = append(h.announces, snap)
	return h.accept, h.reason
}

func testEnvelope(t *testing.T, kind Kind, from string, payload any) Envelope {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return Envelope{Version: ProtocolVersion, Kind: kind, From: from, Seq: 1, SentAt: time.Now().UTC(), Payload: body}
}

func TestMACRoundTripAndTamper(t *testing.T) {
	env := testEnvelope(t, KindPing, "node-1", PingPayload{Nonce: "abc"})
	sign(testSecret, &env)
	if !verifyMAC(testSecret, env) {
		t.Fatal("signed envelope must verify")
	}
	// Tampering with any covered field breaks the MAC.
	for _, mutate := range []func(*Envelope){
		func(e *Envelope) { e.Kind = KindPong },
		func(e *Envelope) { e.From = "node-2" },
		func(e *Envelope) { e.Seq = 2 },
		func(e *Envelope) { e.Payload = json.RawMessage(`{"nonce":"xyz"}`) },
		func(e *Envelope) { e.SentAt = e.SentAt.Add(time.Hour) },
	} {
		dup := env
		mutate(&dup)
		if verifyMAC(testSecret, dup) {
			t.Errorf("tampered envelope verified: %+v", dup)
		}
	}
	// A different secret fails.
	if verifyMAC([]byte("another-mesh-control-secret-!"), env) {
		t.Error("wrong secret must not verify")
	}
	// A malformed MAC fails closed.
	dup := env
	dup.MAC = "not-hex!!"
	if verifyMAC(testSecret, dup) {
		t.Error("malformed MAC must not verify")
	}
}

func TestSeqSourceMonotonic(t *testing.T) {
	s := &seqSource{}
	prev := s.next()
	for i := 0; i < 1000; i++ {
		next := s.next()
		if next <= prev {
			t.Fatalf("seq %d followed %d", next, prev)
		}
		prev = next
	}
}

func TestReplayWindow(t *testing.T) {
	w := newReplayWindow()
	now := time.Now()
	// First sighting accepted.
	if err := w.check("node-1", 10, now, now); err != nil {
		t.Fatalf("first sighting: %v", err)
	}
	// Equal and older sequences replay.
	if err := w.check("node-1", 10, now, now); err == nil {
		t.Error("equal sequence must replay-reject")
	}
	if err := w.check("node-1", 9, now, now); err == nil {
		t.Error("older sequence must replay-reject")
	}
	// A newer sequence passes.
	if err := w.check("node-1", 11, now, now); err != nil {
		t.Fatalf("newer sequence: %v", err)
	}
	// A different peer has its own window.
	if err := w.check("node-2", 1, now, now); err != nil {
		t.Fatalf("other peer: %v", err)
	}
	// Skew both ways rejected, without poisoning the window.
	if err := w.check("node-1", 12, now.Add(6*time.Minute), now); err == nil {
		t.Error("future timestamp beyond skew must be rejected")
	}
	if err := w.check("node-1", 12, now.Add(-6*time.Minute), now); err == nil {
		t.Error("stale timestamp beyond skew must be rejected")
	}
	if err := w.check("node-1", 12, now, now); err != nil {
		t.Fatalf("rejected-skew sequence must still be usable: %v", err)
	}
	// Inside the skew window passes.
	if err := w.check("node-1", 13, now.Add(4*time.Minute), now); err != nil {
		t.Fatalf("in-skew timestamp: %v", err)
	}
}

func TestConnLimiter(t *testing.T) {
	l := newConnLimiter()
	now := time.Now()
	for i := 0; i < maxConnsPerMinutePerIP; i++ {
		if !l.allowConnection("203.0.113.7", now) {
			t.Fatalf("connection %d must be allowed", i+1)
		}
		l.releaseConnection()
	}
	if l.allowConnection("203.0.113.7", now) {
		t.Error("11th connection in a minute must be refused")
	}
	// A new window re-admits.
	if !l.allowConnection("203.0.113.7", now.Add(61*time.Second)) {
		t.Error("a new minute window must re-admit")
	}
	l.releaseConnection()
	// Concurrency cap: fill it without releasing.
	for i := 0; i < MaxConcurrentConns; i++ {
		if !l.allowConnection(fmt.Sprintf("10.0.0.%d", i), now) {
			t.Fatalf("connection %d must be allowed", i+1)
		}
	}
	if l.allowConnection("10.9.9.9", now) {
		t.Error("connection past the concurrency cap must be refused")
	}
}

func TestNewServerRefusesShortSecret(t *testing.T) {
	if _, err := NewServer([]byte("short"), &stubHandler{}, nil); err == nil {
		t.Fatal("short secret must be refused")
	}
	if _, err := NewServer(nil, &stubHandler{}, nil); err == nil {
		t.Fatal("empty secret must be refused")
	}
	if _, err := NewServer(testSecret, nil, nil); err == nil {
		t.Fatal("nil handler must be refused")
	}
	if _, err := NewClient([]byte("short"), "node-1"); err == nil {
		t.Fatal("client must refuse a short secret")
	}
	if _, err := NewClient(testSecret, "BAD ID"); err == nil {
		t.Fatal("client must refuse an invalid node id")
	}
}

func servePipe(t *testing.T, srv *Server, handlerEnd net.Conn) chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.serveConn(context.Background(), handlerEnd)
	}()
	return done
}

// TestServerSilenceOnBadMAC proves the unauthenticated response is
// silence: a bad MAC gets a closed connection and zero reply bytes.
func TestServerSilenceOnBadMAC(t *testing.T) {
	srv, err := NewServer(testSecret, &stubHandler{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetNodeID("node-1")
	clientEnd, handlerEnd := net.Pipe()
	defer clientEnd.Close()
	done := servePipe(t, srv, handlerEnd)
	env := testEnvelope(t, KindPing, "node-2", PingPayload{Nonce: "n"})
	sign([]byte("wrong-mesh-control-secret-32b!"), &env)
	if err := writeFrame(clientEnd, env); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	_ = clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := readFrame(clientEnd); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF (silence + close), got %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit after the bad frame")
	}
}

// TestServerSilenceOnReplay proves a replayed frame is met with
// silence, not an error.
func TestServerSilenceOnReplay(t *testing.T) {
	srv, _ := NewServer(testSecret, &stubHandler{}, nil)
	srv.SetNodeID("node-1")
	clientEnd, handlerEnd := net.Pipe()
	defer clientEnd.Close()
	done := servePipe(t, srv, handlerEnd)
	_ = clientEnd.SetDeadline(time.Now().Add(5 * time.Second))
	env := testEnvelope(t, KindPing, "node-2", PingPayload{Nonce: "n1"})
	env.Seq = 7
	sign(testSecret, &env)
	if err := writeFrame(clientEnd, env); err != nil {
		t.Fatal(err)
	}
	// The first ping earns a pong.
	reply, err := readFrame(clientEnd)
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if reply.Kind != KindPong {
		t.Fatalf("kind = %q, want pong", reply.Kind)
	}
	// The identical frame replayed: silence + close.
	if err := writeFrame(clientEnd, env); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(clientEnd); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after replay, got %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit after the replay")
	}
}

func TestServerClosesAfterMessageCap(t *testing.T) {
	srv, _ := NewServer(testSecret, &stubHandler{}, nil)
	srv.SetNodeID("node-1")
	clientEnd, handlerEnd := net.Pipe()
	defer clientEnd.Close()
	done := servePipe(t, srv, handlerEnd)
	_ = clientEnd.SetDeadline(time.Now().Add(10 * time.Second))
	seq := &seqSource{}
	for i := 0; i < MaxMessagesPerConn; i++ {
		env := testEnvelope(t, KindPing, "node-2", PingPayload{Nonce: "n"})
		env.Seq = seq.next()
		sign(testSecret, &env)
		if err := writeFrame(clientEnd, env); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if _, err := readFrame(clientEnd); err != nil {
			t.Fatalf("read pong %d: %v", i, err)
		}
	}
	// The 33rd message is never answered: the connection is closed.
	env := testEnvelope(t, KindPing, "node-2", PingPayload{Nonce: "n"})
	env.Seq = seq.next()
	sign(testSecret, &env)
	_ = writeFrame(clientEnd, env)
	if _, err := readFrame(clientEnd); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after the message cap, got %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit after the cap")
	}
}

func TestServerRefusesReplyWithoutNodeID(t *testing.T) {
	srv, _ := NewServer(testSecret, &stubHandler{}, nil)
	// No SetNodeID: the handler cannot reply, so the ping goes
	// unanswered and the connection ends.
	clientEnd, handlerEnd := net.Pipe()
	defer clientEnd.Close()
	done := servePipe(t, srv, handlerEnd)
	_ = clientEnd.SetDeadline(time.Now().Add(5 * time.Second))
	env := testEnvelope(t, KindPing, "node-2", PingPayload{Nonce: "n"})
	sign(testSecret, &env)
	if err := writeFrame(clientEnd, env); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(clientEnd); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit")
	}
}

// TestProbeAndAnnounceOverLoopback exercises the full stack —
// listener, dial, ping/pong with nonce binding, announce/ack —
// over real TCP loopback.
func TestProbeAndAnnounceOverLoopback(t *testing.T) {
	handler := &stubHandler{accept: true}
	srv, err := NewServer(testSecret, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetNodeID("node-1")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx, ln) }()
	client, err := NewClient(testSecret, "node-2")
	if err != nil {
		t.Fatal(err)
	}
	rtt, err := client.Probe(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if rtt <= 0 || rtt > 5*time.Second {
		t.Errorf("rtt = %v", rtt)
	}
	if len(handler.pings) != 1 || handler.pings[0] != "node-2" {
		t.Errorf("pings = %v", handler.pings)
	}
	snap, err := mesh.SignSnapshot(mesh.Table{Term: mesh.Term{Number: 3}, Version: 1, ChiefID: "node-1"}, []byte("snapshot-key"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, reason, err := client.Announce(ctx, ln.Addr().String(), snap)
	if err != nil {
		t.Fatalf("Announce: %v", err)
	}
	if !accepted || reason != "" {
		t.Errorf("announce accepted=%v reason=%q", accepted, reason)
	}
	if len(handler.announces) != 1 || !handler.announces[0].Table.Term.IsZero() && handler.announces[0].Table.Term.Number != 3 {
		t.Errorf("announces = %+v", handler.announces)
	}
	// A wrong secret gets silence: the probe fails, never an
	// application error from the server.
	bad, _ := NewClient([]byte("wrong-mesh-control-secret-32b!"), "node-2")
	if _, err := bad.Probe(ctx, ln.Addr().String()); err == nil {
		t.Error("probe with a wrong secret must fail")
	}
	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

func TestProbeRefusesNonceMismatch(t *testing.T) {
	// A server that answers pings with a wrong nonce: the client
	// must reject the reply.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		env, err := readFrame(conn)
		if err != nil {
			return
		}
		reply := Envelope{Version: ProtocolVersion, Kind: KindPong, From: "node-1", Seq: 1, SentAt: time.Now().UTC(), Payload: mustJSON(PongPayload{Nonce: "wrong"})}
		_ = env
		sign(testSecret, &reply)
		_ = writeFrame(conn, reply)
	}()
	client, _ := NewClient(testSecret, "node-2")
	if _, err := client.Probe(context.Background(), ln.Addr().String()); err == nil {
		t.Fatal("a pong with the wrong nonce must be rejected")
	} else if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("error = %v, want a nonce error", err)
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
