// Peer control ports (Phase 3 spec §8.3): node-to-node control
// endpoints for chief coordination. A mesh-private TCP listener on
// the node's primary address, speaking length-prefixed JSON
// envelopes. Every message is HMAC-authenticated with the mesh
// control secret (delivered at enrollment, distinct from the
// data-plane key, never used for data-plane sessions) and carries
// a monotonic per-peer sequence plus a timestamp inside a 5-minute
// skew window, so replays are rejected. The port rate-limits
// aggressively, logs auth failures (throttled), and accepts no
// unauthenticated command: the only unauthenticated response is
// silence — a failed handshake gets a closed connection, never an
// error frame to probe against.
//
// The trust boundary is the same as the spec's snapshot note: the
// secret is shared by every enrolled node, so a compromised node
// could forge peer messages. The blast radius is bounded by what
// peer messages can do: report reachability and announce
// mother-signed snapshots (which the receiver still verifies
// against its own snapshot key — without one, announcements are
// refused). Peer traffic never touches the data plane.
package peercontrol

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/mesh"
	"github.com/Altonomega/Nexounel/core/internal/multisession"
)

// ProtocolVersion is the only peer-control framing version.
const ProtocolVersion = 1

// MaxFrameBytes bounds one peer frame. Peer traffic is tiny
// (pings, announcements); the bound caps allocation per frame.
const MaxFrameBytes = 64 * 1024

// MaxClockSkew bounds acceptable timestamp drift between peers:
// 5 minutes, per the spec. Wider would admit stale replays.
const MaxClockSkew = 5 * time.Minute

// MaxMessagesPerConn bounds one connection's lifetime: peer
// exchanges are short (a probe, an announcement), and a peer
// holding a connection open for hundreds of messages is either
// broken or abusive.
const MaxMessagesPerConn = 32

// MaxConcurrentConns bounds simultaneous peer connections.
const MaxConcurrentConns = 16

// maxConnsPerMinutePerIP is the aggressive per-source rate limit:
// 10 connections per minute from one IP. Peers probe on a 30 s
// cadence, so legitimate traffic never approaches it.
const maxConnsPerMinutePerIP = 10

// MinSecretBytes is the shortest acceptable mesh control secret.
// Shorter secrets are a misconfiguration and are refused rather
// than used.
const MinSecretBytes = 16

// Kind names one peer message kind.
type Kind string

const (
	// KindPing: reachability probe. The pong echoes the nonce.
	KindPing Kind = "ping"
	// KindPong: ping reply.
	KindPong Kind = "pong"
	// KindAnnounce: an election announcement carrying a signed
	// membership snapshot.
	KindAnnounce Kind = "announce"
	// KindAck: the reply to an announcement.
	KindAck Kind = "ack"
)

var validKinds = map[Kind]bool{
	KindPing:     true,
	KindPong:     true,
	KindAnnounce: true,
	KindAck:      true,
}

// Envelope is one peer frame. MAC covers every other field; it is
// computed over the canonical struct encoding (fixed field order),
// never over the raw bytes, so encode/decode round-trips verify.
type Envelope struct {
	Version int             `json:"version"`
	Kind    Kind            `json:"kind"`
	From    string          `json:"from"`
	Seq     uint64          `json:"seq"`
	SentAt  time.Time       `json:"sent_at"`
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}

// macInput is the MAC preimage: the envelope without its MAC.
type macInput struct {
	Version int             `json:"version"`
	Kind    Kind            `json:"kind"`
	From    string          `json:"from"`
	Seq     uint64          `json:"seq"`
	SentAt  time.Time       `json:"sent_at"`
	Payload json.RawMessage `json:"payload"`
}

func computeMAC(secret []byte, env Envelope) string {
	body, _ := json.Marshal(macInput{
		Version: env.Version,
		Kind:    env.Kind,
		From:    env.From,
		Seq:     env.Seq,
		SentAt:  env.SentAt,
		Payload: env.Payload,
	})
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// sign fills env.MAC. The caller sets every other field.
func sign(secret []byte, env *Envelope) {
	env.MAC = computeMAC(secret, *env)
}

// verifyMAC reports whether env.MAC authenticates env under secret.
// It is constant-time in the comparison; a malformed MAC decodes
// to nothing and fails closed.
func verifyMAC(secret []byte, env Envelope) bool {
	want, err := hex.DecodeString(env.MAC)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	body, _ := json.Marshal(macInput{
		Version: env.Version,
		Kind:    env.Kind,
		From:    env.From,
		Seq:     env.Seq,
		SentAt:  env.SentAt,
		Payload: env.Payload,
	})
	mac.Write(body)
	return hmac.Equal(want, mac.Sum(nil))
}

// writeFrame writes one signed envelope, length-prefixed.
func writeFrame(w io.Writer, env Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if len(body) > MaxFrameBytes {
		return fmt.Errorf("peer frame of %d bytes exceeds %d-byte limit", len(body), MaxFrameBytes)
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(body)))
	copy(buf[4:], body)
	_, err = w.Write(buf)
	return err
}

// readFrame reads one length-prefixed envelope. A clean EOF while
// reading the length prefix returns io.EOF.
func readFrame(r io.Reader) (Envelope, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.EOF {
			return Envelope{}, io.EOF
		}
		return Envelope{}, fmt.Errorf("read peer frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrameBytes {
		return Envelope{}, fmt.Errorf("peer frame length %d out of bounds (1..%d)", n, MaxFrameBytes)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Envelope{}, fmt.Errorf("read peer frame body: %w", err)
	}
	var env Envelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return Envelope{}, fmt.Errorf("decode peer envelope: %w", err)
	}
	return env, nil
}

// seqSource hands out monotonic sequence numbers. The base is the
// current wall time in milliseconds, so a restarted process (whose
// counter resets) still issues larger sequences than any it issued
// before the restart, as long as the clock moved forward — which
// it does except in the sub-millisecond restart corner, where a
// few rejected messages are the bounded cost.
type seqSource struct {
	mu      sync.Mutex
	base    int64
	counter uint64
}

func (s *seqSource) next() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixMilli()
	if now > s.base {
		s.base = now
		s.counter = 0
	}
	s.counter++
	return uint64(s.base)<<20 | (s.counter & 0xFFFFF)
}

// replayWindow is the per-peer monotonic-sequence check. A message
// is accepted only when its timestamp is inside the skew window
// and its sequence is strictly greater than the last accepted one
// from the same peer. The first message from a peer is always
// accepted (there is nothing to replay against yet).
type replayWindow struct {
	mu    sync.Mutex
	peers map[string]*replayState
}

type replayState struct {
	lastSeq  uint64
	lastSeen time.Time
}

func newReplayWindow() *replayWindow {
	return &replayWindow{peers: make(map[string]*replayState)}
}

func (w *replayWindow) check(from string, seq uint64, sentAt, now time.Time) error {
	if sentAt.After(now.Add(MaxClockSkew)) || sentAt.Before(now.Add(-MaxClockSkew)) {
		return errors.New("peer frame timestamp outside the 5-minute skew window")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	st, ok := w.peers[from]
	if !ok {
		if len(w.peers) >= 1024 {
			w.pruneLocked(now)
		}
		w.peers[from] = &replayState{lastSeq: seq, lastSeen: now}
		return nil
	}
	if seq <= st.lastSeq {
		return fmt.Errorf("peer frame sequence %d replays last accepted %d from %q", seq, st.lastSeq, from)
	}
	st.lastSeq = seq
	st.lastSeen = now
	return nil
}

// pruneLocked drops peers unseen for over an hour. Callers hold mu.
func (w *replayWindow) pruneLocked(now time.Time) {
	for id, st := range w.peers {
		if now.Sub(st.lastSeen) > time.Hour {
			delete(w.peers, id)
		}
	}
}

// connLimiter is the aggressive per-source connection rate limit.
type connLimiter struct {
	mu       sync.Mutex
	perIP    map[string]*ipBucket
	inFlight int
}

type ipBucket struct {
	windowStart time.Time
	count       int
}

func newConnLimiter() *connLimiter {
	return &connLimiter{perIP: make(map[string]*ipBucket)}
}

// allowConnection admits one connection from ip, enforcing the
// per-IP rate and the global concurrency cap. It returns false
// when the connection must be refused silently.
func (l *connLimiter) allowConnection(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inFlight >= MaxConcurrentConns {
		return false
	}
	b, ok := l.perIP[ip]
	if !ok || now.Sub(b.windowStart) >= time.Minute {
		l.perIP[ip] = &ipBucket{windowStart: now, count: 1}
	} else {
		if b.count >= maxConnsPerMinutePerIP {
			return false
		}
		b.count++
	}
	l.inFlight++
	return true
}

func (l *connLimiter) releaseConnection() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inFlight > 0 {
		l.inFlight--
	}
}

// PingPayload is a reachability probe. The nonce binds the pong to
// this probe: a replayed pong from an earlier exchange carries
// the wrong nonce and is rejected.
type PingPayload struct {
	Nonce string `json:"nonce"`
}

// PongPayload echoes the ping's nonce.
type PongPayload struct {
	Nonce string `json:"nonce"`
}

// AnnouncePayload carries a mother-signed membership snapshot for
// the receiver to verify against its own snapshot key.
type AnnouncePayload struct {
	Snapshot mesh.Snapshot `json:"snapshot"`
}

// AckPayload answers an announcement.
type AckPayload struct {
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

// Handler serves authenticated peer messages. HandlePing always
// earns a pong; HandleAnnounce reports whether the snapshot was
// accepted (verified and recorded) and why not.
type Handler interface {
	HandlePing(ctx context.Context, from string) error
	HandleAnnounce(ctx context.Context, from string, snap mesh.Snapshot) (accepted bool, reason string)
}

// Server is one peer control listener. The zero value is unusable:
// use NewServer.
type Server struct {
	secret  []byte
	handler Handler
	replay  *replayWindow
	limiter *connLimiter
	seq     *seqSource
	// nodeID is this node's id, used as the From of replies. It is
	// set with SetNodeID; replies are refused (silently, by
	// closing) until it is set, rather than sent anonymously.
	nodeID string
	// logf, when set, receives auth-failure and refusal logs
	// (throttled to one line per source per minute). Nil silences
	// them; the silence is about logs, never about responses.
	logf func(format string, args ...any)

	authLogMu sync.Mutex
	authLogAt map[string]time.Time
}

// NewServer builds a peer control server. Secrets shorter than
// MinSecretBytes are refused: a weak secret is worse than no
// listener, because it invites a false sense of authentication.
func NewServer(secret []byte, handler Handler, logf func(format string, args ...any)) (*Server, error) {
	if len(secret) < MinSecretBytes {
		return nil, fmt.Errorf("mesh control secret is %d bytes, want at least %d", len(secret), MinSecretBytes)
	}
	if handler == nil {
		return nil, errors.New("peer control server requires a handler")
	}
	return &Server{
		secret:    append([]byte(nil), secret...),
		handler:   handler,
		replay:    newReplayWindow(),
		limiter:   newConnLimiter(),
		seq:       &seqSource{},
		logf:      logf,
		authLogAt: make(map[string]time.Time),
	}, nil
}

// logAuthFailure logs an authentication refusal, throttled to one
// line per source per minute so a flood cannot fill the log.
func (s *Server) logAuthFailure(source, reason string) {
	if s.logf == nil {
		return
	}
	now := time.Now()
	s.authLogMu.Lock()
	last, ok := s.authLogAt[source]
	if !ok || now.Sub(last) >= time.Minute {
		s.authLogAt[source] = now
		s.authLogMu.Unlock()
		s.logf("peer control: auth failure from %s: %s", source, reason)
		return
	}
	s.authLogMu.Unlock()
}

// Serve accepts connections on ln until ctx ends. It owns the
// listener's lifetime only through ctx: closing the listener on
// ctx end unblocks Accept, in-flight connections drain, and Serve
// returns.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-done:
		}
	}()
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			return fmt.Errorf("peer control accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serveConn(ctx, conn)
		}()
	}
}

// serveConn serves one connection: authenticate every frame, then
// dispatch. Any failure closes the connection silently — no error
// frame, no hint about which check failed.
func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remote)
	if ip == "" {
		ip = remote
	}
	if !s.limiter.allowConnection(ip, time.Now()) {
		s.logAuthFailure(ip, "rate-limited")
		return
	}
	defer s.limiter.releaseConnection()
	for i := 0; i < MaxMessagesPerConn; i++ {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		env, err := readFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logAuthFailure(ip, fmt.Sprintf("unreadable frame: %v", err))
			}
			return
		}
		if err := s.authenticate(env); err != nil {
			s.logAuthFailure(ip, err.Error())
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		switch env.Kind {
		case KindPing:
			var ping PingPayload
			if err := json.Unmarshal(env.Payload, &ping); err != nil {
				s.logAuthFailure(ip, "malformed ping payload")
				return
			}
			if err := s.handler.HandlePing(ctx, env.From); err != nil {
				s.logAuthFailure(ip, fmt.Sprintf("ping handler: %v", err))
			}
			if err := s.reply(conn, KindPong, PongPayload{Nonce: ping.Nonce}); err != nil {
				return
			}
		case KindAnnounce:
			var ann AnnouncePayload
			if err := json.Unmarshal(env.Payload, &ann); err != nil {
				s.logAuthFailure(ip, "malformed announce payload")
				return
			}
			accepted, reason := s.handler.HandleAnnounce(ctx, env.From, ann.Snapshot)
			if err := s.reply(conn, KindAck, AckPayload{Accepted: accepted, Reason: reason}); err != nil {
				return
			}
		default:
			// Authenticated but unknown: ignored, never acted
			// on, never answered. Forward-compatibility
			// without an oracle.
			if s.logf != nil {
				s.logf("peer control: unknown authenticated kind %q from %q ignored", env.Kind, env.From)
			}
		}
	}
}

// authenticate validates one envelope: version, kind, sender,
// MAC, and replay window. The first failure ends the connection;
// the caller logs it (throttled) and stays silent.
func (s *Server) authenticate(env Envelope) error {
	if env.Version != ProtocolVersion {
		return fmt.Errorf("unsupported peer protocol version %d", env.Version)
	}
	if !validKinds[env.Kind] {
		return fmt.Errorf("unknown peer frame kind %q", env.Kind)
	}
	if err := multisession.ValidateNodeID(env.From); err != nil {
		return fmt.Errorf("invalid peer id: %w", err)
	}
	if !verifyMAC(s.secret, env) {
		return errors.New("peer frame MAC verification failed")
	}
	if err := s.replay.check(env.From, env.Seq, env.SentAt, time.Now()); err != nil {
		return err
	}
	return nil
}

// reply writes one signed envelope to the peer, naming this node
// as the sender. When the node id is unset the reply is refused:
// an anonymous reply authenticates nothing and teaches a prober
// that the port answers.
func (s *Server) reply(conn net.Conn, kind Kind, payload any) error {
	if s.nodeID == "" {
		return errors.New("peer server node id is unset")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	env := Envelope{
		Version: ProtocolVersion,
		Kind:    kind,
		From:    s.nodeID,
		Seq:     s.seq.next(),
		SentAt:  time.Now().UTC(),
		Payload: body,
	}
	sign(s.secret, &env)
	return writeFrame(conn, env)
}

// Client probes peers and announces snapshots. It holds the same
// secret as the server side; both directions authenticate.
type Client struct {
	secret []byte
	nodeID string
	seq    *seqSource
	// DialTimeout bounds the TCP connect; ExchangeTimeout bounds
	// the ping/pong (or announce/ack) exchange.
	DialTimeout     time.Duration
	ExchangeTimeout time.Duration
}

// NewClient builds a peer client. The nodeID is this node's id:
// it names the sender of every frame.
func NewClient(secret []byte, nodeID string) (*Client, error) {
	if len(secret) < MinSecretBytes {
		return nil, fmt.Errorf("mesh control secret is %d bytes, want at least %d", len(secret), MinSecretBytes)
	}
	if err := multisession.ValidateNodeID(nodeID); err != nil {
		return nil, fmt.Errorf("peer client node id: %w", err)
	}
	return &Client{
		secret:          append([]byte(nil), secret...),
		nodeID:          nodeID,
		seq:             &seqSource{},
		DialTimeout:     5 * time.Second,
		ExchangeTimeout: 10 * time.Second,
	}, nil
}

// sendFrame signs and writes one envelope, then (when wantReply)
// reads and authenticates the reply. The caller decodes the reply
// payload.
func (c *Client) exchange(ctx context.Context, addr string, kind Kind, payload any) (Envelope, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	env := Envelope{
		Version: ProtocolVersion,
		Kind:    kind,
		From:    c.nodeID,
		Seq:     c.seq.next(),
		SentAt:  time.Now().UTC(),
		Payload: body,
	}
	sign(c.secret, &env)
	dialer := net.Dialer{Timeout: c.DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Envelope{}, fmt.Errorf("dial peer %s: %w", addr, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(c.ExchangeTimeout)
	_ = conn.SetDeadline(deadline)
	if err := writeFrame(conn, env); err != nil {
		return Envelope{}, fmt.Errorf("write peer frame: %w", err)
	}
	reply, err := readFrame(conn)
	if err != nil {
		return Envelope{}, fmt.Errorf("read peer reply: %w", err)
	}
	if err := c.authenticateReply(reply); err != nil {
		return Envelope{}, err
	}
	return reply, nil
}

// authenticateReply validates a reply envelope: version, MAC, and
// sender identity (a well-formed node id; the exact peer is
// pinned by the caller through the nonce/payload checks).
func (c *Client) authenticateReply(env Envelope) error {
	if env.Version != ProtocolVersion {
		return fmt.Errorf("unsupported peer protocol version %d", env.Version)
	}
	if !validKinds[env.Kind] {
		return fmt.Errorf("unknown peer reply kind %q", env.Kind)
	}
	if err := multisession.ValidateNodeID(env.From); err != nil {
		return fmt.Errorf("invalid peer reply id: %w", err)
	}
	if !verifyMAC(c.secret, env) {
		return errors.New("peer reply MAC verification failed")
	}
	return nil
}

// Probe measures one peer's reachability: ping → pong with a
// fresh nonce. It returns the round-trip time. Any failure —
// dial, silence, bad MAC, wrong nonce — is an error: the peer is
// unreachable as far as this node can tell.
func (c *Client) Probe(ctx context.Context, addr string) (time.Duration, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, fmt.Errorf("peer probe nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce[:])
	start := time.Now()
	reply, err := c.exchange(ctx, addr, KindPing, PingPayload{Nonce: nonceHex})
	if err != nil {
		return 0, err
	}
	if reply.Kind != KindPong {
		return 0, fmt.Errorf("peer probe: want pong, got %q", reply.Kind)
	}
	var pong PongPayload
	if err := json.Unmarshal(reply.Payload, &pong); err != nil {
		return 0, fmt.Errorf("peer probe: malformed pong: %w", err)
	}
	if pong.Nonce != nonceHex {
		return 0, errors.New("peer probe: pong nonce mismatch (replayed or misrouted reply)")
	}
	return time.Since(start), nil
}

// Announce delivers one signed snapshot to a peer and reports
// whether the peer accepted it. The peer verifies the snapshot
// against its own snapshot key; a refusal is data, not an error.
func (c *Client) Announce(ctx context.Context, addr string, snap mesh.Snapshot) (bool, string, error) {
	reply, err := c.exchange(ctx, addr, KindAnnounce, AnnouncePayload{Snapshot: snap})
	if err != nil {
		return false, "", err
	}
	if reply.Kind != KindAck {
		return false, "", fmt.Errorf("peer announce: want ack, got %q", reply.Kind)
	}
	var ack AckPayload
	if err := json.Unmarshal(reply.Payload, &ack); err != nil {
		return false, "", fmt.Errorf("peer announce: malformed ack: %w", err)
	}
	return ack.Accepted, ack.Reason, nil
}

// SetNodeID sets the id the server names as the sender of its
// replies. It must be called before Serve starts; it is not safe
// for concurrent use with Serve.
func (s *Server) SetNodeID(id string) { s.nodeID = id }
