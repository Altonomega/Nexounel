// Package control implements the mother control plane's registry
// control socket (§4.1): a root-only Unix-domain socket on the server
// host through which the panel reloads the node registry, adds,
// removes, and rotates nodes, and lists sessions — all without
// restarting the server process.
//
// Protocol: newline-delimited JSON (NDJSON), versioned. One request
// per line, one response per line, then the connection closes. The
// socket is created with mode 0600: filesystem permissions are the
// authentication, exactly as for the registry file itself — only
// root on the mother host can connect, and the panel runs as root.
// There is no network exposure and no separate credential.
//
// Ordering contract with the panel (the panel remains the writer of
// the registry file): the panel writes the registry file FIRST, then
// issues the socket command. reload-registry re-reads the file and
// reconciles in-memory state with it; add-node/remove-node/rotate-key
// update the in-memory codec set directly (no file round-trip) for
// the case where the panel has already written the file and only
// needs the running server to catch up. A restart always loads the
// file, so the file is the durable truth and memory is a cache of it.
//
// In-flight sessions are never disturbed by a reload: sessions hold
// their codec directly, so swapping the codec set affects only
// sessions established afterwards (rotate-key semantics: old
// sessions drain naturally, new sessions require the new key).
package control

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/mesh"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
	"github.com/MNSH-Nexo/Nexounel/core/internal/security"
)

// ProtocolVersion is the only supported control-protocol version.
const ProtocolVersion = 1

// Commands.
const (
	// CmdPing verifies the socket answers; it touches no state.
	CmdPing = "ping"
	// CmdReloadRegistry re-reads the registry file and atomically
	// swaps the in-memory codec set.
	CmdReloadRegistry = "reload-registry"
	// CmdAddNode inserts one node into the in-memory codec set.
	CmdAddNode = "add-node"
	// CmdRemoveNode removes one node from the in-memory codec set.
	CmdRemoveNode = "remove-node"
	// CmdRotateKey replaces one node's in-memory codec.
	CmdRotateKey = "rotate-key"
	// CmdListSessions returns per-node session summaries.
	CmdListSessions = "list-sessions"
	// CmdListMesh returns the mesh membership table plus the last
	// heartbeat per member, for the panel mesh view.
	CmdListMesh = "list-mesh"
	// CmdAddBootstrapKey installs a pending bootstrap key (derived
	// from a join token) so the server can trial-decrypt bootstrap
	// sessions. The key is single-purpose and expires with the token.
	CmdAddBootstrapKey = "add-bootstrap-key"
	// CmdRemoveBootstrapKey drops a pending bootstrap key (token
	// consumed, revoked, or expired).
	CmdRemoveBootstrapKey = "remove-bootstrap-key"
)

// Request is one control-socket request. Args carries command
// arguments: node_id, key, as applicable. Unknown fields are
// rejected: the protocol is closed, and a client speaking a newer
// dialect must fail loudly rather than be half-understood.
type Request struct {
	Version int               `json:"version"`
	Command string            `json:"command"`
	Args    map[string]string `json:"args,omitempty"`
}

// Response is one control-socket response. Data carries
// command-specific results (sessions for list-sessions); Error is
// set when OK is false. Error text names node IDs only, never keys.
type Response struct {
	Version int            `json:"version"`
	OK      bool           `json:"ok"`
	Error   string         `json:"error,omitempty"`
	Data    map[string]any `json:"data,omitempty"`
}

// SessionSummary is one live session as reported for the panel mesh
// view: identity, class MTUs, age, and stream count. Byte counters
// are deliberately absent: the metrics endpoint owns counters; this
// socket reports membership, not traffic.
type SessionSummary struct {
	SessionID     uint16    `json:"session_id"`
	NodeID        string    `json:"node_id"`
	UploadMTU     uint16    `json:"upload_mtu"`
	DownloadMTU   uint16    `json:"download_mtu"`
	CreatedAt     time.Time `json:"created_at"`
	LastActivity  time.Time `json:"last_activity"`
	ActiveStreams int       `json:"active_streams"`
}

// MeshHeartbeatSummary is one member's last heartbeat as reported
// for the panel mesh view: liveness, capacity, leg health, and
// the last control ack (so a failed config push or rotation is
// visible, never silently assumed).
type MeshHeartbeatSummary struct {
	NodeID            string         `json:"node_id"`
	State             mesh.NodeState `json:"state"`
	LastSeen          time.Time      `json:"last_seen"`
	CapacityBps       float64        `json:"capacity_bps"`
	Loss              float64        `json:"loss"`
	LegRTTMs          float64        `json:"leg_rtt_ms"`
	LegOK             bool           `json:"leg_ok"`
	ActiveStreams     int            `json:"active_streams"`
	ForwardPortsBound int            `json:"forward_ports_bound"`
	ConfigVersion     uint64         `json:"config_version"`
	ResolverUsable    int            `json:"resolver_usable"`
	ResolverRejected  int            `json:"resolver_rejected"`
	StreamConnected   bool           `json:"stream_connected"`
	LastAckFor        string         `json:"last_ack_for,omitempty"`
	LastAckError      string         `json:"last_ack_error,omitempty"`
}

// MeshSnapshot is the mesh state for the panel: the enforced
// membership table plus the last heartbeat per known member.
// SnapshotSigning reports whether the mother holds a
// snapshot-signing key (degraded derivation available to nodes
// that hold the matching verification key). It never carries
// key material.
type MeshSnapshot struct {
	Table           mesh.Table             `json:"table"`
	Heartbeats      []MeshHeartbeatSummary `json:"heartbeats"`
	SnapshotSigning bool                   `json:"snapshot_signing"`
	GeneratedAt     time.Time              `json:"generated_at"`
}

// MeshStateSource is the server side of the mesh snapshot: the
// enforced table plus heartbeat records. It is separate from
// CodecSwapper because mesh state is control-plane state, not
// codec state, and a server without a mesh coordinator reports
// unavailability rather than an empty table.
type MeshStateSource interface {
	// MeshSnapshot returns the current mesh snapshot. It must
	// never return key material.
	MeshSnapshot() (MeshSnapshot, error)
}

// MaxRequestBytes bounds one request line: the protocol carries node
// IDs and keys, never bulk data. Oversized input is rejected before
// allocation grows.
const MaxRequestBytes = 64 * 1024

// CodecSwapper is the server side of a codec-set swap: the running
// server atomically replaces its codec set (and parallel node IDs)
// so new sessions authenticate against the new set while in-flight
// sessions keep their existing codecs.
type CodecSwapper interface {
	// SwapCodecs atomically installs codecs/ids. It must reject
	// empty or mismatched arguments without touching the current
	// set (fail closed on the current configuration).
	SwapCodecs(codecs []*security.Codec, nodeIDs []string) error
	// SessionSummaries snapshots live sessions for list-sessions.
	SessionSummaries() []SessionSummary
}

// BootstrapKeyStore is the server side of pending bootstrap keys:
// derived join-token keys the server trial-decrypts bootstrap
// sessions against. It is separate from CodecSwapper because
// bootstrap keys are not node codecs: they never authenticate a
// normal session, never appear in the registry, and expire with
// the token. The store holds derived key bytes only, never the
// raw token.
type BootstrapKeyStore interface {
	// AddBootstrapKey installs key for fingerprint until expiresAt.
	// It must reject malformed fingerprints, wrong-size keys, and
	// non-future expiries without touching the current set.
	AddBootstrapKey(fingerprint string, key []byte, expiresAt time.Time) error
	// RemoveBootstrapKey drops the key for fingerprint. Removing
	// an unknown fingerprint is a no-op success (idempotent, so
	// consume and revoke paths cannot disagree).
	RemoveBootstrapKey(fingerprint string) error
}

// Handler dispatches control requests. It is implemented by
// RegistryHandler (below) and is an interface so the socket server
// stays testable with a fake.
type Handler interface {
	Handle(ctx context.Context, req Request) Response
}

// RegistryHandler implements the registry commands against a
// registry file plus a CodecSwapper. It keeps the last-loaded node
// list in memory: reload-registry refreshes it from disk;
// add/remove/rotate mutate it directly (the panel writes the file
// first; see the package doc).
type RegistryHandler struct {
	mu           sync.Mutex
	registryPath string
	method       int
	swapper      CodecSwapper
	nodes        []multisession.Node // last-known in-memory list
	loaded       bool
	// bootstrapStore, when set, serves the bootstrap-key commands.
	// It is optional: servers without bootstrap support reject
	// those commands rather than silently dropping the keys.
	bootstrapStore BootstrapKeyStore
	// meshSource, when set, serves list-mesh. It is optional:
	// servers without mesh state reject the command rather than
	// reporting an empty table as if the mesh were empty.
	meshSource MeshStateSource
}

// NewRegistryHandler builds a handler. registryPath must be the
// server's registry file; method is the AES-GCM method id (3/4/5).
// The handler loads nothing until the first command: startup must
// not fail on a registry the server already validated.
func NewRegistryHandler(registryPath string, method int, swapper CodecSwapper) (*RegistryHandler, error) {
	if strings.TrimSpace(registryPath) == "" {
		return nil, errors.New("control handler requires a registry path")
	}
	if method < 3 || method > 5 {
		return nil, fmt.Errorf("unsupported AES-GCM method %d", method)
	}
	if swapper == nil {
		return nil, errors.New("control handler requires a codec swapper")
	}
	return &RegistryHandler{registryPath: registryPath, method: method, swapper: swapper}, nil
}

// SetBootstrapStore attaches the pending-bootstrap-key store served
// by the bootstrap-key commands. A nil store disables those
// commands. It must be called before Serve starts; it is not safe
// for concurrent use with Handle.
func (h *RegistryHandler) SetBootstrapStore(store BootstrapKeyStore) {
	h.bootstrapStore = store
}

// SetMeshSource attaches the mesh snapshot source served by
// list-mesh. A nil source disables the command. It must be called
// before Serve starts; it is not safe for concurrent use with
// Handle.
func (h *RegistryHandler) SetMeshSource(source MeshStateSource) {
	h.meshSource = source
}

// validBootstrapFingerprint reports whether fp is a token
// fingerprint: 64 lowercase hex chars (SHA-256 hex). Anything else
// is rejected before it reaches the store, so a malformed command
// can never install or drop a key it did not name exactly.
func validBootstrapFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, r := range fp {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// loadLocked re-reads the registry file into memory. Callers hold mu.
func (h *RegistryHandler) loadLocked() error {
	reg, err := multisession.LoadRegistry(h.registryPath)
	if err != nil {
		return err
	}
	h.nodes = append([]multisession.Node(nil), reg.Nodes...)
	h.loaded = true
	return nil
}

// swapLocked rebuilds codecs from the in-memory node list and swaps
// them in. Callers hold mu. An empty node list is refused: the
// server requires a non-empty registry.
func (h *RegistryHandler) swapLocked() error {
	if len(h.nodes) == 0 {
		return errors.New("refusing an empty node registry: at least one node is required")
	}
	reg := &multisession.Registry{Nodes: append([]multisession.Node(nil), h.nodes...)}
	codecs, err := reg.Codecs(h.method)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(h.nodes))
	for _, n := range h.nodes {
		ids = append(ids, n.ID)
	}
	return h.swapper.SwapCodecs(codecs, ids)
}

// ensureLoadedLocked loads the registry on first use. Callers hold mu.
func (h *RegistryHandler) ensureLoadedLocked() error {
	if h.loaded {
		return nil
	}
	return h.loadLocked()
}

// Handle dispatches one request. Unknown commands, wrong versions,
// and missing arguments are rejected without touching state.
func (h *RegistryHandler) Handle(ctx context.Context, req Request) Response {
	if req.Version != ProtocolVersion {
		return Response{Version: ProtocolVersion, Error: fmt.Sprintf("unsupported control protocol version %d, want %d", req.Version, ProtocolVersion)}
	}
	switch req.Command {
	case CmdPing:
		return Response{Version: ProtocolVersion, OK: true}
	case CmdReloadRegistry:
		h.mu.Lock()
		defer h.mu.Unlock()
		if err := h.loadLocked(); err != nil {
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		if err := h.swapLocked(); err != nil {
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		return Response{Version: ProtocolVersion, OK: true, Data: map[string]any{"nodes": len(h.nodes)}}
	case CmdAddNode:
		id, key := strings.TrimSpace(req.Args["node_id"]), strings.TrimSpace(req.Args["key"])
		if id == "" || key == "" {
			return Response{Version: ProtocolVersion, Error: "add-node requires node_id and key"}
		}
		if err := multisession.ValidateNodeID(id); err != nil {
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if err := h.ensureLoadedLocked(); err != nil {
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		for _, n := range h.nodes {
			if n.ID == id {
				return Response{Version: ProtocolVersion, Error: fmt.Sprintf("node id %q already exists", id)}
			}
		}
		h.nodes = append(h.nodes, multisession.Node{ID: id, Key: key})
		if err := h.swapLocked(); err != nil {
			h.nodes = h.nodes[:len(h.nodes)-1]
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		return Response{Version: ProtocolVersion, OK: true, Data: map[string]any{"nodes": len(h.nodes)}}
	case CmdRemoveNode:
		id := strings.TrimSpace(req.Args["node_id"])
		if id == "" {
			return Response{Version: ProtocolVersion, Error: "remove-node requires node_id"}
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if err := h.ensureLoadedLocked(); err != nil {
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		kept := make([]multisession.Node, 0, len(h.nodes))
		found := false
		for _, n := range h.nodes {
			if n.ID == id {
				found = true
				continue
			}
			kept = append(kept, n)
		}
		if !found {
			return Response{Version: ProtocolVersion, Error: fmt.Sprintf("node %q not found", id)}
		}
		if len(kept) == 0 {
			return Response{Version: ProtocolVersion, Error: fmt.Sprintf("refusing to remove the last node %q", id)}
		}
		previous := h.nodes
		h.nodes = kept
		if err := h.swapLocked(); err != nil {
			h.nodes = previous
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		return Response{Version: ProtocolVersion, OK: true, Data: map[string]any{"nodes": len(h.nodes)}}
	case CmdRotateKey:
		id, key := strings.TrimSpace(req.Args["node_id"]), strings.TrimSpace(req.Args["key"])
		if id == "" || key == "" {
			return Response{Version: ProtocolVersion, Error: "rotate-key requires node_id and key"}
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if err := h.ensureLoadedLocked(); err != nil {
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		previous := ""
		found := false
		for i := range h.nodes {
			if h.nodes[i].ID == id {
				previous = h.nodes[i].Key
				h.nodes[i].Key = key
				found = true
			}
		}
		if !found {
			return Response{Version: ProtocolVersion, Error: fmt.Sprintf("node %q not found", id)}
		}
		if err := h.swapLocked(); err != nil {
			for i := range h.nodes {
				if h.nodes[i].ID == id {
					h.nodes[i].Key = previous
				}
			}
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		return Response{Version: ProtocolVersion, OK: true}
	case CmdListSessions:
		summaries := h.swapper.SessionSummaries()
		sessions := make([]any, 0, len(summaries))
		for _, s := range summaries {
			sessions = append(sessions, map[string]any{
				"session_id":     s.SessionID,
				"node_id":        s.NodeID,
				"upload_mtu":     s.UploadMTU,
				"download_mtu":   s.DownloadMTU,
				"created_at":     s.CreatedAt.UTC().Format(time.RFC3339Nano),
				"last_activity":  s.LastActivity.UTC().Format(time.RFC3339Nano),
				"active_streams": s.ActiveStreams,
			})
		}
		return Response{Version: ProtocolVersion, OK: true, Data: map[string]any{"sessions": sessions}}
	case CmdListMesh:
		if h.meshSource == nil {
			return Response{Version: ProtocolVersion, Error: "mesh state is not available on this server"}
		}
		snap, err := h.meshSource.MeshSnapshot()
		if err != nil {
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		return Response{Version: ProtocolVersion, OK: true, Data: map[string]any{"mesh": snap}}
	case CmdAddBootstrapKey:
		fp := strings.TrimSpace(req.Args["fingerprint"])
		keyHex := strings.TrimSpace(req.Args["key"])
		expiresRaw := strings.TrimSpace(req.Args["expires_unix"])
		if !validBootstrapFingerprint(fp) || keyHex == "" || expiresRaw == "" {
			return Response{Version: ProtocolVersion, Error: "add-bootstrap-key requires fingerprint, key, and expires_unix"}
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil || len(key) != 32 {
			return Response{Version: ProtocolVersion, Error: "add-bootstrap-key requires a 32-byte hex key"}
		}
		expiresUnix, err := strconv.ParseInt(expiresRaw, 10, 64)
		if err != nil || expiresUnix <= time.Now().Unix() {
			return Response{Version: ProtocolVersion, Error: "add-bootstrap-key requires a future expires_unix"}
		}
		if h.bootstrapStore == nil {
			return Response{Version: ProtocolVersion, Error: "bootstrap keys are not supported by this server"}
		}
		if err := h.bootstrapStore.AddBootstrapKey(fp, key, time.Unix(expiresUnix, 0)); err != nil {
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		return Response{Version: ProtocolVersion, OK: true}
	case CmdRemoveBootstrapKey:
		fp := strings.TrimSpace(req.Args["fingerprint"])
		if !validBootstrapFingerprint(fp) {
			return Response{Version: ProtocolVersion, Error: "remove-bootstrap-key requires fingerprint"}
		}
		if h.bootstrapStore == nil {
			return Response{Version: ProtocolVersion, Error: "bootstrap keys are not supported by this server"}
		}
		if err := h.bootstrapStore.RemoveBootstrapKey(fp); err != nil {
			return Response{Version: ProtocolVersion, Error: err.Error()}
		}
		return Response{Version: ProtocolVersion, OK: true}
	default:
		return Response{Version: ProtocolVersion, Error: fmt.Sprintf("unknown control command %q", req.Command)}
	}
}

// Serve runs the control socket on listener until ctx ends. Serve
// owns the listener: it closes it when ctx ends, so a shutdown never
// hangs in Accept. Each connection serves exactly one request line
// and one response line, then closes; a slow or oversized client
// cannot hold the socket. Serve returns when the listener closes.
func Serve(ctx context.Context, listener net.Listener, handler Handler) error {
	if handler == nil {
		return errors.New("control socket requires a handler")
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return fmt.Errorf("control socket accept: %w", err)
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveConn(ctx, conn, handler)
		}()
	}
}

func serveConn(ctx context.Context, conn net.Conn, handler Handler) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReaderSize(conn, MaxRequestBytes)
	line, err := reader.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	line = []byte(strings.TrimRight(string(line), "\r\n"))
	if len(line) > MaxRequestBytes {
		writeResponse(conn, Response{Version: ProtocolVersion, Error: "request exceeds the size limit"})
		return
	}
	var req Request
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeResponse(conn, Response{Version: ProtocolVersion, Error: fmt.Sprintf("decode control request: %v", err)})
		return
	}
	resp := handler.Handle(ctx, req)
	writeResponse(conn, resp)
}

func writeResponse(conn net.Conn, resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(data, '\n'))
}

// Listen creates the Unix control socket at socketPath, removing a
// stale socket file first (a leftover from an unclean shutdown) and
// chmodding the new socket to 0600. The caller owns the listener
// and removes the socket file on shutdown.
func Listen(socketPath string) (net.Listener, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, errors.New("control socket path is empty")
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale control socket %s: %w", socketPath, err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on control socket %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("restrict control socket %s: %w", socketPath, err)
	}
	return listener, nil
}

// Client is the control-socket client used by the panel (and by
// operators). One request per connection; the socket path is the
// only addressing (same host, root-only).
type Client struct {
	SocketPath string
	Timeout    time.Duration // default 10 s when zero
}

// Call sends one request and returns the response. A response with
// OK=false is returned as an error naming the command and the
// server's message (which never contains key material).
func (c Client) Call(ctx context.Context, req Request) (Response, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return Response{}, fmt.Errorf("dial control socket %s: %w", c.SocketPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req.Version = ProtocolVersion
	data, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return Response{}, fmt.Errorf("write control request: %w", err)
	}
	reader := bufio.NewReaderSize(conn, MaxRequestBytes)
	line, err := reader.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return Response{}, fmt.Errorf("read control response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal([]byte(strings.TrimRight(string(line), "\r\n")), &resp); err != nil {
		return Response{}, fmt.Errorf("decode control response: %w", err)
	}
	if resp.Version != ProtocolVersion {
		return resp, fmt.Errorf("control protocol version %d, want %d", resp.Version, ProtocolVersion)
	}
	if !resp.OK {
		return resp, fmt.Errorf("control command %q failed: %s", req.Command, resp.Error)
	}
	return resp, nil
}

// ReloadRegistry asks the server to re-read its registry file.
func (c Client) ReloadRegistry(ctx context.Context) error {
	_, err := c.Call(ctx, Request{Command: CmdReloadRegistry})
	return err
}

// AddNode inserts one node into the server's in-memory codec set.
func (c Client) AddNode(ctx context.Context, nodeID, key string) error {
	_, err := c.Call(ctx, Request{Command: CmdAddNode, Args: map[string]string{"node_id": nodeID, "key": key}})
	return err
}

// RemoveNode removes one node from the server's in-memory codec set.
func (c Client) RemoveNode(ctx context.Context, nodeID string) error {
	_, err := c.Call(ctx, Request{Command: CmdRemoveNode, Args: map[string]string{"node_id": nodeID}})
	return err
}

// RotateKey replaces one node's in-memory codec.
func (c Client) RotateKey(ctx context.Context, nodeID, key string) error {
	_, err := c.Call(ctx, Request{Command: CmdRotateKey, Args: map[string]string{"node_id": nodeID, "key": key}})
	return err
}

// ListSessions returns the server's live session summaries.
func (c Client) ListSessions(ctx context.Context) ([]SessionSummary, error) {
	resp, err := c.Call(ctx, Request{Command: CmdListSessions})
	if err != nil {
		return nil, err
	}
	raw, ok := resp.Data["sessions"]
	if !ok {
		return nil, errors.New("list-sessions response carries no sessions")
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var sessions []SessionSummary
	if err := json.Unmarshal(data, &sessions); err != nil {
		return nil, fmt.Errorf("decode session summaries: %w", err)
	}
	return sessions, nil
}

// ListMesh returns the server's mesh snapshot (membership table
// plus last heartbeats). An unavailable mesh source is an error,
// never an empty table: the panel must show the mesh as
// unavailable, not as empty.
func (c Client) ListMesh(ctx context.Context) (MeshSnapshot, error) {
	resp, err := c.Call(ctx, Request{Command: CmdListMesh})
	if err != nil {
		return MeshSnapshot{}, err
	}
	raw, ok := resp.Data["mesh"]
	if !ok {
		return MeshSnapshot{}, errors.New("list-mesh response carries no mesh snapshot")
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return MeshSnapshot{}, err
	}
	var snap MeshSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return MeshSnapshot{}, fmt.Errorf("decode mesh snapshot: %w", err)
	}
	return snap, nil
}

// AddBootstrapKey installs a pending bootstrap key on the server.
// keyHex is the lowercase hex of the 32-byte derived key (the form
// BootstrapKeyString produces); expiresAt is the token expiry. The
// key is useless after the token burns or expires, and the panel
// removes it with RemoveBootstrapKey when the token is consumed,
// revoked, or swept.
func (c Client) AddBootstrapKey(ctx context.Context, fingerprint, keyHex string, expiresAt time.Time) error {
	_, err := c.Call(ctx, Request{Command: CmdAddBootstrapKey, Args: map[string]string{
		"fingerprint":  fingerprint,
		"key":          keyHex,
		"expires_unix": strconv.FormatInt(expiresAt.Unix(), 10),
	}})
	return err
}

// RemoveBootstrapKey drops a pending bootstrap key from the server.
// Removing an unknown fingerprint succeeds (idempotent).
func (c Client) RemoveBootstrapKey(ctx context.Context, fingerprint string) error {
	_, err := c.Call(ctx, Request{Command: CmdRemoveBootstrapKey, Args: map[string]string{"fingerprint": fingerprint}})
	return err
}
