// Control streams carry the mesh control exchange (Phase 3 spec §4.2):
// node heartbeats up, membership tables, config pushes, key rotation
// orders, and term announcements down — inside the node's own DNS
// session, authenticated by the session key, addressed to the
// reserved "control" target the server intercepts. There is no
// separate credential and no unauthenticated surface: a control
// stream is opened only over a live, keyed session, and both sides
// validate every frame.
//
// Framing is deliberately boring: a 4-byte big-endian length prefix
// followed by one JSON envelope {version, kind, payload}. The length
// bound (64 KiB) keeps a compromised or buggy peer from making either
// side allocate unbounded memory; the version gate keeps future
// framing revisions from being misread as v1 frames.
package mesh

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ControlFrameVersion is the only framing version this code speaks.
const ControlFrameVersion = 1

// MaxControlFrameBytes bounds one framed message. Control traffic is
// small (heartbeats, tables, config text); 64 KiB leaves ample room
// for a full config push while capping allocation per frame.
const MaxControlFrameBytes = 64 * 1024

// FrameKind names one control message kind.
type FrameKind string

const (
	// KindHeartbeat: node → mother, every 30 s and on change.
	KindHeartbeat FrameKind = "heartbeat"
	// KindTable: mother → node, the current membership table (plus an
	// optional signed snapshot when the mother holds a signing key).
	KindTable FrameKind = "table"
	// KindConfig: mother → node, a config push (§4.3).
	KindConfig FrameKind = "config"
	// KindRotation: mother → node, a key rotation order (§8.2).
	KindRotation FrameKind = "rotation"
	// KindTerm: mother → node, a term announcement or step-down order (§6).
	KindTerm FrameKind = "term"
	// KindAck: either direction, acknowledging a table/config/rotation/
	// term frame. Ack.Error non-empty means the frame was NOT applied.
	KindAck FrameKind = "ack"
)

// validFrameKinds is the closed set ReadFrame accepts.
var validFrameKinds = map[FrameKind]bool{
	KindHeartbeat: true,
	KindTable:     true,
	KindConfig:    true,
	KindRotation:  true,
	KindTerm:      true,
	KindAck:       true,
}

// Frame is one decoded control envelope. Payload is the raw JSON of
// the kind-specific message; Decode unmarshals it into v.
type Frame struct {
	Version int             `json:"version"`
	Kind    FrameKind       `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

// Decode unmarshals the frame payload into v. The caller checks Kind
// first; Decode never guesses the message type.
func (f Frame) Decode(v any) error {
	if len(f.Payload) == 0 {
		return errors.New("control frame has empty payload")
	}
	return json.Unmarshal(f.Payload, v)
}

// WriteFrame marshals payload as the body of a versioned envelope of
// the given kind and writes it length-prefixed to w. The length
// prefix and body go out in a single Write so a reader never sees a
// torn header.
func WriteFrame(w io.Writer, kind FrameKind, payload any) error {
	if !validFrameKinds[kind] {
		return fmt.Errorf("unknown control frame kind %q", kind)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal control payload: %w", err)
	}
	env, err := json.Marshal(Frame{Version: ControlFrameVersion, Kind: kind, Payload: body})
	if err != nil {
		return fmt.Errorf("marshal control envelope: %w", err)
	}
	if len(env) > MaxControlFrameBytes {
		return fmt.Errorf("control frame of %d bytes exceeds %d-byte limit", len(env), MaxControlFrameBytes)
	}
	buf := make([]byte, 4+len(env))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(env)))
	copy(buf[4:], env)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write control frame: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed envelope from r. A clean EOF
// while reading the length prefix returns io.EOF (the peer closed
// the stream); any other short read is an error. Version and kind
// are validated before the frame is returned; payload shape is the
// caller's job (Frame.Decode).
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.EOF {
			return Frame{}, io.EOF
		}
		return Frame{}, fmt.Errorf("read control frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxControlFrameBytes {
		return Frame{}, fmt.Errorf("control frame length %d out of bounds (1..%d)", n, MaxControlFrameBytes)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Frame{}, fmt.Errorf("read control frame body: %w", err)
	}
	var f Frame
	if err := json.Unmarshal(buf, &f); err != nil {
		return Frame{}, fmt.Errorf("decode control envelope: %w", err)
	}
	if f.Version != ControlFrameVersion {
		return Frame{}, fmt.Errorf("unsupported control frame version %d", f.Version)
	}
	if !validFrameKinds[f.Kind] {
		return Frame{}, fmt.Errorf("unknown control frame kind %q", f.Kind)
	}
	if len(f.Payload) == 0 {
		return Frame{}, errors.New("control frame has empty payload")
	}
	return f, nil
}

// ClassCapacity is one capacity class as the node reports it: the
// operating point the probe pass measured, how many resolvers feed
// it, and the class's share of the node's distribution weight.
type ClassCapacity struct {
	UploadMTU   int     `json:"upload_mtu"`
	DownloadMTU int     `json:"download_mtu"`
	Members     int     `json:"members"`
	Weight      float64 `json:"weight"`
}

// ResolverHealth is one resolver's last measured state as the node
// reports it. State is "usable" (measured, in a class) or "rejected"
// (probe failed); "down" is reserved for runtime re-probe results,
// which this milestone does not yet produce.
type ResolverHealth struct {
	Address     string  `json:"address"`
	State       string  `json:"state"`
	UploadMTU   int     `json:"upload_mtu"`
	DownloadMTU int     `json:"download_mtu"`
	Loss        float64 `json:"loss"`
}

// PeerReachability is one peer leg as the node sees it (§5): the
// peer control-port probe result, or the empty list when peer
// control ports are disabled.
type PeerReachability struct {
	PeerID  string  `json:"peer_id"`
	LegKind string  `json:"leg_kind"`
	RTTMs   float64 `json:"rtt_ms"`
	OK      bool    `json:"ok"`
}

// Heartbeat is the node → mother report (§4.2). CapacityBps is the
// node's probe ceiling: per-resolver download MTUs summed over the
// node's classes (raw ceiling, NOT loss-discounted); Loss is the
// MTU-weighted mean loss fraction, and the mother applies the
// discount when it computes weights (NodeWeight) — discounting on
// both sides would double-count. LegRTTMs is 0 (unmeasured,
// neutral) until peer probes measure legs; LegOK reports whether
// the node has a ready session, which is what reachability means
// before peer probes exist — a heartbeating node is reachable
// through the tunnel by construction. ForwardPortsBound counts
// the forward listeners currently bound — a binding check, not an
// end-to-end forward proof (a dial-based check would open spurious
// upstream connections; see the milestone doc).
type Heartbeat struct {
	NodeID            string             `json:"node_id"`
	Role              string             `json:"role"` // "plain" or "chief"
	Version           string             `json:"version"`
	Term              Term               `json:"term"`
	CapacityBps       float64            `json:"capacity_bps"`
	Loss              float64            `json:"loss"`
	LegRTTMs          float64            `json:"leg_rtt_ms"`
	LegOK             bool               `json:"leg_ok"`
	ActiveStreams     int                `json:"active_streams"`
	Classes           []ClassCapacity    `json:"classes"`
	Resolvers         []ResolverHealth   `json:"resolvers"`
	Reachability      []PeerReachability `json:"reachability"`
	ForwardPortsBound int                `json:"forward_ports_bound"`
	ConfigVersion     uint64             `json:"config_version"`
	SentAt            time.Time          `json:"sent_at"`
}

// TablePush carries the current membership table, plus the signed
// snapshot when the mother holds a snapshot-signing key. Without a
// key the snapshot is nil and the table still applies; degraded
// derivation stays disabled on the node (see the milestone doc).
type TablePush struct {
	Table    Table     `json:"table"`
	Snapshot *Snapshot `json:"snapshot,omitempty"`
}

// ConfigPush carries a full replacement node config (§4.3) and the
// version the mother assigned it. The node stages, validates with
// the existing config checker, and renames atomically; the version
// is what the next heartbeat reports back.
type ConfigPush struct {
	Version uint64 `json:"version"`
	TOML    string `json:"toml"`
}

// RotationOrder carries a new node key (§8.2): hex-encoded 32 bytes,
// generated on the mother, delivered over the session-encrypted
// control stream. The node writes it atomically (0600), the mother
// updates the registry via the control socket, and the node
// re-registers new sessions under the new key (live re-registration
// is future work; until then the key takes effect on restart).
type RotationOrder struct {
	NodeID    string `json:"node_id"`
	NewKeyHex string `json:"new_key_hex"`
	Reason    string `json:"reason"`
}

// TermAnnouncement carries a chief term announcement or a step-down
// order (§6). StepDown true means the mother orders this node to
// relinquish the chief role; the mother elects the successor (no
// 60 s wait). Term application itself travels with tables; this
// frame's term is informational except for the step-down flag.
type TermAnnouncement struct {
	Term     Term   `json:"term"`
	StepDown bool   `json:"step_down"`
	Reason   string `json:"reason"`
}

// Ack acknowledges one received frame. For is the kind that was
// acked; Error non-empty means the frame was received but NOT
// applied, with the reason — the sender must never assume an
// unacknowledged or error-acked order took effect. AppliedVersion
// carries the config version after a config push.
type Ack struct {
	For             FrameKind `json:"for"`
	AppliedVersion  uint64    `json:"applied_version"`
	RestartRequired bool      `json:"restart_required"`
	Message         string    `json:"message"`
	Error           string    `json:"error,omitempty"`
}
