// Mesh control state (Phase 3 spec §4.2): the mother-side
// coordinator, heartbeat records, and the open control streams
// that carry tables down to nodes. All coordinator access is
// serialized through meshState.mu: the Coordinator is
// single-threaded by contract, and the heartbeat handler, the
// evaluation ticker, and the panel's list-mesh reads all share
// this state.
//
// A control stream is one reserved "control" stream inside a
// node's own DNS session, authenticated by the session key. The
// stream handler is fail-closed throughout: a session that is
// not a registry-keyed normal session, a heartbeat whose NodeID
// does not match the session's registry identity, or a malformed
// frame ends the stream (the node re-opens on its next heartbeat
// tick). Nothing here trusts the node's self-assertion: membership
// comes from the registry (the session key proves it), capacity
// from measured heartbeats, and tables from the term rule.
package udpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/control"
	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
	"github.com/MNSH-Nexo/Nexounel/core/internal/mesh"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
)

// controlReadTimeout bounds silence on a control stream: heartbeats
// arrive every 30 s, so 90 s without a frame means the stream is
// dead and the node will re-open it. The timeout is refreshed on
// every frame; it never fires on a live stream.
const controlReadTimeout = 90 * time.Second

// controlWriteTimeout bounds one frame write into a control stream
// (heartbeat reply or panel-ordered delivery). A stuck write must
// not wedge the handler or the delivery path.
const controlWriteTimeout = 30 * time.Second

// meshEvaluateInterval paces the mother-side evaluation ticker:
// suspect/down transitions and chief elections run on this cadence,
// well inside the 60 s suspect threshold.
const meshEvaluateInterval = 10 * time.Second

// meshHeartbeatRecord is one member's last heartbeat plus the
// control-plane facts the panel needs about it.
type meshHeartbeatRecord struct {
	heartbeat mesh.Heartbeat
	received  time.Time
	state     mesh.NodeState
	lastAck   *mesh.Ack
}

// meshStreamConn is one node's open control stream. Writes are
// serialized through writeMu: the stream handler (heartbeat
// replies) and the panel delivery path share the connection.
type meshStreamConn struct {
	conn    net.Conn
	writeMu sync.Mutex
}

// meshState is the mother-side mesh control plane. The zero value
// is unusable: New builds it, and &Server{} literals in tests have
// a nil mesh field, which every entry point treats as "mesh
// unavailable" (fail closed).
type meshState struct {
	mu          sync.Mutex
	coord       *mesh.Coordinator
	heartbeats  map[string]*meshHeartbeatRecord
	streams     map[string]*meshStreamConn
	snapshotKey []byte
}

// newMeshState builds mother-side mesh state with no members and
// no snapshot key. The coordinator starts with the zero table;
// InitMesh installs the registry-derived table, and heartbeats
// from registry-authenticated sessions admit members one by one.
func newMeshState(snapshotKey []byte) *meshState {
	coord, err := mesh.NewCoordinator("", true, mesh.Timeouts{}, snapshotKey)
	if err != nil {
		// Default timeouts always validate; this is unreachable
		// in practice, but a mesh that cannot be built must not
		// take the server down with it.
		return &meshState{
			heartbeats:  make(map[string]*meshHeartbeatRecord),
			streams:     make(map[string]*meshStreamConn),
			snapshotKey: append([]byte(nil), snapshotKey...),
		}
	}
	return &meshState{
		coord:       coord,
		heartbeats:  make(map[string]*meshHeartbeatRecord),
		streams:     make(map[string]*meshStreamConn),
		snapshotKey: append([]byte(nil), snapshotKey...),
	}
}

// meshStateOrNil returns the server's mesh state, or nil for
// servers built without New (test literals). Callers treat nil as
// unavailable and fail closed.
func (s *Server) meshStateOrNil() *meshState {
	if s == nil {
		return nil
	}
	return s.mesh
}

// InitMesh installs the registry-derived membership table: one
// ACTIVE member per registry node, tenure in registry order
// (enrollment order), zero weights until the first heartbeat, and
// the deterministic first chief when the mesh is non-empty. The
// table is issued as the first real term (T1). Calling InitMesh
// twice replaces the state; the server calls it once at startup.
func (s *Server) InitMesh(memberIDs []string, snapshotKey []byte) {
	st := newMeshState(snapshotKey)
	members := make([]mesh.Member, 0, len(memberIDs))
	for i, id := range memberIDs {
		members = append(members, mesh.Member{ID: id, State: mesh.StateActive, TenureSeq: uint64(i + 1)})
	}
	table := mesh.Table{Term: mesh.Term{Number: 1}, Version: 1, Members: members, Weights: make(map[string]float64, len(members))}
	for _, m := range members {
		table.Weights[m.ID] = 0
	}
	table.ChiefID = mesh.RankSuccessor(members, "")
	st.coord.ApplyTable(table)
	s.mesh = st
}

// handleHeartbeat validates one heartbeat against the session
// that carried it and folds it into the table. The heartbeat's
// NodeID must equal the session's registry identity; anything
// else is rejected (the handler closes the stream). An unknown
// member that heartbeats over a registry-authenticated session is
// admitted — the session key is the membership proof, and the
// registry is the membership source. It returns the table push
// the handler replies with.
func (st *meshState) handleHeartbeat(hb mesh.Heartbeat, sessionNodeID string) (mesh.TablePush, error) {
	if err := multisession.ValidateNodeID(hb.NodeID); err != nil {
		return mesh.TablePush{}, fmt.Errorf("heartbeat node id: %w", err)
	}
	if hb.NodeID != sessionNodeID {
		return mesh.TablePush{}, fmt.Errorf("heartbeat node %q does not match session identity %q", hb.NodeID, sessionNodeID)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.coord == nil {
		return mesh.TablePush{}, errors.New("mesh coordinator unavailable")
	}
	known := false
	for _, m := range st.coord.Current().Members {
		if m.ID == hb.NodeID {
			known = true
			break
		}
	}
	if !known {
		st.coord.AddMember(mesh.Member{ID: hb.NodeID})
	}
	now := time.Now()
	st.coord.NoteHeartbeat(hb.NodeID, hb.CapacityBps, hb.Loss, hb.LegRTTMs, hb.LegOK, now)
	st.coord.EnsureChief()
	published, err := st.coord.PublishMotherTable()
	if err != nil {
		return mesh.TablePush{}, err
	}
	st.coord.ApplyTable(published)
	push := mesh.TablePush{Table: st.coord.Current()}
	if len(st.snapshotKey) > 0 {
		if snap, err := mesh.SignSnapshot(push.Table, st.snapshotKey); err == nil {
			push.Snapshot = &snap
		}
	}
	rec, ok := st.heartbeats[hb.NodeID]
	if !ok {
		rec = &meshHeartbeatRecord{}
		st.heartbeats[hb.NodeID] = rec
	}
	rec.heartbeat = hb
	rec.received = now
	rec.state = stateOf(push.Table, hb.NodeID)
	return push, nil
}

// stateOf reads one member's state from a table; unknown members
// report PENDING (enrolled, not yet in the table).
func stateOf(t mesh.Table, id string) mesh.NodeState {
	for _, m := range t.Members {
		if m.ID == id {
			return m.State
		}
	}
	return mesh.StatePending
}

// recordAck stores one node's ack of a mother-originated frame, so
// the panel can tell an applied push from an ignored one. Acks with
// an error mark the push failed; the panel flags unacknowledged
// orders, never assumes them.
func (st *meshState) recordAck(nodeID string, ack mesh.Ack) {
	st.mu.Lock()
	defer st.mu.Unlock()
	rec, ok := st.heartbeats[nodeID]
	if !ok {
		rec = &meshHeartbeatRecord{}
		st.heartbeats[nodeID] = rec
	}
	ackCopy := ack
	rec.lastAck = &ackCopy
}

// registerStream records one node's open control stream, replacing
// any previous stream for the node. The previous connection is
// closed so its handler unblocks and exits; the caller owns the
// new connection.
func (st *meshState) registerStream(nodeID string, conn net.Conn) *meshStreamConn {
	st.mu.Lock()
	defer st.mu.Unlock()
	if prev, ok := st.streams[nodeID]; ok {
		_ = prev.conn.Close()
	}
	sc := &meshStreamConn{conn: conn}
	st.streams[nodeID] = sc
	return sc
}

// unregisterStream drops a node's control stream, but only when it
// is still the registered one (a re-opened stream must not be
// unregistered by its predecessor's exit).
func (st *meshState) unregisterStream(nodeID string, sc *meshStreamConn) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if cur, ok := st.streams[nodeID]; ok && cur == sc {
		delete(st.streams, nodeID)
	}
}

// deliverFrame writes one mother-originated frame into a node's
// open control stream. It errors when the node has no open stream:
// delivery is best-effort over the live stream, and the panel must
// surface "node not connected" rather than queue the order into a
// future it cannot see. The ack (or its absence) is the delivery
// record, tracked separately.
func (st *meshState) deliverFrame(nodeID string, kind mesh.FrameKind, payload any) error {
	st.mu.Lock()
	sc, ok := st.streams[nodeID]
	st.mu.Unlock()
	if !ok {
		return fmt.Errorf("node %q has no open control stream", nodeID)
	}
	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()
	_ = sc.conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
	return mesh.WriteFrame(sc.conn, kind, payload)
}

// evaluate advances the mother-side decisions at now and
// republishes the table when anything changed: suspect/down
// transitions fold into the table, and a chief-lost event elects
// the successor (term bump, version reset) through the term rule.
// It returns the events for the caller's log.
func (st *meshState) evaluate(now time.Time) []mesh.Event {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.coord == nil {
		return nil
	}
	events := st.coord.Evaluate(now)
	if len(events) == 0 {
		return nil
	}
	for _, e := range events {
		if e.Kind == mesh.EventChiefLost {
			elected := st.coord.Current()
			elected.ChiefID = e.Successor
			elected.Term = e.Term
			elected.Version = 1
			st.coord.ApplyTable(elected)
		}
	}
	st.coord.EnsureChief()
	if published, err := st.coord.PublishMotherTable(); err == nil {
		st.coord.ApplyTable(published)
	}
	current := st.coord.Current()
	for id, rec := range st.heartbeats {
		rec.state = stateOf(current, id)
	}
	return events
}

// MeshSnapshot implements control.MeshStateSource: the enforced
// table plus the last heartbeat per known member, sorted by node
// ID. It never carries key material.
func (st *meshState) MeshSnapshot() (control.MeshSnapshot, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.coord == nil {
		return control.MeshSnapshot{}, errors.New("mesh coordinator unavailable")
	}
	table := st.coord.Current()
	ids := make([]string, 0, len(st.heartbeats))
	for id := range st.heartbeats {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	summaries := make([]control.MeshHeartbeatSummary, 0, len(ids))
	for _, id := range ids {
		rec := st.heartbeats[id]
		sum := control.MeshHeartbeatSummary{
			NodeID:            id,
			State:             rec.state,
			LastSeen:          rec.received,
			CapacityBps:       rec.heartbeat.CapacityBps,
			Loss:              rec.heartbeat.Loss,
			LegRTTMs:          rec.heartbeat.LegRTTMs,
			LegOK:             rec.heartbeat.LegOK,
			ActiveStreams:     rec.heartbeat.ActiveStreams,
			ForwardPortsBound: rec.heartbeat.ForwardPortsBound,
			ConfigVersion:     rec.heartbeat.ConfigVersion,
			StreamConnected:   false,
		}
		if _, ok := st.streams[id]; ok {
			sum.StreamConnected = true
		}
		if rec.lastAck != nil {
			sum.LastAckFor = string(rec.lastAck.For)
			sum.LastAckError = rec.lastAck.Error
		}
		summaries = append(summaries, sum)
	}
	return control.MeshSnapshot{
		Table:           table,
		Heartbeats:      summaries,
		SnapshotSigning: len(st.snapshotKey) > 0,
		GeneratedAt:     time.Now().UTC(),
	}, nil
}

// MeshSnapshot implements control.MeshStateSource for the panel's
// list-mesh command: the enforced table plus the last heartbeat
// per known member. It errors when the server has no mesh state
// (single-key mode or a test literal), so the panel shows the
// mesh as unavailable rather than empty.
func (s *Server) MeshSnapshot() (control.MeshSnapshot, error) {
	st := s.meshStateOrNil()
	if st == nil {
		return control.MeshSnapshot{}, errors.New("mesh state unavailable")
	}
	return st.MeshSnapshot()
}

// MeshLoop runs the mother-side evaluation ticker until ctx ends.
// It is a no-op when the server has no mesh state.
func (s *Server) MeshLoop(ctx context.Context) {
	st := s.meshStateOrNil()
	if st == nil {
		return
	}
	ticker := time.NewTicker(meshEvaluateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for _, e := range st.evaluate(now) {
				if s.log != nil {
					s.log.Warnf("mesh: %s", e)
				}
			}
		}
	}
}

// serveControlStream serves one control stream for the life of the
// stream: heartbeats in, table pushes out, acks recorded. It runs
// detached on the pipe end the dispatch attached, and returns when
// the stream closes, the peer goes silent, or a frame is malformed
// — all of which the node treats as "re-open the stream".
func (s *Server) serveControlStream(conn net.Conn, record *sessionRecord) {
	defer conn.Close()
	st := s.meshStateOrNil()
	if st == nil || record.Kind != enroll.SessionKindNormal || record.NodeID == "" {
		if s.log != nil {
			s.log.Warnf("control stream denied: mesh unavailable, non-normal session, or anonymous session (node %q)", record.NodeID)
		}
		return
	}
	nodeID := record.NodeID
	sc := st.registerStream(nodeID, conn)
	defer st.unregisterStream(nodeID, sc)
	if s.log != nil {
		s.log.Infof("mesh: control stream opened for node %q", nodeID)
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(controlReadTimeout))
		frame, err := mesh.ReadFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && s.log != nil {
				s.log.Warnf("mesh: control stream for node %q closed: %v", nodeID, err)
			}
			return
		}
		switch frame.Kind {
		case mesh.KindHeartbeat:
			var hb mesh.Heartbeat
			if err := frame.Decode(&hb); err != nil {
				if s.log != nil {
					s.log.Warnf("mesh: malformed heartbeat from node %q: %v", nodeID, err)
				}
				return
			}
			push, err := st.handleHeartbeat(hb, nodeID)
			if err != nil {
				if s.log != nil {
					s.log.Warnf("mesh: heartbeat from node %q rejected: %v", nodeID, err)
				}
				return
			}
			sc.writeMu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
			werr := mesh.WriteFrame(conn, mesh.KindTable, push)
			sc.writeMu.Unlock()
			if werr != nil {
				if s.log != nil {
					s.log.Warnf("mesh: table push to node %q failed: %v", nodeID, werr)
				}
				return
			}
		case mesh.KindAck:
			var ack mesh.Ack
			if err := frame.Decode(&ack); err != nil {
				if s.log != nil {
					s.log.Warnf("mesh: malformed ack from node %q: %v", nodeID, err)
				}
				return
			}
			st.recordAck(nodeID, ack)
		default:
			// A node never sends tables, config, rotation, or
			// term frames. Unknown and node-originated kinds
			// are ignored (forward-compatible), never acted on.
			if s.log != nil {
				s.log.Warnf("mesh: unexpected %q frame from node %q ignored", frame.Kind, nodeID)
			}
		}
	}
}
