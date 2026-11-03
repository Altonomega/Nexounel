// Node-side mesh control agent (Phase 3 spec §4.2): the control
// exchange inside the node's own DNS session. The agent opens a
// reserved "control" stream over a ready session, heartbeats every
// 30 s, enforces the membership tables the mother sends, and
// applies config pushes and rotation orders — all authenticated
// by the session key, with no separate credential and no inbound
// port.
//
// Failure discipline is fail-closed and self-healing: a dead or
// malformed stream is dropped and re-opened with backoff; a
// rejected config push or rotation order is acked with the error
// and nothing is written; a table that loses the term rule is
// ignored, never partially applied. The agent never stops the
// node: losing the mesh degrades the node to standalone operation
// (it keeps serving its own direct users), and the mesh resumes
// when the stream re-opens.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/client"
	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	"github.com/MNSH-Nexo/Nexounel/core/internal/logger"
	"github.com/MNSH-Nexo/Nexounel/core/internal/mesh"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
	"github.com/MNSH-Nexo/Nexounel/core/internal/version"
)

// heartbeatSnapshot is the node's measured state for one heartbeat.
// The run functions build it from their session state; the agent
// only stamps identity, term, role, version, and config version.
type heartbeatSnapshot struct {
	CapacityBps       float64
	Loss              float64
	LegOK             bool
	ActiveStreams     int
	Classes           []mesh.ClassCapacity
	Resolvers         []mesh.ResolverHealth
	ForwardPortsBound int
}

// meshAgent owns the node side of the control exchange. All
// coordinator access is serialized through mu: the heartbeat
// ticker, the frame reader, and the step-down query share it.
type meshAgent struct {
	nodeID     string
	cfg        config.ClientConfig
	configPath string
	overrides  config.ClientConfigOverrides
	openStream func(ctx context.Context) (net.Conn, error)
	snapshot   func() heartbeatSnapshot
	log        *logger.Logger

	mu             sync.Mutex
	coord          *mesh.Coordinator
	appliedVersion uint64
	stepDownReq    bool
	stepDownTerm   mesh.Term
	lastTable      mesh.Table
	haveTable      bool
	// notify wakes the heartbeat loop for an immediate heartbeat
	// when state changes (table applied, push applied, step-down).
	// Buffered 1: a poke never blocks the frame handler, and
	// coalesced pokes collapse into one immediate heartbeat.
	notify chan struct{}
}

// newMeshAgent builds the agent. The coordinator is node-perspective
// with no snapshot key: degraded derivation stays disabled until
// the election milestone issues snapshot keys at enrollment (the
// table exchange works without it). A coordinator that cannot be
// built (unreachable with default timeouts) disables the agent
// rather than failing startup.
func newMeshAgent(cfg config.ClientConfig, configPath string, overrides config.ClientConfigOverrides, openStream func(ctx context.Context) (net.Conn, error), snapshot func() heartbeatSnapshot, log *logger.Logger) *meshAgent {
	coord, err := mesh.NewCoordinator(cfg.NodeID, false, mesh.Timeouts{}, nil)
	if err != nil {
		return nil
	}
	a := &meshAgent{
		nodeID:     cfg.NodeID,
		cfg:        cfg,
		configPath: configPath,
		overrides:  overrides,
		openStream: openStream,
		snapshot:   snapshot,
		log:        log,
		coord:      coord,
		notify:     make(chan struct{}, 1),
	}
	a.appliedVersion = loadAppliedConfigVersion(configPath)
	return a
}

// poke requests one immediate heartbeat. It never blocks: the
// channel holds one pending poke, and further pokes coalesce.
func (a *meshAgent) poke() {
	if a.notify == nil {
		return
	}
	select {
	case a.notify <- struct{}{}:
	default:
	}
}

// appliedVersionPath is the sibling file recording the last applied
// config-push version. It holds a bare number — no secrets — so it
// is world-readable; the number only tells the panel which push
// the node last staged.
func appliedVersionPath(configPath string) string {
	return configPath + ".mesh-version"
}

func loadAppliedConfigVersion(configPath string) uint64 {
	raw, err := os.ReadFile(appliedVersionPath(configPath))
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func storeAppliedConfigVersion(configPath string, v uint64) error {
	return writeFileAtomic(appliedVersionPath(configPath), []byte(strconv.FormatUint(v, 10)+"\n"), 0o644)
}

// Run opens control streams until ctx ends, backing off between
// attempts. It never returns an error: mesh loss must not stop
// the node.
func (a *meshAgent) Run(ctx context.Context) {
	backoff := 5 * time.Second
	for ctx.Err() == nil {
		conn, err := a.openStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if a.log != nil {
				a.log.Debugf("mesh: control stream unavailable: %v (retry in %s)", err, backoff)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			continue
		}
		backoff = 5 * time.Second
		a.serve(ctx, conn)
		_ = conn.Close()
	}
}

// serve runs one control stream: heartbeats out on a ticker,
// mother frames in on the reader. It returns when the stream
// breaks, goes silent, or carries a malformed frame — the Run
// loop re-opens it.
func (a *meshAgent) serve(ctx context.Context, conn net.Conn) {
	done := make(chan struct{})
	defer close(done)
	go func() {
		a.sendHeartbeat(conn)
		ticker := time.NewTicker(mesh.DefaultTimeouts().HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-a.notify:
				a.sendHeartbeat(conn)
			case <-ticker.C:
				a.sendHeartbeat(conn)
			}
		}
	}()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		frame, err := mesh.ReadFrame(conn)
		if err != nil {
			if a.log != nil && !errors.Is(err, io.EOF) {
				a.log.Debugf("mesh: control stream read ended: %v", err)
			}
			return
		}
		if !a.handleFrame(conn, frame) {
			return
		}
	}
}

// sendHeartbeat snapshots the node's state, stamps identity, and
// writes one heartbeat frame. A failed write ends the stream via
// the reader's deadline; the send itself never blocks the agent:
// the write deadline bounds it.
func (a *meshAgent) sendHeartbeat(conn net.Conn) {
	snap := a.snapshot()
	a.mu.Lock()
	term := a.coord.Current().Term
	role := "plain"
	if a.coord.IsChief() {
		role = "chief"
	}
	version := a.appliedVersion
	a.mu.Unlock()
	hb := mesh.Heartbeat{
		NodeID:            a.nodeID,
		Role:              role,
		Version:           versionString(),
		Term:              term,
		CapacityBps:       snap.CapacityBps,
		Loss:              snap.Loss,
		LegRTTMs:          0,
		LegOK:             snap.LegOK,
		ActiveStreams:     snap.ActiveStreams,
		Classes:           snap.Classes,
		Resolvers:         snap.Resolvers,
		ForwardPortsBound: snap.ForwardPortsBound,
		ConfigVersion:     version,
		SentAt:            time.Now().UTC(),
	}
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := mesh.WriteFrame(conn, mesh.KindHeartbeat, hb); err != nil {
		if a.log != nil {
			a.log.Debugf("mesh: heartbeat write failed: %v", err)
		}
		// Break the reader out: closing the stream is the only
		// signal the read loop needs.
		_ = conn.Close()
	}
}

func versionString() string {
	return version.GetVersion()
}

// handleFrame dispatches one mother frame. It returns false when
// the stream must end (a malformed frame is a broken peer: drop
// and re-open rather than guess).
func (a *meshAgent) handleFrame(conn net.Conn, frame mesh.Frame) bool {
	switch frame.Kind {
	case mesh.KindTable:
		var push mesh.TablePush
		if err := frame.Decode(&push); err != nil {
			if a.log != nil {
				a.log.Warnf("mesh: malformed table push: %v", err)
			}
			return false
		}
		a.applyTable(push)
		return true
	case mesh.KindConfig:
		var push mesh.ConfigPush
		if err := frame.Decode(&push); err != nil {
			if a.log != nil {
				a.log.Warnf("mesh: malformed config push: %v", err)
			}
			return false
		}
		a.sendAck(conn, mesh.KindConfig, a.applyConfigPush(push))
		return true
	case mesh.KindRotation:
		var order mesh.RotationOrder
		if err := frame.Decode(&order); err != nil {
			if a.log != nil {
				a.log.Warnf("mesh: malformed rotation order: %v", err)
			}
			return false
		}
		a.sendAck(conn, mesh.KindRotation, a.applyRotation(order))
		return true
	case mesh.KindTerm:
		var ann mesh.TermAnnouncement
		if err := frame.Decode(&ann); err != nil {
			if a.log != nil {
				a.log.Warnf("mesh: malformed term announcement: %v", err)
			}
			return false
		}
		a.sendAck(conn, mesh.KindTerm, a.applyTermAnnouncement(ann))
		return true
	default:
		// The mother never sends heartbeats or acks. Unknown
		// kinds are ignored (forward-compatible), never acted on.
		if a.log != nil {
			a.log.Warnf("mesh: unexpected %q frame ignored", frame.Kind)
		}
		return true
	}
}

// sendAck writes one ack frame. A failed ack write is logged, not
// fatal: the next heartbeat carries the applied state anyway.
func (a *meshAgent) sendAck(conn net.Conn, forKind mesh.FrameKind, ack mesh.Ack) {
	ack.For = forKind
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := mesh.WriteFrame(conn, mesh.KindAck, ack); err != nil && a.log != nil {
		a.log.Warnf("mesh: ack write for %q failed: %v", forKind, err)
	}
}

// applyTable enforces one membership table by the term rule and
// records mother contact. A rejected table (stale term) is normal
// during transitions and is logged, never partially applied. A
// signed snapshot is recorded only when this node holds a
// verification key; without one it is ignored and the plain
// table still applies.
func (a *meshAgent) applyTable(push mesh.TablePush) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.coord.NoteMotherAnnouncement(time.Now())
	if push.Snapshot != nil {
		a.coord.NoteSignedSnapshot(*push.Snapshot)
	}
	if a.coord.ApplyTable(push.Table) {
		a.lastTable = push.Table
		a.haveTable = true
		if a.log != nil {
			a.log.Infof("mesh: table applied: term=%s version=%d chief=%q members=%d", push.Table.Term, push.Table.Version, push.Table.ChiefID, len(push.Table.Members))
		}
		a.poke()
	} else if a.log != nil {
		a.log.Debugf("mesh: table ignored (term rule): term=%s version=%d chief=%q", push.Table.Term, push.Table.Version, push.Table.ChiefID)
	}
}

// applyConfigPush stages, validates, and installs one config push
// (§4.3), returning the ack. Nothing is written unless the staged
// config validates with the node's own overrides; a push that
// would change the node's identity or key file is refused. The
// installed config takes effect on restart (session-layer
// live-apply is future work), so every successful push acks
// RestartRequired. A redelivered push at the applied version acks
// success without rewriting; a stale version is refused.
func (a *meshAgent) applyConfigPush(push mesh.ConfigPush) mesh.Ack {
	a.mu.Lock()
	defer a.mu.Unlock()
	if push.Version == a.appliedVersion && a.appliedVersion != 0 {
		return mesh.Ack{AppliedVersion: a.appliedVersion, Message: "config push already applied"}
	}
	if push.Version < a.appliedVersion || push.Version == 0 {
		return mesh.Ack{AppliedVersion: a.appliedVersion, Error: fmt.Sprintf("stale config version %d (applied %d)", push.Version, a.appliedVersion)}
	}
	if strings.TrimSpace(push.TOML) == "" {
		return mesh.Ack{AppliedVersion: a.appliedVersion, Error: "empty config push"}
	}
	dir := filepath.Dir(a.configPath)
	staging, err := os.CreateTemp(dir, ".nexounel-config-push-*")
	if err != nil {
		return mesh.Ack{AppliedVersion: a.appliedVersion, Error: fmt.Sprintf("stage config push: %v", err)}
	}
	stagingName := staging.Name()
	defer os.Remove(stagingName)
	if _, err := staging.WriteString(push.TOML); err != nil {
		_ = staging.Close()
		return mesh.Ack{AppliedVersion: a.appliedVersion, Error: fmt.Sprintf("write staged config: %v", err)}
	}
	if err := staging.Close(); err != nil {
		return mesh.Ack{AppliedVersion: a.appliedVersion, Error: fmt.Sprintf("close staged config: %v", err)}
	}
	parsed, err := config.LoadClientConfigWithOverrides(stagingName, a.overrides)
	if err != nil {
		return mesh.Ack{AppliedVersion: a.appliedVersion, Error: fmt.Sprintf("pushed config does not validate: %v", err)}
	}
	if parsed.NodeID != a.nodeID {
		return mesh.Ack{AppliedVersion: a.appliedVersion, Error: fmt.Sprintf("pushed config changes node id %q to %q", a.nodeID, parsed.NodeID)}
	}
	if parsed.NodeKeyFile != a.cfg.NodeKeyFile {
		return mesh.Ack{AppliedVersion: a.appliedVersion, Error: "pushed config changes the node key file"}
	}
	if err := os.Rename(stagingName, a.configPath); err != nil {
		return mesh.Ack{AppliedVersion: a.appliedVersion, Error: fmt.Sprintf("install pushed config: %v", err)}
	}
	if err := storeAppliedConfigVersion(a.configPath, push.Version); err != nil {
		// The config is installed but the version record failed:
		// report it, so the panel flags the divergence instead
		// of believing the push fully landed.
		return mesh.Ack{AppliedVersion: a.appliedVersion, Error: fmt.Sprintf("config installed but version record failed: %v", err)}
	}
	a.appliedVersion = push.Version
	if a.log != nil {
		a.log.Infof("mesh: config push v%d installed; restart the node to apply it", push.Version)
	}
	a.poke()
	return mesh.Ack{AppliedVersion: push.Version, RestartRequired: true, Message: "config staged; restart the node to apply it"}
}

// applyRotation installs one rotation order (§8.2): the new key is
// written atomically to the node key file (0600, hex + newline,
// the same format enrollment writes). Current sessions keep their
// codec; new sessions after a restart use the new key, so the ack
// says RestartRequired. A wrong-node order or malformed key is
// refused with nothing written.
func (a *meshAgent) applyRotation(order mesh.RotationOrder) mesh.Ack {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.coord.NoteMotherAnnouncement(time.Now())
	if order.NodeID != a.nodeID {
		return mesh.Ack{Error: fmt.Sprintf("rotation order for node %q, not %q", order.NodeID, a.nodeID)}
	}
	keyHex := strings.TrimSpace(order.NewKeyHex)
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return mesh.Ack{Error: "rotation order carries a malformed key (want 64 hex chars)"}
	}
	if err := writeFileAtomic(a.cfg.NodeKeyFile, []byte(keyHex+"\n"), 0o600); err != nil {
		return mesh.Ack{Error: fmt.Sprintf("write rotated key file: %v", err)}
	}
	if a.log != nil {
		a.log.Infof("mesh: rotated node key installed (%s); restart the node to re-register under it", order.Reason)
	}
	a.poke()
	return mesh.Ack{RestartRequired: true, Message: "rotated key installed; restart the node to re-register under it"}
}

// applyTermAnnouncement records mother contact and honors a
// step-down order: the local chief claim is relinquished and the
// request is remembered for the (future) chief loop. The term
// itself travels with tables; this frame's term is informational
// except for the step-down flag.
func (a *meshAgent) applyTermAnnouncement(ann mesh.TermAnnouncement) mesh.Ack {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.coord.NoteMotherAnnouncement(time.Now())
	if !ann.StepDown {
		return mesh.Ack{Message: fmt.Sprintf("term announcement %s recorded", ann.Term)}
	}
	wasChief := a.coord.StepDown()
	a.stepDownReq = true
	a.stepDownTerm = ann.Term
	if a.log != nil {
		a.log.Infof("mesh: step-down order honored (was chief: %v, term %s, reason: %s)", wasChief, ann.Term, ann.Reason)
	}
	a.poke()
	return mesh.Ack{Message: fmt.Sprintf("stepped down (was chief: %v)", wasChief)}
}

// StepDownRequested reports whether the mother ordered this node to
// step down, and the term of the order. The chief loop (future
// work) consumes it; until then it is recorded state only.
func (a *meshAgent) StepDownRequested() (bool, mesh.Term) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stepDownReq, a.stepDownTerm
}

// CurrentTable returns the enforced membership table, if any.
func (a *meshAgent) CurrentTable() (mesh.Table, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastTable, a.haveTable
}

// heartbeatCapacity aggregates probe results into the heartbeat's
// capacity/loss pair: CapacityBps is the raw download-MTU ceiling
// summed over valid resolvers, Loss the MTU-weighted mean loss.
// Invalid rows contribute nothing. It is shared by the single- and
// multi-session snapshot builders.
func heartbeatCapacity(results []multisession.ProbeResult) (capacityBps float64, loss float64) {
	var weightedLoss float64
	for _, r := range results {
		if !r.Valid || r.DownloadMTU <= 0 {
			continue
		}
		capacityBps += float64(r.DownloadMTU)
		weightedLoss += float64(r.DownloadMTU) * r.Loss
	}
	if capacityBps > 0 {
		loss = weightedLoss / capacityBps
	}
	return capacityBps, loss
}

// heartbeatResolvers maps probe results to heartbeat resolver
// health: valid rows are usable, the rest rejected.
func heartbeatResolvers(results []multisession.ProbeResult) []mesh.ResolverHealth {
	out := make([]mesh.ResolverHealth, 0, len(results))
	for _, r := range results {
		state := "rejected"
		if r.Valid {
			state = "usable"
		}
		out = append(out, mesh.ResolverHealth{
			Address:     r.Resolver + ":" + strconv.Itoa(r.Port),
			State:       state,
			UploadMTU:   r.UploadMTU,
			DownloadMTU: r.DownloadMTU,
			Loss:        r.Loss,
		})
	}
	return out
}

// singleSessionSnapshot builds the heartbeat snapshot for one
// client: a single class from the synced operating point.
func singleSessionSnapshot(app *client.Client) heartbeatSnapshot {
	if app == nil {
		return heartbeatSnapshot{}
	}
	results := app.ProbeResults()
	capacity, loss := heartbeatCapacity(results)
	up, down := app.SyncedMTUs()
	valid := 0
	for _, r := range results {
		if r.Valid {
			valid++
		}
	}
	ready := app.SessionReady()
	bound := 0
	if ready {
		bound = 1
	}
	return heartbeatSnapshot{
		CapacityBps:   capacity,
		Loss:          loss,
		LegOK:         ready,
		ActiveStreams: app.ActiveStreamCount(),
		Classes: []mesh.ClassCapacity{
			{UploadMTU: up, DownloadMTU: down, Members: valid, Weight: 1},
		},
		Resolvers:         heartbeatResolvers(results),
		ForwardPortsBound: bound,
	}
}

// multiSessionSnapshot builds the heartbeat snapshot for the class
// coordinator: one class entry per capacity class, resolvers
// deduplicated across class clients (best row wins, matching
// ProbeResults' own dedup rule).
func multiSessionSnapshot(classes []multisession.Class, clients []*client.Client) heartbeatSnapshot {
	snap := heartbeatSnapshot{
		Classes: make([]mesh.ClassCapacity, 0, len(classes)),
	}
	seen := make(map[string]multisession.ProbeResult)
	var all []multisession.ProbeResult
	for i, class := range classes {
		snap.Classes = append(snap.Classes, mesh.ClassCapacity{
			UploadMTU:   class.OperatingUpload,
			DownloadMTU: class.OperatingDownload,
			Members:     len(class.Members),
			Weight:      multisession.Weight(class),
		})
		if i < len(clients) && clients[i] != nil {
			for _, r := range clients[i].ProbeResults() {
				key := r.Resolver + ":" + strconv.Itoa(r.Port)
				if prev, ok := seen[key]; !ok || r.DownloadMTU > prev.DownloadMTU ||
					(r.DownloadMTU == prev.DownloadMTU && r.UploadMTU > prev.UploadMTU) {
					seen[key] = r
				}
			}
			snap.ActiveStreams += clients[i].ActiveStreamCount()
			if clients[i].SessionReady() {
				snap.LegOK = true
			}
		}
	}
	for _, r := range seen {
		all = append(all, r)
	}
	snap.CapacityBps, snap.Loss = heartbeatCapacity(all)
	snap.Resolvers = heartbeatResolvers(all)
	return snap
}
