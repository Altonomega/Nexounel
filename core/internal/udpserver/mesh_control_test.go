package udpserver

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
	"github.com/MNSH-Nexo/Nexounel/core/internal/mesh"
)

func TestInitMeshBuildsFirstTable(t *testing.T) {
	srv := &Server{mesh: newMeshState(nil)}
	srv.InitMesh([]string{"node-b", "node-a"}, nil)
	table := srv.mesh.coord.Current()
	if table.Term != (mesh.Term{Number: 1}) || table.Version != 1 {
		t.Errorf("table = term %v version %d, want T1 v1", table.Term, table.Version)
	}
	if table.ChiefID != "node-b" {
		t.Errorf("chief = %q, want node-b (first in registry order = longest tenure)", table.ChiefID)
	}
	if len(table.Members) != 2 || table.Members[0].TenureSeq != 1 || table.Members[1].TenureSeq != 2 {
		t.Errorf("members = %+v", table.Members)
	}
	for _, m := range table.Members {
		if m.State != mesh.StateActive {
			t.Errorf("member %q state = %s, want ACTIVE", m.ID, m.State)
		}
		if table.Weights[m.ID] != 0 {
			t.Errorf("member %q weight = %v, want 0 until first heartbeat", m.ID, table.Weights[m.ID])
		}
	}
}

func TestHandleHeartbeatAdmitsUnknownMember(t *testing.T) {
	st := newMeshState(nil)
	st.coord.ApplyTable(mesh.Table{Term: mesh.Term{Number: 1}, Version: 1})
	hb := mesh.Heartbeat{NodeID: "node-x", CapacityBps: 500, Loss: 0.1, LegOK: true}
	push, err := st.handleHeartbeat(hb, "node-x")
	if err != nil {
		t.Fatalf("handleHeartbeat: %v", err)
	}
	found := false
	for _, m := range push.Table.Members {
		if m.ID == "node-x" {
			found = true
			if m.CapacityBps != 500 || m.Loss != 0.1 {
				t.Errorf("member = %+v, want folded heartbeat values", m)
			}
		}
	}
	if !found {
		t.Fatalf("table %+v does not contain node-x", push.Table)
	}
	if push.Table.ChiefID != "node-x" {
		t.Errorf("chief = %q, want node-x (sole member)", push.Table.ChiefID)
	}
	if push.Snapshot != nil {
		t.Error("unsigned state must not attach a snapshot")
	}
	if _, ok := st.heartbeats["node-x"]; !ok {
		t.Error("heartbeat was not recorded")
	}
}

func TestHandleHeartbeatRejectsIdentityMismatch(t *testing.T) {
	st := newMeshState(nil)
	if _, err := st.handleHeartbeat(mesh.Heartbeat{NodeID: "node-a"}, "node-b"); err == nil {
		t.Fatal("heartbeat with a mismatched session identity must be rejected")
	}
	if len(st.heartbeats) != 0 {
		t.Error("rejected heartbeat must not be recorded")
	}
}

func TestHandleHeartbeatRejectsInvalidNodeID(t *testing.T) {
	st := newMeshState(nil)
	if _, err := st.handleHeartbeat(mesh.Heartbeat{NodeID: "BAD ID"}, "BAD ID"); err == nil {
		t.Fatal("heartbeat with an invalid node id must be rejected")
	}
}

func TestHandleHeartbeatSignsSnapshotWhenKeyPresent(t *testing.T) {
	key := []byte("snapshot-signing-key-for-tests-only")
	st := newMeshState(key)
	push, err := st.handleHeartbeat(mesh.Heartbeat{NodeID: "node-1"}, "node-1")
	if err != nil {
		t.Fatalf("handleHeartbeat: %v", err)
	}
	if push.Snapshot == nil {
		t.Fatal("keyed state must attach a signed snapshot")
	}
	if !push.Snapshot.Verify(key) {
		t.Error("attached snapshot does not verify under the signing key")
	}
}

func TestEvaluateElectsSuccessorOnChiefLoss(t *testing.T) {
	srv := &Server{mesh: newMeshState(nil)}
	srv.InitMesh([]string{"node-a", "node-b"}, nil)
	st := srv.mesh
	t0 := time.Now()
	// Both members heartbeat at t0; only node-b keeps heartbeating.
	st.coord.NoteHeartbeat("node-a", 100, 0, 10, true, t0)
	st.coord.NoteHeartbeat("node-b", 500, 0, 10, true, t0)
	if st.coord.Current().ChiefID != "node-a" {
		t.Fatalf("chief = %q, want node-a", st.coord.Current().ChiefID)
	}
	later := t0.Add(61 * time.Second)
	st.coord.NoteHeartbeat("node-b", 500, 0, 10, true, later)
	events := st.evaluate(later)
	var found *mesh.Event
	for _, e := range events {
		if e.Kind == mesh.EventChiefLost {
			ev := e
			found = &ev
		}
	}
	if found == nil {
		t.Fatalf("expected a chief-lost event, got %v", events)
	}
	if found.Successor != "node-b" || found.Term != (mesh.Term{Number: 2}) {
		t.Errorf("election = successor %q term %v, want node-b T2", found.Successor, found.Term)
	}
	cur := st.coord.Current()
	if cur.ChiefID != "node-b" {
		t.Errorf("chief after election = %q, want node-b", cur.ChiefID)
	}
	if cur.Term != (mesh.Term{Number: 2}) {
		t.Errorf("term after election = %v, want T2", cur.Term)
	}
}

func TestEvaluateMarksSuspectAndDown(t *testing.T) {
	st := newMeshState(nil)
	st.coord.ApplyTable(mesh.Table{Term: mesh.Term{Number: 1}, Version: 1, ChiefID: "node-a", Members: []mesh.Member{
		{ID: "node-a", State: mesh.StateActive, TenureSeq: 1},
		{ID: "node-b", State: mesh.StateActive, TenureSeq: 2},
	}})
	t0 := time.Now()
	st.coord.NoteHeartbeat("node-a", 100, 0, 10, true, t0)
	st.coord.NoteHeartbeat("node-b", 100, 0, 10, true, t0)
	events := st.evaluate(t0.Add(61 * time.Second))
	var suspect bool
	for _, e := range events {
		if e.Kind == mesh.EventNodeSuspect {
			suspect = true
		}
	}
	if !suspect {
		t.Fatalf("expected suspect events, got %v", events)
	}
	for _, m := range st.coord.Current().Members {
		if m.State != mesh.StateSuspect {
			t.Errorf("member %q state = %s, want SUSPECT", m.ID, m.State)
		}
	}
	events = st.evaluate(t0.Add(121 * time.Second))
	var down int
	for _, e := range events {
		if e.Kind == mesh.EventNodeDown {
			down++
		}
	}
	if down != 2 {
		t.Fatalf("expected 2 down events, got %v", events)
	}
}

func TestServeControlStreamExchange(t *testing.T) {
	srv := &Server{mesh: newMeshState(nil)}
	srv.InitMesh([]string{"node-1"}, nil)
	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.serveControlStream(serverEnd, &sessionRecord{ID: 1, Kind: enroll.SessionKindNormal, NodeID: "node-1"})
	}()
	_ = clientEnd.SetDeadline(time.Now().Add(10 * time.Second))
	// Heartbeat in, table out.
	if err := mesh.WriteFrame(clientEnd, mesh.KindHeartbeat, mesh.Heartbeat{NodeID: "node-1", CapacityBps: 500, LegOK: true}); err != nil {
		t.Fatalf("write heartbeat: %v", err)
	}
	frame, err := mesh.ReadFrame(clientEnd)
	if err != nil {
		t.Fatalf("read table push: %v", err)
	}
	if frame.Kind != mesh.KindTable {
		t.Fatalf("kind = %q, want table", frame.Kind)
	}
	var push mesh.TablePush
	if err := frame.Decode(&push); err != nil {
		t.Fatalf("decode table push: %v", err)
	}
	if push.Table.ChiefID != "node-1" || len(push.Table.Members) != 1 {
		t.Errorf("table = %+v", push.Table)
	}
	// Ack in, recorded for the panel.
	if err := mesh.WriteFrame(clientEnd, mesh.KindAck, mesh.Ack{For: mesh.KindConfig, AppliedVersion: 3}); err != nil {
		t.Fatalf("write ack: %v", err)
	}
	// Give the handler a moment to record the ack (same-process
	// pipe: poll briefly rather than sleep blindly).
	deadline := time.Now().Add(2 * time.Second)
	for {
		snap, err := srv.MeshSnapshot()
		if err != nil {
			t.Fatalf("MeshSnapshot: %v", err)
		}
		if len(snap.Heartbeats) == 1 && snap.Heartbeats[0].LastAckFor == string(mesh.KindConfig) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ack not recorded: %+v", snap.Heartbeats)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Mother-originated delivery over the open stream. The pipe
	// is unbuffered, so delivery runs in its own goroutine while
	// this goroutine reads — a synchronous write-then-read would
	// deadlock (the write waits for the read).
	st := srv.mesh
	deliverErr := make(chan error, 1)
	go func() {
		deliverErr <- st.deliverFrame("node-1", mesh.KindConfig, mesh.ConfigPush{Version: 4, TOML: "NODE_ID=node-1\n"})
	}()
	frame, err = mesh.ReadFrame(clientEnd)
	if err != nil {
		t.Fatalf("read delivered frame: %v", err)
	}
	if err := <-deliverErr; err != nil {
		t.Fatalf("deliverFrame: %v", err)
	}
	if frame.Kind != mesh.KindConfig {
		t.Fatalf("delivered kind = %q, want config", frame.Kind)
	}
	var cfg mesh.ConfigPush
	if err := frame.Decode(&cfg); err != nil || cfg.Version != 4 {
		t.Fatalf("delivered config = %+v, err %v", cfg, err)
	}
	// Closing the client end must end the handler.
	_ = clientEnd.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("control stream handler did not exit after the stream closed")
	}
	if _, ok := st.streams["node-1"]; ok {
		t.Error("closed stream must be unregistered")
	}
}

func TestServeControlStreamDeniesAnonymousAndBootstrap(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record *sessionRecord
	}{
		{"anonymous", &sessionRecord{ID: 1, Kind: enroll.SessionKindNormal, NodeID: ""}},
		{"bootstrap", &sessionRecord{ID: 1, Kind: enroll.SessionKindBootstrap, NodeID: "node-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{mesh: newMeshState(nil)}
			serverEnd, clientEnd := net.Pipe()
			defer clientEnd.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				srv.serveControlStream(serverEnd, tc.record)
			}()
			_ = clientEnd.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := mesh.ReadFrame(clientEnd); !errors.Is(err, io.EOF) {
				t.Fatalf("expected EOF (handler closed the stream), got %v", err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("denied handler did not exit")
			}
		})
	}
}

func TestServeControlStreamDeniesNilMesh(t *testing.T) {
	srv := &Server{}
	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.serveControlStream(serverEnd, &sessionRecord{ID: 1, Kind: enroll.SessionKindNormal, NodeID: "node-1"})
	}()
	_ = clientEnd.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := mesh.ReadFrame(clientEnd); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit")
	}
}

func TestServeControlStreamIgnoresUnknownKinds(t *testing.T) {
	srv := &Server{mesh: newMeshState(nil)}
	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.serveControlStream(serverEnd, &sessionRecord{ID: 1, Kind: enroll.SessionKindNormal, NodeID: "node-1"})
	}()
	_ = clientEnd.SetDeadline(time.Now().Add(5 * time.Second))
	// A term frame is mother-originated; from the node it must be
	// ignored, and the stream must stay up for the next heartbeat.
	if err := mesh.WriteFrame(clientEnd, mesh.KindTerm, mesh.TermAnnouncement{Term: mesh.Term{Number: 9}}); err != nil {
		t.Fatalf("write term frame: %v", err)
	}
	if err := mesh.WriteFrame(clientEnd, mesh.KindHeartbeat, mesh.Heartbeat{NodeID: "node-1"}); err != nil {
		t.Fatalf("write heartbeat: %v", err)
	}
	frame, err := mesh.ReadFrame(clientEnd)
	if err != nil {
		t.Fatalf("read table push: %v", err)
	}
	if frame.Kind != mesh.KindTable {
		t.Fatalf("kind = %q, want table", frame.Kind)
	}
	_ = clientEnd.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit")
	}
}

func TestDeliverFrameWithoutStreamFails(t *testing.T) {
	st := newMeshState(nil)
	if err := st.deliverFrame("node-1", mesh.KindConfig, mesh.ConfigPush{}); err == nil {
		t.Fatal("delivery without an open stream must fail")
	}
}

func TestMeshSnapshotUnavailableWithoutState(t *testing.T) {
	srv := &Server{}
	if _, err := srv.MeshSnapshot(); err == nil {
		t.Fatal("a server without mesh state must report unavailability, not an empty snapshot")
	}
}

func TestMeshLoopNoopsWithoutState(t *testing.T) {
	srv := &Server{}
	// Must return immediately, not block or panic.
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.MeshLoop(t.Context())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("MeshLoop without state did not return")
	}
}
