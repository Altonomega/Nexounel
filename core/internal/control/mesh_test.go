package control

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/mesh"
)

type fakeMeshSource struct {
	snap MeshSnapshot
	err  error
}

func (f *fakeMeshSource) MeshSnapshot() (MeshSnapshot, error) {
	if f.err != nil {
		return MeshSnapshot{}, f.err
	}
	return f.snap, nil
}

func testMeshSnapshot() MeshSnapshot {
	return MeshSnapshot{
		Table: mesh.Table{
			Term:    mesh.Term{Number: 2},
			Version: 5,
			ChiefID: "node-a",
			Members: []mesh.Member{
				{ID: "node-a", State: mesh.StateActive, CapacityBps: 500, TenureSeq: 1},
				{ID: "node-b", State: mesh.StateSuspect, CapacityBps: 100, TenureSeq: 2},
			},
			Weights: map[string]float64{"node-a": 0.8, "node-b": 0},
		},
		Heartbeats: []MeshHeartbeatSummary{
			{NodeID: "node-a", State: mesh.StateActive, CapacityBps: 500, LegOK: true, StreamConnected: true, LastSeen: time.Now().UTC().Truncate(time.Second)},
			{NodeID: "node-b", State: mesh.StateSuspect, CapacityBps: 100, LastAckFor: "config", LastAckError: "stale config version"},
		},
		SnapshotSigning: true,
		GeneratedAt:     time.Now().UTC().Truncate(time.Second),
	}
}

func TestListMeshHandler(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	writeTestRegistry(t, regPath, registryContent("id = \"node-a\"\nkey = \""+testKeyA+"\""))
	h, _ := NewRegistryHandler(regPath, 5, &fakeSwapper{})
	// Without a source the command is refused, never an empty table.
	resp := h.Handle(context.Background(), Request{Version: ProtocolVersion, Command: CmdListMesh})
	if resp.OK {
		t.Fatal("list-mesh without a mesh source must fail")
	}
	h.SetMeshSource(&fakeMeshSource{snap: testMeshSnapshot()})
	resp = h.Handle(context.Background(), Request{Version: ProtocolVersion, Command: CmdListMesh})
	if !resp.OK {
		t.Fatalf("list-mesh: %v", resp.Error)
	}
	if _, ok := resp.Data["mesh"]; !ok {
		t.Fatalf("response carries no mesh snapshot: %v", resp.Data)
	}
}

func TestListMeshSourceError(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	writeTestRegistry(t, regPath, registryContent("id = \"node-a\"\nkey = \""+testKeyA+"\""))
	h, _ := NewRegistryHandler(regPath, 5, &fakeSwapper{})
	h.SetMeshSource(&fakeMeshSource{err: errors.New("coordinator unavailable")})
	resp := h.Handle(context.Background(), Request{Version: ProtocolVersion, Command: CmdListMesh})
	if resp.OK || resp.Error != "coordinator unavailable" {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestListMeshSocketRoundTrip(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	writeTestRegistry(t, regPath, registryContent("id = \"node-a\"\nkey = \""+testKeyA+"\""))
	h, _ := NewRegistryHandler(regPath, 5, &fakeSwapper{})
	h.SetMeshSource(&fakeMeshSource{snap: testMeshSnapshot()})
	path, _ := startTestSocket(t, h)
	snap, err := Client{SocketPath: path}.ListMesh(context.Background())
	if err != nil {
		t.Fatalf("ListMesh: %v", err)
	}
	if snap.Table.ChiefID != "node-a" || snap.Table.Term.Number != 2 || snap.Table.Version != 5 {
		t.Errorf("table = %+v", snap.Table)
	}
	if !snap.SnapshotSigning {
		t.Error("snapshot_signing must round-trip true")
	}
	if len(snap.Heartbeats) != 2 {
		t.Fatalf("heartbeats = %+v", snap.Heartbeats)
	}
	if snap.Heartbeats[0].NodeID != "node-a" || !snap.Heartbeats[0].StreamConnected {
		t.Errorf("heartbeat[0] = %+v", snap.Heartbeats[0])
	}
	if snap.Heartbeats[1].LastAckError != "stale config version" {
		t.Errorf("heartbeat[1] = %+v", snap.Heartbeats[1])
	}
}
