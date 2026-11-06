package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/mesh"
)

// TestHeartbeatFleetScaleReachesMother reproduces the M2 field-test
// failure (2026-11-03): with the live 1,064-resolver fleet, the node
// sent 0 heartbeats in ~3 hours while its log stayed silent. The
// heartbeat carried one ResolverHealth entry per resolver, so the
// framed heartbeat exceeded mesh.MaxControlFrameBytes (64 KiB);
// WriteFrame failed, sendHeartbeat closed the stream at Debug level
// only, and the agent re-opened a stream that could never carry a
// heartbeat. A fleet-scale snapshot must therefore reach the mother
// as aggregate counts, never as a per-resolver list.
func TestHeartbeatFleetScaleReachesMother(t *testing.T) {
	dir := t.TempDir()
	agent, _, _, _, _ := meshTestAgent(t, dir)

	resolvers := make([]mesh.ResolverHealth, 0, 1064)
	for i := 0; i < 1064; i++ {
		state := "usable"
		loss := 0.05
		if i%10 == 0 {
			state = "rejected"
			loss = 0.9
		}
		resolvers = append(resolvers, mesh.ResolverHealth{
			Address:     fmt.Sprintf("198.51.100.%d:53", i%250+1),
			State:       state,
			UploadMTU:   110,
			DownloadMTU: 1015 + i%1463,
			Loss:        loss,
		})
	}
	agent.snapshot = func() heartbeatSnapshot {
		return heartbeatSnapshot{CapacityBps: 1500000, Loss: 0.1, LegOK: true, ActiveStreams: 2, ForwardPortsBound: 10, Resolvers: resolvers}
	}

	motherEnd, agentEnd := net.Pipe()
	defer motherEnd.Close()
	defer agentEnd.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		agent.serve(ctx, agentEnd)
	}()
	_ = motherEnd.SetDeadline(time.Now().Add(10 * time.Second))

	frame, err := mesh.ReadFrame(motherEnd)
	if err != nil {
		t.Fatalf("no heartbeat reached the mother: %v (fleet-scale heartbeat must fit one control frame)", err)
	}
	if frame.Kind != mesh.KindHeartbeat {
		t.Fatalf("first frame kind = %q, want heartbeat", frame.Kind)
	}
	var hb mesh.Heartbeat
	if err := frame.Decode(&hb); err != nil {
		t.Fatalf("decode heartbeat: %v", err)
	}
	if hb.NodeID != "node-1" || !hb.LegOK || hb.ForwardPortsBound != 10 {
		t.Fatalf("heartbeat = %+v, want node-1, leg OK, 10 forward ports", hb)
	}
	if len(hb.Resolvers) != 0 {
		t.Fatalf("heartbeat carries %d per-resolver entries; the mother never consumes the list and it blows the frame limit", len(hb.Resolvers))
	}
	if hb.ResolverUsable+hb.ResolverRejected != 1064 {
		t.Fatalf("resolver counts = %d usable + %d rejected, want 1064 total", hb.ResolverUsable, hb.ResolverRejected)
	}
	_ = motherEnd.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("agent serve did not exit after the stream closed")
	}
}
