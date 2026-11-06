// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Tests for the scale-audit liveness pre-filter (F1b). The live path (a
// resolver answering) cannot be exercised in the sandbox — UDP loopback is
// blocked there — and is covered by reusing sendUploadMTUProbe verbatim;
// these tests pin the gate, the pool mechanics, and the dead path (timeout
// against an unanswered loopback address, which is exactly what the sandbox
// produces).
// ==============================================================================

package client

import (
	"context"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/config"
	"github.com/Altonomega/Nexounel/core/internal/security"
)

func TestLivenessPrefilterGate(t *testing.T) {
	if livenessPrefilterEnabled(0) || livenessPrefilterEnabled(256) {
		t.Fatal("pre-filter must stay off at or below the fleet gate")
	}
	if !livenessPrefilterEnabled(257) {
		t.Fatal("pre-filter must run above the fleet gate")
	}
}

func TestPrefilterLiveConnectionsWithStubProber(t *testing.T) {
	conns := make([]Connection, 300)
	for i := range conns {
		conns[i] = Connection{Resolver: "10.0.0.1", ResolverPort: 53, ResolverLabel: "10.0.0.1:53"}
	}
	c := &Client{connections: conns}
	indices := make([]int, len(conns))
	for i := range indices {
		indices[i] = i
	}
	// Stub: even indices answer, odd indices are dead.
	live := c.prefilterLiveConnectionsWithProber(context.Background(), indices, func(_ context.Context, conn *Connection) bool {
		for i := range conns {
			if &conns[i] == conn {
				return i%2 == 0
			}
		}
		return false
	})
	if len(live) != 150 {
		t.Fatalf("expected 150 live indices, got %d", len(live))
	}
	for i, idx := range live {
		if idx != i*2 {
			t.Fatalf("live[%d] = %d, want %d (order must be preserved)", i, idx, i*2)
		}
	}
}

func TestPrefilterLiveConnectionsGateKeepsSmallFleet(t *testing.T) {
	conns := make([]Connection, 100)
	c := &Client{connections: conns}
	indices := []int{0, 50, 99}
	called := 0
	out := c.prefilterLiveConnectionsWithProber(context.Background(), indices, func(_ context.Context, _ *Connection) bool {
		called++
		return false
	})
	if called != 0 {
		t.Fatalf("prober must not run for a gated fleet (called %d times)", called)
	}
	if len(out) != len(indices) {
		t.Fatalf("gated fleet must pass through unchanged: got %v", out)
	}
}

func TestPrefilterLiveConnectionsCancelledContextPassesThrough(t *testing.T) {
	conns := make([]Connection, 300)
	c := &Client{connections: conns}
	indices := make([]int, len(conns))
	for i := range indices {
		indices[i] = i
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := 0
	out := c.prefilterLiveConnectionsWithProber(ctx, indices, func(_ context.Context, _ *Connection) bool {
		called++
		return true
	})
	if called != 0 {
		t.Fatalf("prober must not run on a cancelled context (called %d times)", called)
	}
	if len(out) != len(indices) {
		t.Fatalf("cancelled context must pass indices through unchanged")
	}
}

func TestProbeConnectionLivenessDeadResolver(t *testing.T) {
	codec, err := security.NewCodec(5, "liveness-test-key")
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{
		cfg: config.ClientConfig{
			Domains:        []string{"tunnel.example.com"},
			MinUploadMTU:   100,
			MaxUploadMTU:   200,
			MinDownloadMTU: 1000,
			MaxDownloadMTU: 4000,
		},
		codec:          codec,
		mtuTestTimeout: 100 * time.Millisecond,
	}
	// 127.0.0.1:53 has no listener in the sandbox; UDP loopback delivery is
	// blocked there, so every probe times out: the dead path.
	conn := &Connection{
		Domain:        "tunnel.example.com",
		Resolver:      "127.0.0.1",
		ResolverPort:  53,
		ResolverLabel: "127.0.0.1:53",
	}
	start := time.Now()
	if c.probeConnectionLiveness(context.Background(), conn) {
		t.Fatal("unanswered resolver must report dead")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("dead probe took %v, want under 5s (2 attempts x short timeout)", elapsed)
	}
}
