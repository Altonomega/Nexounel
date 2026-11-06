package udpserver

import (
	"encoding/binary"
	"testing"

	"github.com/Altonomega/Nexounel/core/internal/security"
)

// TestTwoConcurrentSessionsDifferentMTUsAndKeys proves the session
// store invariant multi-session operation depends on: two sessions
// opened with different node keys and different advertised MTUs coexist
// as independent records, each keeping its own codec and MTUs, and a
// replayed init reuses only the record opened with the same key.
// Live end-to-end proof (real binaries, loopback) is the lab test;
// this pins the store-level contract the lab relies on.
func TestTwoConcurrentSessionsDifferentMTUsAndKeys(t *testing.T) {
	codecA, err := security.NewCodec(5, "node-a-key-two-sessions-test")
	if err != nil {
		t.Fatal(err)
	}
	codecB, err := security.NewCodec(5, "node-b-key-two-sessions-test")
	if err != nil {
		t.Fatal(err)
	}

	store := newSessionStore(8, 32)
	store.setClientMTUCeilings(0, 0) // no ceilings: advertised MTUs pass through

	initPayload := func(upload, download uint16, verify byte) []byte {
		payload := make([]byte, sessionInitDataSize)
		payload[0] = 0 // plain response mode
		payload[1] = 0 // no compression
		binary.BigEndian.PutUint16(payload[2:4], upload)
		binary.BigEndian.PutUint16(payload[4:6], download)
		for i := 6; i < 10; i++ {
			payload[i] = verify
		}
		return payload
	}

	payloadA := initPayload(120, 400, 0xA1)
	recA, reusedA, err := store.findOrCreate(payloadA, 0, 0, 4, false, codecA)
	if err != nil {
		t.Fatalf("session A: %v", err)
	}
	if reusedA || recA == nil {
		t.Fatalf("session A: reused=%v rec=%v, want fresh record", reusedA, recA)
	}

	payloadB := initPayload(180, 1200, 0xB2)
	recB, reusedB, err := store.findOrCreate(payloadB, 0, 0, 4, false, codecB)
	if err != nil {
		t.Fatalf("session B: %v", err)
	}
	if reusedB || recB == nil {
		t.Fatalf("session B: reused=%v rec=%v, want fresh record", reusedB, recB)
	}

	if recA == recB || recA.ID == recB.ID {
		t.Fatalf("sessions collided: A=%p/%d B=%p/%d", recA, recA.ID, recB, recB.ID)
	}
	if recA.Codec != codecA || recB.Codec != codecB {
		t.Fatal("session records did not keep their opening codec")
	}
	if recA.UploadMTU != 120 || recA.DownloadMTU != 400 {
		t.Fatalf("session A MTUs = %d/%d, want 120/400", recA.UploadMTU, recA.DownloadMTU)
	}
	if recB.UploadMTU != 180 || recB.DownloadMTU != 1200 {
		t.Fatalf("session B MTUs = %d/%d, want 180/1200", recB.UploadMTU, recB.DownloadMTU)
	}

	// Both records stay live concurrently.
	if got, ok := store.Get(recA.ID); !ok || got != recA {
		t.Fatal("session A not retrievable after B was created")
	}
	if got, ok := store.Get(recB.ID); !ok || got != recB {
		t.Fatal("session B not retrievable")
	}

	// Node attribution follows the opening codec.
	srv := &Server{}
	srv.SetNodeCodecs([]*security.Codec{codecA, codecB}, []string{"node-a", "node-b"})
	if got := srv.nodeIDForCodec(recA.Codec); got != "node-a" {
		t.Fatalf("session A node = %q, want node-a", got)
	}
	if got := srv.nodeIDForCodec(recB.Codec); got != "node-b" {
		t.Fatalf("session B node = %q, want node-b", got)
	}

	// Replayed init with the same key reuses the same record.
	recA2, reused, err := store.findOrCreate(payloadA, 0, 0, 4, false, codecA)
	if err != nil || !reused || recA2 != recA {
		t.Fatalf("replay: reused=%v same=%v err=%v, want reuse of A", reused, recA2 == recA, err)
	}

	// Same init bytes under the OTHER key must not reuse A's record:
	// the store keys reuse on (signature, codec) identity.
	recC, reused, err := store.findOrCreate(payloadA, 0, 0, 4, false, codecB)
	if err != nil || reused || recC == nil || recC == recA {
		t.Fatalf("cross-key init: reused=%v sameAsA=%v err=%v, want a fresh record", reused, recC == recA, err)
	}
	if recC.Codec != codecB {
		t.Fatal("cross-key record did not keep codec B")
	}
}
