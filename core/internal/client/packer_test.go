// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Tests for the outbound segment Packer and its dispatcher gate. All tests
// are loopback/in-process only: no network, no live servers, fixtures use
// synthetic payloads and example domains only (see createTestClient).
package client

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	Enums "github.com/MNSH-Nexo/Nexounel/core/internal/enums"
	"github.com/MNSH-Nexo/Nexounel/core/internal/mlq"
	VpnProto "github.com/MNSH-Nexo/Nexounel/core/internal/vpnproto"
)

func collectBatches(t *testing.T, emits chan [][]byte) [][][]byte {
	t.Helper()
	var batches [][][]byte
	for {
		select {
		case b := <-emits:
			batches = append(batches, b)
		default:
			return batches
		}
	}
}

func flattenBatches(batches [][][]byte) [][]byte {
	var out [][]byte
	for _, b := range batches {
		out = append(out, b...)
	}
	return out
}

func batchBytes(batch [][]byte) int {
	n := 0
	for _, s := range batch {
		n += len(s)
	}
	return n
}

func segmentsEqual(t *testing.T, got, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("segment count = %d, want %d (got %q, want %q)", len(got), len(want), got, want)
	}
	for i := range want {
		if string(got[i]) != string(want[i]) {
			t.Fatalf("segment %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestPackerFlushOnMTUBudget: batches fill to the caller-supplied MTU
// budget and never split a segment.
func TestPackerFlushOnMTUBudget(t *testing.T) {
	emits := make(chan [][]byte, 16)
	p := NewPacker(PackerConfig{MTUBudget: 110, MaxDelay: time.Second, MaxBufferBytes: 1 << 20}, func(b [][]byte) { emits <- b })
	defer func() { _ = p.Close() }()

	// 40-byte segments against a 110-byte budget.
	segs := [][]byte{
		make([]byte, 40), make([]byte, 40), make([]byte, 40), make([]byte, 40),
	}
	for i := range segs {
		for j := range segs[i] {
			segs[i][j] = byte('a' + i)
		}
	}
	for _, s := range segs {
		if !p.Add(s) {
			t.Fatal("Add returned false on an open Packer")
		}
	}
	// 40+40=80 buffered; the third would reach 120 > 110, so it
	// pre-flushes [40,40] on arrival and buffers the third; the fourth
	// (40+40=80 <= 110) joins it. One 80-byte batch is emitted, one
	// 80-byte batch remains buffered for Flush.
	batches := collectBatches(t, emits)
	if len(batches) != 1 {
		t.Fatalf("emitted batches = %d, want 1", len(batches))
	}
	if n := batchBytes(batches[0]); n != 80 {
		t.Fatalf("batch 0 bytes = %d, want 80", n)
	}
	rest := p.Flush()
	if rest == nil || batchBytes(rest) != 80 {
		t.Fatalf("drained batch bytes = %v, want one 80-byte batch", rest)
	}
	if p.Len() != 0 || p.PendingBytes() != 0 {
		t.Fatal("Packer not empty after flush")
	}
	// Concatenated emission order must reproduce the input exactly.
	all := append(flattenBatches(batches), rest...)
	segmentsEqual(t, all, segs)
	for _, b := range batches {
		if batchBytes(b) > 110 {
			t.Fatalf("batch of %d bytes exceeds MTU budget 110", batchBytes(b))
		}
	}
}

// TestPackerFlushOnTimerExpiry: a sparse stream is flushed by the delay
// budget even though the MTU budget is never reached.
func TestPackerFlushOnTimerExpiry(t *testing.T) {
	emits := make(chan [][]byte, 4)
	p := NewPacker(PackerConfig{MTUBudget: 1 << 20, MaxDelay: 30 * time.Millisecond, MaxBufferBytes: 1 << 20}, func(b [][]byte) { emits <- b })
	defer func() { _ = p.Close() }()

	if !p.Add([]byte("first")) || !p.Add([]byte("second")) {
		t.Fatal("Add returned false on an open Packer")
	}
	select {
	case b := <-emits:
		t.Fatalf("batch emitted before delay expiry: %q", b)
	case <-time.After(15 * time.Millisecond):
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		select {
		case b := <-emits:
			segmentsEqual(t, b, [][]byte{[]byte("first"), []byte("second")})
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("no batch emitted within 500ms of the 30ms delay budget")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestPackerFlushOnBufferCap: the absolute buffer ceiling flushes even
// when the MTU budget is effectively unbounded.
func TestPackerFlushOnBufferCap(t *testing.T) {
	emits := make(chan [][]byte, 16)
	// Small cap on purpose (below the operator floor of 1024; the
	// config layer enforces that floor — see TestPackingConfigClamps).
	p := NewPacker(PackerConfig{MTUBudget: 1 << 20, MaxDelay: time.Second, MaxBufferBytes: 100}, func(b [][]byte) { emits <- b })
	defer func() { _ = p.Close() }()

	for i := 0; i < 3; i++ {
		if !p.Add(make([]byte, 40)) {
			t.Fatal("Add returned false on an open Packer")
		}
	}
	// 40, 80 buffered; the third would reach 120 > cap 100, so it
	// pre-flushes the 80 buffered bytes and buffers the last 40.
	batches := collectBatches(t, emits)
	if len(batches) != 1 || batchBytes(batches[0]) != 80 {
		t.Fatalf("batches = %v, want one 80-byte pre-flush", batches)
	}
	rest := p.Flush()
	if rest == nil || batchBytes(rest) != 40 {
		t.Fatalf("drained = %v, want one 40-byte segment", rest)
	}
	if p.Len() != 0 {
		t.Fatal("buffer not drained by Flush")
	}

	// Exact cap: 50+50 reaches the 100-byte cap without overshoot, so
	// the size rule (buffered >= cap) flushes both together.
	emits2 := make(chan [][]byte, 16)
	pExact := NewPacker(PackerConfig{MTUBudget: 1 << 20, MaxDelay: time.Second, MaxBufferBytes: 100}, func(b [][]byte) { emits2 <- b })
	defer func() { _ = pExact.Close() }()
	_ = pExact.Add(make([]byte, 50))
	_ = pExact.Add(make([]byte, 50))
	batches = collectBatches(t, emits2)
	if len(batches) != 1 || batchBytes(batches[0]) != 100 {
		t.Fatalf("batches = %v, want one 100-byte cap flush", batches)
	}

	// Overshoot-before-append: 60 buffered, a second 60 would exceed the
	// cap, so the first flushes alone and the second stays buffered.
	p2 := NewPacker(PackerConfig{MTUBudget: 1 << 20, MaxDelay: time.Second, MaxBufferBytes: 100}, func(b [][]byte) { emits <- b })
	defer func() { _ = p2.Close() }()
	_ = p2.Add(make([]byte, 60))
	_ = p2.Add(make([]byte, 60))
	batches = collectBatches(t, emits)
	if len(batches) != 1 || batchBytes(batches[0]) != 60 {
		t.Fatalf("batches = %v, want one 60-byte pre-flush", batches)
	}
	rest = p2.Flush()
	if rest == nil || batchBytes(rest) != 60 {
		t.Fatalf("drained = %v, want one 60-byte segment", rest)
	}
}

// TestPackerOversizeSegmentAlone: a segment larger than the budget is
// emitted whole, alone, and never split.
func TestPackerOversizeSegmentAlone(t *testing.T) {
	emits := make(chan [][]byte, 8)
	p := NewPacker(PackerConfig{MTUBudget: 110, MaxDelay: time.Second, MaxBufferBytes: 1 << 20}, func(b [][]byte) { emits <- b })
	defer func() { _ = p.Close() }()

	big := make([]byte, 500)
	for i := range big {
		big[i] = 'x'
	}
	if !p.Add(big) {
		t.Fatal("Add returned false")
	}
	batches := collectBatches(t, emits)
	if len(batches) != 1 || len(batches[0]) != 1 || len(batches[0][0]) != 500 {
		t.Fatalf("oversize segment emitted as %v, want one 500-byte batch", batches)
	}
	if string(batches[0][0]) != string(big) {
		t.Fatal("oversize segment bytes changed")
	}
}

// TestPackerCloseDrainsInOrder: Close returns the remainder in order,
// is idempotent, and rejects later Adds explicitly (never silently).
func TestPackerCloseDrainsInOrder(t *testing.T) {
	emitted := atomic.Int32{}
	p := NewPacker(PackerConfig{MTUBudget: 1 << 20, MaxDelay: time.Second, MaxBufferBytes: 1 << 20}, func(b [][]byte) { emitted.Add(1) })
	_ = p.Add([]byte("one"))
	_ = p.Add([]byte("two"))
	_ = p.Add([]byte("three"))

	rest := p.Close()
	segmentsEqual(t, rest, [][]byte{[]byte("one"), []byte("two"), []byte("three")})
	if got := p.Close(); got != nil {
		t.Fatalf("second Close returned %q, want nil", got)
	}
	if p.Add([]byte("late")) {
		t.Fatal("Add after Close returned true; the segment would be silently dropped")
	}
	// The delay timer must not fire after Close.
	time.Sleep(50 * time.Millisecond)
	if emitted.Load() != 0 {
		t.Fatal("emit callback fired after Close")
	}
	if got := p.Flush(); got != nil {
		t.Fatalf("Flush after Close returned %q, want nil", got)
	}
}

// TestPackerZeroDelayFlushesImmediately: a zero delay budget means no
// holding at all — every Add emits a singleton at once.
func TestPackerZeroDelayFlushesImmediately(t *testing.T) {
	emits := make(chan [][]byte, 8)
	p := NewPacker(PackerConfig{MTUBudget: 1 << 20, MaxDelay: 0, MaxBufferBytes: 1 << 20}, func(b [][]byte) { emits <- b })
	defer func() { _ = p.Close() }()
	for _, s := range []string{"a", "b", "c"} {
		if !p.Add([]byte(s)) {
			t.Fatal("Add returned false")
		}
		if p.Len() != 0 {
			t.Fatal("zero-delay Packer buffered a segment")
		}
	}
	batches := collectBatches(t, emits)
	if len(batches) != 3 {
		t.Fatalf("batches = %d, want 3 singletons", len(batches))
	}
	for i, b := range batches {
		if len(b) != 1 {
			t.Fatalf("batch %d has %d segments, want 1", i, len(b))
		}
	}
}

// TestPackerInertWithNonPositiveBudget: no probed MTU yet means no
// coalescing and no timer — singleton batches, immediately.
func TestPackerInertWithNonPositiveBudget(t *testing.T) {
	emits := make(chan [][]byte, 8)
	p := NewPacker(PackerConfig{MTUBudget: 0, MaxDelay: 25 * time.Millisecond, MaxBufferBytes: 32768}, func(b [][]byte) { emits <- b })
	defer func() { _ = p.Close() }()
	_ = p.Add([]byte("a"))
	_ = p.Add([]byte("bb"))
	batches := collectBatches(t, emits)
	if len(batches) != 2 {
		t.Fatalf("batches = %d, want 2 singletons", len(batches))
	}
	if p.Len() != 0 {
		t.Fatal("inert Packer buffered a segment")
	}
}

// TestPackerEmptySegmentPreserved: empty segments are not dropped.
func TestPackerEmptySegmentPreserved(t *testing.T) {
	p := NewPacker(PackerConfig{MTUBudget: 1 << 20, MaxDelay: time.Second, MaxBufferBytes: 1 << 20}, func(b [][]byte) {})
	defer func() { _ = p.Close() }()
	_ = p.Add([]byte("a"))
	_ = p.Add([]byte{})
	_ = p.Add([]byte("b"))
	rest := p.Flush()
	segmentsEqual(t, rest, [][]byte{[]byte("a"), []byte{}, []byte("b")})
}

// TestPackerCopiesSegments: mutating the caller's slice after Add must
// not corrupt the buffered segment.
func TestPackerCopiesSegments(t *testing.T) {
	p := NewPacker(PackerConfig{MTUBudget: 1 << 20, MaxDelay: time.Second, MaxBufferBytes: 1 << 20}, func(b [][]byte) {})
	defer func() { _ = p.Close() }()
	seg := []byte("original")
	_ = p.Add(seg)
	seg[0] = 'X'
	rest := p.Flush()
	if string(rest[0]) != "original" {
		t.Fatalf("buffered segment mutated to %q", rest[0])
	}
}

// TestPackerConcurrentUse: concurrent Adds preserve every segment and
// each goroutine's own order; nothing is lost or reordered per producer.
func TestPackerConcurrentUse(t *testing.T) {
	var mu sync.Mutex
	var emitted [][]byte
	p := NewPacker(PackerConfig{MTUBudget: 200, MaxDelay: 5 * time.Millisecond, MaxBufferBytes: 1 << 20}, func(b [][]byte) {
		mu.Lock()
		emitted = append(emitted, b...)
		mu.Unlock()
	})

	const producers = 8
	const perProducer = 50
	var wg sync.WaitGroup
	for id := 0; id < producers; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				seg := []byte(fmt.Sprintf("p%02d-%03d", id, i))
				if !p.Add(seg) {
					t.Error("Add returned false on an open Packer")
					return
				}
			}
		}(id)
	}
	wg.Wait()
	if rest := p.Close(); rest != nil {
		mu.Lock()
		emitted = append(emitted, rest...)
		mu.Unlock()
	}
	mu.Lock()
	defer mu.Unlock()
	if len(emitted) != producers*perProducer {
		t.Fatalf("emitted %d segments, want %d", len(emitted), producers*perProducer)
	}
	// Per-producer index order must be monotonic in emission order.
	last := make(map[int]int, producers)
	seen := make(map[string]bool, producers*perProducer)
	for _, seg := range emitted {
		var id, idx int
		if _, err := fmt.Sscanf(string(seg), "p%02d-%03d", &id, &idx); err != nil {
			t.Fatalf("unparsable emitted segment %q: %v", seg, err)
		}
		if seen[string(seg)] {
			t.Fatalf("duplicate segment %q", seg)
		}
		seen[string(seg)] = true
		if prev, ok := last[id]; ok && idx <= prev {
			t.Fatalf("producer %d out of order: %d after %d", id, idx, prev)
		}
		last[id] = idx
	}
}

// TestPackerNoGoroutineOrTimerLeak: repeated Packer lifecycles,
// including armed timers with buffered data, leave no goroutines or
// timers behind and never emit after Close.
func TestPackerNoGoroutineOrTimerLeak(t *testing.T) {
	// Settle, then take a baseline.
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	base := runtime.NumGoroutine()

	for i := 0; i < 100; i++ {
		p := NewPacker(PackerConfig{MTUBudget: 1 << 20, MaxDelay: 50 * time.Millisecond, MaxBufferBytes: 1 << 20}, func(b [][]byte) {})
		if i%2 == 0 {
			_ = p.Add([]byte("pending"))
		}
		_ = p.Close()
	}
	// Allow any in-flight timer callback to observe the closed state.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= base+1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutine count = %d, baseline %d: Packer lifecycle leaked", runtime.NumGoroutine(), base)
}

// TestPackerConfigClamps: Packer-level normalization bounds the delay
// and the buffer ceiling; small buffers stay small for tests.
func TestPackerConfigClamps(t *testing.T) {
	p := NewPacker(PackerConfig{MTUBudget: 110, MaxDelay: -time.Second, MaxBufferBytes: 0}, func(b [][]byte) {})
	if got := p.EffectiveMaxDelay(); got != 0 {
		t.Fatalf("negative delay clamped to %v, want 0", got)
	}
	if got := p.EffectiveMaxBufferBytes(); got != 32768 {
		t.Fatalf("zero buffer clamped to %d, want 32768", got)
	}
	_ = p.Close()

	p = NewPacker(PackerConfig{MTUBudget: 110, MaxDelay: 5 * time.Second, MaxBufferBytes: 2 << 20}, func(b [][]byte) {})
	if got := p.EffectiveMaxDelay(); got != time.Second {
		t.Fatalf("delay clamped to %v, want 1s", got)
	}
	if got := p.EffectiveMaxBufferBytes(); got != 1<<20 {
		t.Fatalf("buffer clamped to %d, want 1MiB", got)
	}
	_ = p.Close()

	p = NewPacker(PackerConfig{MTUBudget: 110, MaxDelay: 25 * time.Millisecond, MaxBufferBytes: 64}, func(b [][]byte) {})
	if got := p.EffectiveMaxBufferBytes(); got != 64 {
		t.Fatalf("small test buffer changed to %d, want 64", got)
	}
	_ = p.Close()
}

// TestPackingConfigClamps mirrors finalizeClientConfig so a
// directly-constructed Client (no config load) behaves identically.
func TestPackingConfigClamps(t *testing.T) {
	c := &Client{cfg: config.ClientConfig{
		PackingEnabled:        true,
		PackingMaxDelayMs:     -5,
		PackingMaxBufferBytes: 10,
	}}
	// syncedUploadMTU is 0 here: budget 0 (inert) until an MTU syncs.
	// finalizeClientConfig: a buffer below 1024 defaults to 32768.
	cfg := c.packingConfig()
	if cfg.MaxDelay != 0 || cfg.MaxBufferBytes != 32768 || cfg.MTUBudget != 0 {
		t.Fatalf("packingConfig = %+v, want delay 0, buffer 32768, budget 0", cfg)
	}
	if !c.packingEnabled() {
		t.Fatal("packingEnabled = false with PACKING_ENABLED set")
	}

	c.cfg.PackingMaxDelayMs = 5000
	c.cfg.PackingMaxBufferBytes = 2 << 20
	c.syncedUploadMTU = 110
	cfg = c.packingConfig()
	if cfg.MaxDelay != time.Second || cfg.MaxBufferBytes != 1<<20 || cfg.MTUBudget != 110 {
		t.Fatalf("packingConfig = %+v, want delay 1s, buffer 1MiB, budget 110", cfg)
	}

	zero := &Client{}
	if zero.packingEnabled() {
		t.Fatal("zero Client reports packing enabled")
	}
	// A zero config has delay 0 (finalize clamps, it does not re-default;
	// the 25ms default comes from defaultClientConfig at load time) and
	// a sub-1024 buffer defaults to 32768.
	if zc := zero.packingConfig(); zc.MaxDelay != 0 || zc.MaxBufferBytes != 32768 {
		t.Fatalf("zero Client packingConfig = %+v, want delay 0, buffer 32768", zc)
	}
	var nilClient *Client
	if nilClient.packingEnabled() {
		t.Fatal("nil Client reports packing enabled")
	}
}

// TestSegmentsMergeableForPackingNeverAdmits: the gate admits nothing
// under the current wire format, for every packet type, with or without
// payload. If this test ever fails, a wire-format change has landed
// and emitOutboundTask's merge branch must exist before it can pass.
func TestSegmentsMergeableForPackingNeverAdmits(t *testing.T) {
	types := []uint8{
		Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND,
		Enums.PACKET_SOCKS5_SYN, Enums.PACKET_DNS_QUERY_REQ, Enums.PACKET_DNS_QUERY_RES,
		Enums.PACKET_PING, Enums.PACKET_PONG, Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_SYN,
		0x00, 0xFF,
	}
	for _, pt := range types {
		for _, payload := range [][]byte{nil, {}, []byte("payload-bytes")} {
			task := rawOutboundTask{opts: VpnProto.BuildOptions{PacketType: pt, Payload: payload}}
			if segmentsMergeableForPacking(task) {
				t.Fatalf("gate admitted packet type %#x with payload len %d", pt, len(payload))
			}
		}
	}
}

// TestEmitOutboundTaskPassthroughDisabled: PACKING_ENABLED=false sends
// the task unmodified, unbatched, with no added delay.
func TestEmitOutboundTaskPassthroughDisabled(t *testing.T) {
	c := &Client{
		cfg:       config.ClientConfig{},
		txChannel: make(chan rawOutboundTask, 4),
	}
	payload := []byte("segment-bytes")
	task := rawOutboundTask{
		packetType: Enums.PACKET_STREAM_DATA,
		payload:    payload,
		opts:       VpnProto.BuildOptions{PacketType: Enums.PACKET_STREAM_DATA, StreamID: 7, SequenceNum: 42, Payload: payload},
	}
	start := time.Now()
	if !c.emitOutboundTask(context.Background(), task) {
		t.Fatal("emitOutboundTask returned false on an open channel")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("disabled emit took %v, want no added delay", elapsed)
	}
	select {
	case got := <-c.txChannel:
		if got.packetType != task.packetType || string(got.payload) != string(payload) ||
			got.opts.StreamID != 7 || got.opts.SequenceNum != 42 || string(got.opts.Payload) != string(payload) {
			t.Fatalf("task modified in disabled mode: %+v", got)
		}
	default:
		t.Fatal("task not delivered to txChannel")
	}
}

// TestEmitOutboundTaskPassthroughEnabledNoDelay: PACKING_ENABLED=true
// must behave identically today — the gate admits nothing, so the task
// is emitted at once, never held for the delay budget.
func TestEmitOutboundTaskPassthroughEnabledNoDelay(t *testing.T) {
	c := &Client{
		cfg: config.ClientConfig{
			PackingEnabled:        true,
			PackingMaxDelayMs:     25,
			PackingMaxBufferBytes: 32768,
		},
		txChannel:       make(chan rawOutboundTask, 512),
		syncedUploadMTU: 110,
	}
	// Every packet type must pass through without panic or delay.
	for pt := 0; pt < 256; pt++ {
		payload := []byte{byte(pt), 0xAA}
		task := rawOutboundTask{
			packetType: uint8(pt),
			payload:    payload,
			opts:       VpnProto.BuildOptions{PacketType: uint8(pt), StreamID: 3, SequenceNum: uint16(pt), Payload: payload},
		}
		start := time.Now()
		if !c.emitOutboundTask(context.Background(), task) {
			t.Fatalf("emitOutboundTask returned false for type %#x", pt)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("enabled emit for type %#x took %v: task held for packing", pt, elapsed)
		}
	}
	if n := len(c.txChannel); n != 256 {
		t.Fatalf("delivered %d tasks, want 256 unbatched tasks", n)
	}
	for pt := 0; pt < 256; pt++ {
		got := <-c.txChannel
		if got.packetType != uint8(pt) || len(got.opts.Payload) != 2 || got.opts.Payload[0] != byte(pt) {
			t.Fatalf("task %d modified by enabled emit: %+v", pt, got)
		}
	}
}

// TestEmitOutboundTaskCtxCancelledReleases: a cancelled context
// releases the packet exactly as the inline send it replaced did.
func TestEmitOutboundTaskCtxCancelledReleases(t *testing.T) {
	item := &clientStreamTXPacket{Payload: []byte("queued")}
	selected := &Stream_client{}
	c := &Client{txChannel: make(chan rawOutboundTask)} // unbuffered, no receiver
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	task := rawOutboundTask{item: item, selected: selected}
	if c.emitOutboundTask(ctx, task) {
		t.Fatal("emitOutboundTask returned true with a cancelled context")
	}
	if item.Payload != nil {
		t.Fatal("packet not released on cancelled emit")
	}
}

// TestDispatcherPackingEnabledIdentical: end-to-end through the real
// dispatcher, packing on vs off must deliver identical tasks in
// identical order, with no delay-budget hold.
func TestDispatcherPackingEnabledIdentical(t *testing.T) {
	run := func(enabled bool) []rawOutboundTask {
		c := createTestClient(t)
		c.cfg.PackingEnabled = enabled
		c.cfg.PackingMaxDelayMs = 25
		c.cfg.PackingMaxBufferBytes = 32768
		c.syncedUploadMTU = 110
		if err := c.BuildConnectionMap(); err != nil {
			t.Fatalf("BuildConnectionMap: %v", err)
		}
		c.txChannel = make(chan rawOutboundTask, 8)
		c.active_streams = make(map[uint16]*Stream_client)
		stream := &Stream_client{client: c, StreamID: 1, txQueue: mlq.New[*clientStreamTXPacket](8)}
		c.active_streams[stream.StreamID] = stream
		c.bumpStreamSetVersion()
		for i, payload := range []string{"first", "second", "third"} {
			if !stream.PushTXPacket(0, 0x99, uint16(i+1), 0, 0, 0, 0, []byte(payload)) {
				t.Fatal("PushTXPacket failed")
			}
		}
		c.clearTxSignal()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c.asyncWG.Add(1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			c.asyncStreamDispatcher(ctx)
		}()
		select {
		case c.txSignal <- struct{}{}:
		default:
		}
		start := time.Now()
		waitForCondition(t, 2*time.Second, func() bool { return len(c.txChannel) == 3 }, "dispatcher did not drain 3 packets")
		if enabled && time.Since(start) > 500*time.Millisecond {
			t.Fatalf("enabled dispatcher took %v to drain: tasks held for packing", time.Since(start))
		}
		cancel()
		c.asyncWG.Wait()
		var tasks []rawOutboundTask
		for {
			select {
			case task := <-c.txChannel:
				tasks = append(tasks, task)
			default:
				return tasks
			}
		}
	}

	off := run(false)
	on := run(true)
	if len(off) != 3 || len(on) != 3 {
		t.Fatalf("off=%d on=%d tasks, want 3 each", len(off), len(on))
	}
	for i := range off {
		if string(off[i].payload) != string(on[i].payload) || off[i].packetType != on[i].packetType {
			t.Fatalf("task %d differs: off=%q on=%q", i, off[i].payload, on[i].payload)
		}
		if off[i].wasPacked != on[i].wasPacked {
			t.Fatalf("task %d wasPacked differs", i)
		}
	}
}

// --- Benchmarks (in-process synthetic streams; no network) ---
//
// "Before" is today's behaviour: one DNS query per segment. "After" is
// the Packer batching segments up to the budget. The Packer-level gain
// is real only once a packed-data wire format can frame a batch; see
// the file header. Budgets: 110 B is the probed upload MTU on the
// current resolver fleet (research notes, 2026-11-03); 1200 B is the
// ARQ default MTU used before probing; 32768 B is the default buffer
// cap. Run 1-core pinned: taskset -c 0 go test -bench Packer -run '^$'.

func makeSegments(t *testing.B, count, size int) [][]byte {
	segs := make([][]byte, count)
	// Deterministic pattern bytes; content is irrelevant to the Packer
	// (no compression happens here) and must stay synthetic.
	pattern := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	for i := range segs {
		seg := make([]byte, size)
		for j := range seg {
			seg[j] = pattern[(i+j)%len(pattern)]
		}
		segs[i] = seg
	}
	return segs
}

func benchPackerStream(b *testing.B, segSize, budget int, delay time.Duration) {
	b.Helper()
	const totalBytes = 1 << 20 // 1 MiB of segments per iteration set
	var segs [][]byte
	var count int
	if segSize == 0 {
		// Mixed case: sizes cycle 40..200 B.
		for total := 0; total < totalBytes; {
			sz := 40 + (total % 161)
			seg := make([]byte, sz)
			for j := range seg {
				seg[j] = byte('a' + (total+j)%26)
			}
			segs = append(segs, seg)
			total += sz
		}
		count = len(segs)
	} else {
		count = totalBytes / segSize
		if count == 0 {
			count = 1
		}
		segs = makeSegments(b, count, segSize)
	}

	var batches int64
	var totalSegBytes int64
	emit := func(batch [][]byte) {
		batches++
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batches, totalSegBytes = 0, 0
		p := NewPacker(PackerConfig{MTUBudget: budget, MaxDelay: delay, MaxBufferBytes: 1 << 20}, emit)
		for _, s := range segs {
			_ = p.Add(s)
			totalSegBytes += int64(len(s))
		}
		if rest := p.Close(); rest != nil {
			batches++
		}
		_ = totalSegBytes
	}
	b.StopTimer()
	totalMB := float64(totalSegBytes) / (1 << 20)
	queriesBefore := float64(count)
	// batches/totalSegBytes hold the LAST iteration only (reset per
	// iteration above); do not divide by b.N again.
	queriesAfter := float64(batches)
	if queriesAfter < 1 {
		queriesAfter = 1
	}
	perMBBefore := queriesBefore / totalMB
	perMBAfter := queriesAfter / totalMB
	ratio := queriesBefore / queriesAfter
	b.ReportMetric(perMBBefore, "queries/MB-before")
	b.ReportMetric(perMBAfter, "queries/MB-after")
	b.ReportMetric(ratio, "packing-ratio")
	b.Logf("segments=%d budget=%d delay=%v queries/MB before=%.0f after=%.0f ratio=%.2fx",
		count, budget, delay, perMBBefore, perMBAfter, ratio)
}

func BenchmarkPackerMixed40To200BBudget110(b *testing.B) {
	benchPackerStream(b, 0, 110, 25*time.Millisecond)
}

// BenchmarkPackerSmall40BBudget110: uniformly tiny segments against the
// 110 B fleet MTU — the case packing was proposed for (two 40 B
// segments fit one query; a third would exceed the budget).
func BenchmarkPackerSmall40BBudget110(b *testing.B) {
	benchPackerStream(b, 40, 110, 25*time.Millisecond)
}

func BenchmarkPackerMixed40To200BBudget1200(b *testing.B) {
	benchPackerStream(b, 0, 1200, 25*time.Millisecond)
}

func BenchmarkPacker1KBSegmentsBudget1200(b *testing.B) {
	benchPackerStream(b, 1024, 1200, 25*time.Millisecond)
}

// BenchmarkPacker1KBSegmentsBudget32768: 1 KiB segments against the
// 32 KiB buffer cap pack ~32 per query when the delay budget allows.
func BenchmarkPacker1KBSegmentsBudget32768(b *testing.B) {
	benchPackerStream(b, 1024, 32768, 25*time.Millisecond)
}

// BenchmarkPackerAddedLatency measures the hold time each segment
// suffers: burst feeding (budget flushes, ~0 hold) vs trickle feeding
// (one segment per 5 ms, delay budget 25 ms, ~25 ms hold). The
// distribution is what an operator trades for fewer queries.
func BenchmarkPackerAddedLatency(b *testing.B) {
	for _, mode := range []string{"burst", "trickle"} {
		b.Run(mode, func(b *testing.B) {
			const nSegs = 200
			seg := make([]byte, 100)
			var mu sync.Mutex
			var holds []time.Duration
			starts := make([]time.Time, nSegs)
			var idx atomic.Int32
			p := NewPacker(PackerConfig{MTUBudget: 1200, MaxDelay: 25 * time.Millisecond, MaxBufferBytes: 1 << 20}, func(batch [][]byte) {
				now := time.Now()
				mu.Lock()
				for range batch {
					i := int(idx.Add(1)) - 1
					if i < nSegs {
						holds = append(holds, now.Sub(starts[i]))
					}
				}
				mu.Unlock()
			})
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				idx.Store(0)
				holds = holds[:0]
				// Fresh packer per iteration: Close the old one first.
				_ = p.Close()
				p = NewPacker(PackerConfig{MTUBudget: 1200, MaxDelay: 25 * time.Millisecond, MaxBufferBytes: 1 << 20}, func(batch [][]byte) {
					now := time.Now()
					mu.Lock()
					for range batch {
						j := int(idx.Add(1)) - 1
						if j < nSegs {
							holds = append(holds, now.Sub(starts[j]))
						}
					}
					mu.Unlock()
				})
				for s := 0; s < nSegs; s++ {
					starts[s] = time.Now()
					_ = p.Add(seg)
					if mode == "trickle" {
						time.Sleep(5 * time.Millisecond)
					}
				}
				if rest := p.Close(); rest != nil {
					now := time.Now()
					for k := len(holds); k < nSegs; k++ {
						holds = append(holds, now.Sub(starts[k]))
					}
				}
			}
			b.StopTimer()
			if len(holds) == 0 {
				b.Fatal("no hold samples collected")
			}
			sorted := append([]time.Duration(nil), holds...)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
			p50 := sorted[len(sorted)/2]
			p95 := sorted[int(float64(len(sorted))*0.95)]
			b.ReportMetric(float64(p50.Microseconds()), "hold-p50-us")
			b.ReportMetric(float64(p95.Microseconds()), "hold-p95-us")
			b.ReportMetric(float64(sorted[len(sorted)-1].Microseconds()), "hold-max-us")
			b.Logf("mode=%s n=%d hold p50=%v p95=%v max=%v", mode, len(sorted), p50, p95, sorted[len(sorted)-1])
		})
	}
}
