// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the CottenDns client.
// This file (packer.go) implements outbound segment coalescing (packing)
// for the throughput prototype, and the gate that decides whether a
// dispatched outbound task may be coalesced at all.
//
// READ THIS BEFORE ROUTING TRAFFIC THROUGH Packer
// ------------------------------------------------
// Packer coalesces ordered byte segments into batches. A batch is emitted
// as ONE frame only when the caller can frame it without losing per-segment
// identity. Packing happens BEFORE compression: each flushed batch is fed
// to VpnProto.BuildRawAuto (see asyncEncodeWorker) as one independent
// frame, so a lost query loses exactly that one frame and no compressor
// state shared with any other frame. Do NOT change any packet format here.
//
// Under the CURRENT wire format no queued outbound packet type is
// mergeable, and segmentsMergeableForPacking says so explicitly. Every
// STREAM_DATA / STREAM_RESEND segment carries its own StreamID,
// SequenceNum and FragmentID in the frame header; the peer's ARQ keys
// its receive buffer, ACKs, NACKs and retransmits by sequence number, so
// concatenating two segments under one header would deliver the bytes
// under the first sequence number, leave the second un-ACKed, and make
// the inevitable retransmit of the second segment DUPLICATE bytes at
// the peer. Control packets with payloads (SOCKS5_SYN, DNS_QUERY_REQ,
// ...) carry the same per-segment header fields and fragment identity.
// Empty-payload control packets are already coalesced by
// packControlBlocks into PACKET_PACKED_CONTROL_BLOCKS, which is the one
// packed format the wire already has; holding a packed control frame
// for a delay budget to merge it with a later one would delay ACKs for
// at most a few 7-byte blocks and is deliberately not done.
//
// Packer is therefore a complete, tested coalescing engine that stays
// OUT of the live send path until a packed-data frame format exists
// (per-segment framing mirroring PACKET_PACKED_CONTROL_BLOCKS, plus
// server-side unpacking and ARQ ACK accounting for the packed segments).
// That format change is outside this prototype's constraints (no packet
// format change, no ARQ/FEC/negotiation changes). Until it lands, the
// dispatcher emits every task unchanged, packing on or off, and the
// only live effect of PACKING_ENABLED is the gate evaluation itself.
// The synthetic benchmarks in packer_test.go measure what packing
// WOULD buy once the format exists; they are not live-tunnel numbers.
//
// Caps (enforced in two layers):
//   - Config layer (finalizeClientConfig, already committed; not touched
//     here): PACKING_MAX_DELAY_MS clamped to 0..1000, PACKING_MAX_BUFFER_BYTES
//     clamped to 1024..1MiB, defaults 25ms / 32768 bytes, PACKING_ENABLED
//     defaults false. packingConfig re-applies the same clamps so a
//     directly-constructed test Client behaves identically.
//   - Packer layer (NewPacker): MaxDelay clamped to 0..1000ms, MaxBufferBytes
//     clamped to at most 1MiB (a non-positive value means the 32768 default;
//     values below 1024 are accepted here only so tests can exercise the
//     cap rule cheaply — the config layer is the 1024 floor for operators).
//     MTUBudget is supplied per call site by the caller (the probed
//     per-resolver upload MTU, in plaintext payload bytes — the same unit
//     ARQ fragments to); a non-positive budget makes the Packer inert and
//     every segment is emitted alone, immediately, with no timer.
//
// ==============================================================================
package client

import (
	"context"
	"sync"
	"time"
)

// PackerConfig tunes one Packer. MTUBudget is the per-resolver MTU budget
// in payload bytes supplied by the caller; MaxDelay is the hold budget
// since the first buffered segment; MaxBufferBytes is the absolute
// buffering ceiling regardless of the MTU budget.
type PackerConfig struct {
	MTUBudget      int
	MaxDelay       time.Duration
	MaxBufferBytes int
}

const (
	// packerDefaultMaxBufferBytes is the Packer-level default when the
	// caller passes a non-positive MaxBufferBytes. It matches the config
	// default (PACKING_MAX_BUFFER_BYTES).
	packerDefaultMaxBufferBytes = 32768
	// packerMaxBufferBytesCap is the absolute Packer-level ceiling.
	packerMaxBufferBytesCap = 1 << 20
	// packerMaxDelayCap bounds the hold budget even if a caller passes a
	// larger value; it matches the config clamp (PACKING_MAX_DELAY_MS <= 1000).
	packerMaxDelayCap = 1000 * time.Millisecond
)

// Packer coalesces ordered byte segments into batches and flushes a batch
// when (a) adding a segment would push the buffered bytes past the MTU
// budget, (b) MaxDelay expires since the first buffered segment, or
// (c) the buffered bytes reach MaxBufferBytes. Close drains the remainder.
//
// Packer owns no goroutine. Delay expiry is driven by a single
// time.AfterFunc timer, armed when the first segment is buffered and
// stopped whenever the buffer empties or the Packer closes, so there is
// nothing to leak: Close stops the timer and drains the buffer, and it
// is safe to call repeatedly. Segments are copied on Add, so callers
// may reuse or pool their slices after Add returns. Batches are
// emitted in Add order; concurrent Adds are serialized by the mutex, so
// each goroutine's own Add order is preserved in the emitted stream.
// Segments are never split: a segment larger than the MTU budget is
// emitted alone as its own batch, whole.
//
// The emit callback is invoked WITHOUT holding the Packer mutex, so emit
// may call back into the Packer (e.g. to Close it) without deadlocking.
// Emitted slices are owned by the receiver once emit returns; the Packer
// never reuses a batch's backing storage.
type Packer struct {
	mu             sync.Mutex
	budget         int
	maxDelay       time.Duration
	maxBufferBytes int
	emit           func(batch [][]byte)

	buffered     [][]byte
	bufferedByte int
	// timer fires the delay expiry for the current buffer contents. gen
	// guards against a stale AfterFunc callback flushing a newer buffer.
	timer  *time.Timer
	gen    uint64
	closed bool
}

// NewPacker returns a Packer that delivers flushed batches to emit.
// emit must not be nil. Config values are normalized as described in the
// file header; use the Effective* accessors to observe the result.
func NewPacker(cfg PackerConfig, emit func(batch [][]byte)) *Packer {
	if emit == nil {
		panic("client: NewPacker requires a non-nil emit callback")
	}
	maxDelay := cfg.MaxDelay
	if maxDelay < 0 {
		maxDelay = 0
	}
	if maxDelay > packerMaxDelayCap {
		maxDelay = packerMaxDelayCap
	}
	maxBuffer := cfg.MaxBufferBytes
	if maxBuffer <= 0 {
		maxBuffer = packerDefaultMaxBufferBytes
	}
	if maxBuffer > packerMaxBufferBytesCap {
		maxBuffer = packerMaxBufferBytesCap
	}
	return &Packer{
		budget:         cfg.MTUBudget,
		maxDelay:       maxDelay,
		maxBufferBytes: maxBuffer,
		emit:           emit,
	}
}

// EffectiveMTUBudget reports the MTU budget this Packer flushes against.
// A non-positive value means the Packer is inert (singleton batches).
func (p *Packer) EffectiveMTUBudget() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.budget
}

// EffectiveMaxDelay reports the clamped hold budget.
func (p *Packer) EffectiveMaxDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxDelay
}

// EffectiveMaxBufferBytes reports the clamped buffering ceiling.
func (p *Packer) EffectiveMaxBufferBytes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxBufferBytes
}

// PendingBytes reports how many payload bytes are currently buffered.
func (p *Packer) PendingBytes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bufferedByte
}

// Len reports how many segments are currently buffered.
func (p *Packer) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.buffered)
}

// Add buffers one segment, preserving order. It returns false only if
// the Packer is already closed, in which case the segment is NOT
// buffered — the caller must handle that explicitly; nothing is
// silently dropped. When the MTU budget or the buffer cap is reached,
// the flushed batch is emitted synchronously before Add returns (but
// without holding the mutex). A zero-length segment is preserved as a
// segment: it contributes no bytes and can never by itself trigger a
// size flush, but it is emitted in order with its neighbours.
func (p *Packer) Add(segment []byte) bool {
	seg := append([]byte(nil), segment...)

	var toEmit [][]byte
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return false
	}
	// Inert or zero-delay mode: no holding, no timer, singleton batch.
	if p.budget <= 0 || p.maxDelay <= 0 {
		toEmit = [][]byte{seg}
		p.mu.Unlock()
		p.emit(toEmit)
		return true
	}
	// Keep batches tight: if this segment would push a non-empty buffer
	// past the MTU budget or the buffer cap, flush what is buffered
	// first instead of overshooting by a whole segment.
	if len(p.buffered) > 0 &&
		(p.bufferedByte+len(seg) > p.budget || p.bufferedByte+len(seg) > p.maxBufferBytes) {
		toEmit = p.takeLocked()
	}
	p.buffered = append(p.buffered, seg)
	p.bufferedByte += len(seg)
	if len(p.buffered) == 1 {
		p.armTimerLocked()
	}
	if p.bufferedByte >= p.budget || p.bufferedByte >= p.maxBufferBytes {
		// takeLocked stops the timer; append to any earlier flush so
		// both batches are emitted in order below. In practice toEmit
		// is nil here (the pre-flush above already drained the buffer
		// whenever the new segment would overshoot), but keep the
		// ordering invariant explicit.
		flushed := p.takeLocked()
		if toEmit == nil {
			toEmit = flushed
		} else {
			// Two batches from one Add: emit the earlier one first.
			// Preserve order by emitting sequentially below.
			p.mu.Unlock()
			p.emit(toEmit)
			p.emit(flushed)
			return true
		}
	}
	p.mu.Unlock()
	if toEmit != nil {
		p.emit(toEmit)
	}
	return true
}

// Flush drains whatever is buffered as one ordered batch and returns it
// (nil when nothing was buffered). It stops the delay timer. Calling
// Flush on a closed Packer returns nil; Close is the draining close.
func (p *Packer) Flush() [][]byte {
	p.mu.Lock()
	batch := p.takeLocked()
	p.mu.Unlock()
	return batch
}

// Close stops the delay timer, marks the Packer closed, and returns any
// buffered segments as one final ordered batch (nil when empty). It is
// idempotent: later Closes return nil and later Adds return false. No
// segment buffered before Close is lost; the caller owns the returned
// batch. No timer or goroutine survives Close.
func (p *Packer) Close() [][]byte {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	batch := p.takeLocked()
	p.mu.Unlock()
	return batch
}

// takeLocked removes the current buffer contents and stops the timer.
// The caller must hold p.mu. The returned batch is nil when empty.
func (p *Packer) takeLocked() [][]byte {
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	if len(p.buffered) == 0 {
		return nil
	}
	batch := p.buffered
	p.buffered = nil
	p.bufferedByte = 0
	return batch
}

// armTimerLocked arms the delay timer for the just-buffered first
// segment. The caller must hold p.mu and the buffer must be non-empty.
// The generation guard keeps a callback armed for an earlier buffer
// from flushing a newer one if Stop raced the firing.
func (p *Packer) armTimerLocked() {
	if p.timer != nil || p.maxDelay <= 0 {
		return
	}
	p.gen++
	gen := p.gen
	p.timer = time.AfterFunc(p.maxDelay, func() {
		p.mu.Lock()
		if p.closed || p.gen != gen || len(p.buffered) == 0 {
			p.mu.Unlock()
			return
		}
		batch := p.takeLocked()
		p.mu.Unlock()
		p.emit(batch)
	})
}

// packingEnabled reports whether the operator enabled segment packing.
// It reads only the already-finalized client config; the zero value
// (a directly-constructed test Client) is disabled, matching the
// config default of PACKING_ENABLED=false.
func (c *Client) packingEnabled() bool {
	if c == nil {
		return false
	}
	return c.cfg.PackingEnabled
}

// packingConfig returns the clamped Packer tuning for this client. The
// clamps mirror finalizeClientConfig exactly (delay clamped to 0..1000ms
// with no re-defaulting — 0 is a valid explicit value meaning "no hold";
// a buffer below 1024 defaults to 32768, above 1MiB clamps to 1MiB) so
// test-constructed Clients (which bypass config finalization) behave
// exactly like loaded ones. The MTU budget is the probed upload MTU in
// plaintext payload bytes — the same unit ARQ fragments STREAM_DATA
// to — or 0 when no MTU has been synced yet, which makes a Packer
// built from it inert.
func (c *Client) packingConfig() PackerConfig {
	if c == nil {
		return PackerConfig{MTUBudget: 0, MaxDelay: 0, MaxBufferBytes: packerDefaultMaxBufferBytes}
	}
	delayMs := c.cfg.PackingMaxDelayMs
	if delayMs < 0 {
		delayMs = 0
	}
	if delayMs > 1000 {
		delayMs = 1000
	}
	bufferBytes := c.cfg.PackingMaxBufferBytes
	if bufferBytes < 1024 {
		bufferBytes = packerDefaultMaxBufferBytes
	}
	if bufferBytes > 1<<20 {
		bufferBytes = 1 << 20
	}
	budget := c.syncedUploadMTU
	if budget < 0 {
		budget = 0
	}
	return PackerConfig{
		MTUBudget:      budget,
		MaxDelay:       time.Duration(delayMs) * time.Millisecond,
		MaxBufferBytes: bufferBytes,
	}
}

// segmentsMergeableForPacking is the safety gate for byte-level packing.
// It answers whether the payloads of two or more queued tasks sharing
// this task's header identity could be concatenated into ONE frame
// without changing what the peer delivers. Under the current wire
// format the answer is always false:
//
//   - STREAM_DATA / STREAM_RESEND: header carries StreamID, SequenceNum
//     and FragmentID; ARQ ACK/NACK/retransmit accounting is keyed by
//     sequence number, so concatenation corrupts the stream on any loss
//     (see the file header). This is the bulk-data case packing was
//     proposed for, and it is exactly the case that must not merge.
//   - Control packets with payloads (SOCKS5_SYN, DNS_QUERY_REQ/RES,
//     MTU probes, ...): same per-segment sequence/fragment header
//     fields; several are also fragment-reassembly units or measurement
//     instruments whose payload boundaries are meaningful.
//   - Empty-payload control packets: merging is meaningless (there are
//     no bytes to coalesce) and they already have a packed format
//     (PACKET_PACKED_CONTROL_BLOCKS via packControlBlocks).
//   - Anything else: unknown today, never merge by default.
//
// This function must stay conservative: a future packed-data frame
// format changes it (and only it, plus the server unpacker and ARQ
// accounting) to admit the types that format can frame. Until then,
// returning false here is what keeps PACKING_ENABLED safe to turn on.
func segmentsMergeableForPacking(task rawOutboundTask) bool {
	// No bytes to coalesce: packable controls are handled upstream by
	// packControlBlocks; every other empty payload has no packing gain.
	if len(task.opts.Payload) == 0 {
		return false
	}
	// Every payload-carrying queued type carries per-segment header
	// identity (stream/sequence/fragment) that concatenation would
	// destroy. There is no payload-carrying type in the current format
	// whose bytes are a free-standing stream. See the file header.
	return false
}

// emitOutboundTask hands one dispatcher-built task to the encode workers
// through txChannel. It is the single choke point where packing would
// intercept the send path: packing is flag-gated here, and the merge
// gate (segmentsMergeableForPacking) decides whether the task may be
// held for coalescing at all. Today the gate admits nothing, so this
// sends the task unchanged whether PACKING_ENABLED is on or off —
// provably identical behaviour, zero added delay, and no Packer is
// even constructed on the live path. When a packed-data wire format
// exists, the mergeable branch is where a Packer fed by the dispatcher
// (single-threaded owner of pop/release accounting, unlike the parallel
// encode workers) will hold and flush batches before BuildRawAuto.
//
// It returns false only when ctx ends before the send completes, in
// which case the task's packet is released exactly as the inline send
// it replaced did (non-packed tasks only; packed control blocks were
// already released by packControlBlocks).
func (c *Client) emitOutboundTask(ctx context.Context, task rawOutboundTask) bool {
	// Gate evaluation is intentionally cheap and side-effect free: the
	// mergeable branch does not exist yet, and must not be added without
	// the packed-data wire format described above.
	if c.packingEnabled() && segmentsMergeableForPacking(task) {
		// Unreachable with the current wire format: the gate admits
		// nothing. If it ever admits a type without a Packer wiring,
		// sending the task unmerged is still correct (it is a
		// complete segment; only merging could corrupt ARQ
		// accounting), so log loudly and fall through to the normal
		// send instead of crashing the process.
		if c.log != nil {
			c.log.Errorf("packing gate admitted a mergeable task with no Packer wiring; sending unmerged")
		}
	}
	select {
	case c.txChannel <- task:
		return true
	case <-ctx.Done():
		if !task.wasPacked && task.selected != nil {
			task.selected.ReleaseTXPacket(task.item)
		}
		return false
	}
}
