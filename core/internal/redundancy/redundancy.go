// Package redundancy implements EndRE-style redundancy elimination for
// the Nexounel throughput pack: both ends of a direction keep a
// synchronized, bounded cache of previously seen byte chunks; the sender
// replaces repeated chunks with short references, and the receiver
// reconstructs the original bytes from its cache.
//
// The layer is deliberately self-contained and stdlib-only so the
// coordinator can wire it into the session path without touching the
// compression package or any config file. See
// docs/throughput-pack-redundancy-design.md for the wire format, the
// ACK-gating protocol, and the exact composition contract with the codec.
//
// Correctness invariants (enforced by construction, asserted in tests):
//
//   - A frame's decodability depends only on its own bytes plus the set
//     of chunks ACKed before it was encoded. Losing one frame never
//     breaks a later frame.
//   - The sender references only chunks the peer has ACKed. A reference
//     to an unknown chunk fails atomically on decode (no output, no
//     cache inserts) and is repaired by literal fallback.
//   - Decoding is byte-exact even under hash collision: a colliding
//     chunk travels as a Raw record and is never cached or referenced.
//
// Concurrency: Cache is safe for concurrent use. Encoder and Decoder
// serialize their own calls with an internal mutex and are also safe
// for concurrent use, but each direction must use its own Encoder and
// Decoder sharing nothing except the transport.
package redundancy

import (
	"crypto/sha256"
	"errors"
	"time"
)

// ChunkID identifies a chunk: the first 8 bytes of its SHA-256 hash.
// A truncated strong hash is used deliberately: a false identity would
// silently corrupt reconstructed bytes, so the identity function must
// make accidental collision negligible. See the design doc §3.
type ChunkID [8]byte

// Fingerprint returns the ChunkID of data.
func Fingerprint(data []byte) ChunkID {
	sum := sha256.Sum256(data)
	var id ChunkID
	copy(id[:], sum[:8])
	return id
}

// Chunking and framing constants. See the design doc §2 and §8.
const (
	// MinChunkSize is the smallest cacheable chunk. Smaller fragments
	// are emitted as Raw records: reference overhead would eat the gain.
	MinChunkSize = 128
	// MaxChunkSize is the forced-cut size: it bounds scan time, cache
	// entry size, and the damage one mutation does to a chunk.
	MaxChunkSize = 512
	// MaxFrameBytes caps one Encode input and one Decode output (1 MiB).
	MaxFrameBytes = 1 << 20
	// frameVersion is the only wire version defined by this package.
	frameVersion = 0x01
	// entryOverheadBytes is the deterministic per-entry accounting
	// charge (id, LRU links, timestamps). Cache accounting never uses
	// runtime memory statistics, so cap enforcement is reproducible.
	entryOverheadBytes = 64
	// gearCutMask gives a 1/128 cut probability per byte after the
	// minimum, for a target average chunk size of ~256 B.
	gearCutMask = 0x7F
	gearCutVal  = 0x7F
)

var (
	// ErrMalformedFrame reports a frame that fails structural
	// validation (bad version, truncated record, trailing bytes,
	// declared length mismatch). It implies a corrupt or foreign frame,
	// never a cache state problem; the sender cannot repair it by
	// re-encoding through this layer.
	ErrMalformedFrame = errors.New("redundancy: malformed frame")
	// ErrFrameTooLarge reports an Encode input or a declared decode
	// output larger than MaxFrameBytes.
	ErrFrameTooLarge = errors.New("redundancy: frame exceeds size limit")
	// ErrUnknownChunk is unwrapped by MissError: a frame referenced a
	// chunk the receiver does not hold. Use AsMiss to recover the id.
	ErrUnknownChunk = errors.New("redundancy: referenced chunk not in cache")
)

// MissError is returned by Decoder.Decode when a frame references a
// chunk the receiver does not hold. It always wraps ErrUnknownChunk and
// carries the missing id so the sender can invalidate it and fall back
// to literals. No output bytes and no cache inserts accompany it.
type MissError struct {
	Seq uint64
	ID  ChunkID
}

func (e *MissError) Error() string {
	return "redundancy: referenced chunk not in cache"
}

// Unwrap exposes ErrUnknownChunk for errors.Is.
func (e *MissError) Unwrap() error { return ErrUnknownChunk }

// AsMiss reports whether err is a *MissError and returns the Miss the
// sender must act on (see Encoder.NoteMiss).
func AsMiss(err error) (Miss, bool) {
	var m *MissError
	if errors.As(err, &m) {
		return Miss{FrameSeq: m.Seq, Missing: m.ID}, true
	}
	return Miss{}, false
}

// Config tunes a Cache. The zero value is not usable directly: use
// DefaultConfig or resolve it through NewCache, which clamps every
// field to its enforced range.
type Config struct {
	// MaxCacheBytes caps accounted cache bytes (stored bytes + per
	// entry overhead). Clamped to [1 KiB, 512 MiB]; the coordinator
	// normally passes CacheBytesFromMB values (1..512 MiB), and the
	// low floor exists so tests and small deployments can use small
	// caches without the clamp silently enlarging them.
	MaxCacheBytes int
	// MaxEntries caps the number of cached chunks. Clamped to [1, 1<<20].
	MaxEntries int
	// PendingTimeout is how long an un-ACKed (pending) sender entry is
	// exempt from eviction. Defaults to 30s when <= 0.
	PendingTimeout time.Duration
	// Now is the clock used for pending-entry expiry. Defaults to
	// time.Now. Tests inject a fake clock for deterministic eviction.
	Now func() time.Time
}

// DefaultConfig returns the prototype defaults: a 128 MiB cache, the
// entry cap for ~256 B average chunks, and a 30 s pending timeout. The
// coordinator derives MaxCacheBytes from RE_CACHE_MAX_MB (default 128,
// clamp 1..512) via CacheBytesFromMB.
func DefaultConfig() Config {
	return Config{
		MaxCacheBytes:  128 << 20,
		MaxEntries:     524288,
		PendingTimeout: 30 * time.Second,
	}
}

// CacheBytesFromMB converts an RE_CACHE_MAX_MB-style value to a byte
// cap, clamped to [1 MiB, 512 MiB] exactly as the config layer clamps
// RE_CACHE_MAX_MB to [1, 512].
func CacheBytesFromMB(mb int) int {
	if mb < 1 {
		mb = 1
	}
	if mb > 512 {
		mb = 512
	}
	return mb << 20
}

func (c Config) resolved() Config {
	if c.MaxCacheBytes < 1<<10 {
		c.MaxCacheBytes = 1 << 10
	}
	if c.MaxCacheBytes > 512<<20 {
		c.MaxCacheBytes = 512 << 20
	}
	if c.MaxEntries < 1 {
		c.MaxEntries = 1
	}
	if c.MaxEntries > 1<<20 {
		c.MaxEntries = 1 << 20
	}
	if c.PendingTimeout <= 0 {
		c.PendingTimeout = 30 * time.Second
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// splitChunks partitions data with content-defined boundaries (gear
// rolling hash, §2 of the design doc). Returned slices are views of
// data; all but the last are in [MinChunkSize, MaxChunkSize], and the
// last may be shorter (the tail). Splitting is deterministic: identical
// input always yields identical boundaries, and a small insertion
// shifts only the boundaries near the edit.
func splitChunks(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	var out [][]byte
	start := 0
	var h uint64
	for i := 0; i < len(data); i++ {
		h = (h << 1) + uint64(data[i])
		n := i - start + 1
		if n >= MinChunkSize && ((h&gearCutMask) == gearCutVal || n >= MaxChunkSize) {
			out = append(out, data[start:i+1])
			start = i + 1
			h = 0
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}

// Split is the exported form of splitChunks, for coordinator
// diagnostics and tests. Chunk Data slices are views of the input;
// Fingerprint identifies each chunk.
type Chunk struct {
	Data []byte
	ID   ChunkID
}

// Split partitions data exactly as the encoder does and fingerprints
// every chunk. It performs no caching.
func Split(data []byte) []Chunk {
	parts := splitChunks(data)
	out := make([]Chunk, 0, len(parts))
	for _, p := range parts {
		out = append(out, Chunk{Data: p, ID: Fingerprint(p)})
	}
	return out
}
