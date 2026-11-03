package redundancy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
)

// Record tags for RE frame v1. See the design doc §1.
const (
	recordLiteral byte = 0x01
	recordRef     byte = 0x02
	recordRaw     byte = 0x03
)

// RecordKind names a parsed frame record.
type RecordKind byte

const (
	// RecordLiteral is a cacheable chunk carried in full.
	RecordLiteral RecordKind = RecordKind(recordLiteral)
	// RecordReference names a cached chunk by id.
	RecordReference RecordKind = RecordKind(recordRef)
	// RecordRaw is uncached payload carried in full.
	RecordRaw RecordKind = RecordKind(recordRaw)
)

// Record is one parsed frame record. For Literal and Raw records Data
// holds the payload (a view of the parsed wire bytes: do not mutate);
// for Reference records ID and Len describe the chunk and Data is nil.
type Record struct {
	Kind RecordKind
	ID   ChunkID
	Len  int
	Data []byte
}

// Frame is one encoded segment. Wire is the complete RE frame to hand
// to the codec layer; LiteralBytes concatenates the Literal and Raw
// payloads in order (the compressible remainder, for the entropy-gate
// contract in the design doc §7); HasReferences tells the coordinator
// whether the frame is worth keeping at all.
type Frame struct {
	Seq           uint64
	Wire          []byte
	OriginalLen   int
	HasReferences bool
	LiteralBytes  []byte
	References    int
	Literals      int
	RawRecords    int
}

// Ack is the message the receiver emits after a successful decode and
// the coordinator delivers to the sender. ChunkIDs are the ids the
// receiver newly holds from that frame, in frame order. ACKs are
// idempotent and need no reliability: a lost ACK only delays future
// references. See the design doc §5.
type Ack struct {
	FrameSeq uint64
	ChunkIDs []ChunkID
}

// Miss is the message the receiver emits when a frame references an
// unknown chunk. The sender must call Encoder.NoteMiss, which deletes
// the id and lets the next Encode reintroduce the chunk as a literal.
type Miss struct {
	FrameSeq uint64
	Missing  ChunkID
}

// EncoderStats counts encoder activity over its lifetime.
// HeldUnackedResends counts literals re-sent for chunks the sender
// holds but the peer has not ACKed yet. The encoder must never
// reference such a chunk; it re-sends the literal instead. This
// counter is informational (it is legitimately nonzero before the
// first ACK arrives); gating itself is asserted by auditing emitted
// frames with ParseFrame, which proves no Reference names an
// un-ACKed chunk.
type EncoderStats struct {
	Frames             int
	References         int
	Literals           int
	RawRecords         int
	HeldUnackedResends int
	MissesNoted        int
	BytesIn            int64
	BytesOut           int64
}

// Encoder turns plaintext segments into RE frames against its Cache.
// It owns the frame sequence and the ACK/miss state for one direction.
// See the package doc for the call order: Encode, deliver Wire, the
// peer decodes and returns an Ack (or a Miss), NoteAck/NoteMiss, repeat.
type Encoder struct {
	mu    sync.Mutex
	cache *Cache
	seq   uint64
	stats EncoderStats
}

// NewEncoder builds an Encoder over cache. A nil cache gets a fresh
// default cache; sharing one Cache between two Encoders is a wiring
// error (each direction needs its own).
func NewEncoder(cache *Cache) *Encoder {
	if cache == nil {
		cache = NewCache(DefaultConfig())
	}
	return &Encoder{cache: cache}
}

// Cache exposes the encoder's cache for wiring and diagnostics.
func (e *Encoder) Cache() *Cache { return e.cache }

// Stats returns a copy of lifetime encoder counters.
func (e *Encoder) Stats() EncoderStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

// NoteAck marks the ACKed chunks usable as references. Unknown or
// already-acked ids are ignored (ACKs are idempotent).
func (e *Encoder) NoteAck(ack Ack) {
	e.cache.MarkAcked(ack.ChunkIDs)
}

// NoteMiss invalidates the missing chunk: it is no longer acked
// anywhere, so the next Encode of the same plaintext reintroduces it
// as a literal. Call it exactly once per Miss received.
func (e *Encoder) NoteMiss(m Miss) {
	e.mu.Lock()
	e.stats.MissesNoted++
	e.mu.Unlock()
	e.cache.Invalidate(m.Missing)
}

// Encode transforms plaintext into an RE frame. Chunks already held
// and ACKed become References; every other cacheable chunk becomes a
// Literal (and is inserted into the sender cache as pending); the
// short tail and collision-conflicted chunks become Raw records.
// Encode returns ErrFrameTooLarge for inputs over MaxFrameBytes. The
// returned Frame.Wire is owned by the caller; LiteralBytes is owned by
// the Frame.
func (e *Encoder) Encode(plaintext []byte) (*Frame, error) {
	if len(plaintext) > MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	seq := e.seq

	var body bytes.Buffer
	var literals bytes.Buffer
	frame := &Frame{Seq: seq, OriginalLen: len(plaintext)}
	records := 0

	emitLiteral := func(chunk []byte) {
		body.WriteByte(recordLiteral)
		body.Write(binary.AppendUvarint(nil, uint64(len(chunk))))
		body.Write(chunk)
		literals.Write(chunk)
		frame.Literals++
		records++
	}
	emitRaw := func(chunk []byte) {
		body.WriteByte(recordRaw)
		body.Write(binary.AppendUvarint(nil, uint64(len(chunk))))
		body.Write(chunk)
		literals.Write(chunk)
		frame.RawRecords++
		records++
	}

	for _, chunk := range splitChunks(plaintext) {
		if len(chunk) < MinChunkSize {
			// Short tail (or a tiny whole input): never cached, so
			// it can never be referenced. Also the collision path:
			// see below.
			emitRaw(chunk)
			continue
		}
		id := Fingerprint(chunk)
		if held, ok := e.cache.Lookup(id); ok {
			if !bytes.Equal(held, chunk) {
				// Same id, different bytes in the sender cache:
				// a hash collision. Travel as Raw; never cached
				// or referenced on either end.
				emitRaw(chunk)
				continue
			}
			if e.cache.IsAcked(id) {
				body.WriteByte(recordRef)
				body.Write(id[:])
				body.Write(binary.AppendUvarint(nil, uint64(len(chunk))))
				frame.References++
				frame.HasReferences = true
				records++
				continue
			}
			// Held but not yet ACKed: referencing it would break
			// the ACK-gating invariant. Emit a literal (the peer
			// re-inserts idempotently and ACKs again) and count
			// the defensive re-send.
			e.stats.HeldUnackedResends++
			emitLiteral(chunk)
			continue
		}
		// New chunk: introduce it as a pending literal. Whether the
		// insert is held or dropped (cache full of pending entries)
		// does not change the wire: the receiver inserts what it
		// receives, and the sender references only what it holds
		// and has seen ACKed.
		e.cache.Insert(chunk)
		emitLiteral(chunk)
	}

	wire := make([]byte, 0, 1+10+10+10+body.Len())
	wire = append(wire, frameVersion)
	wire = binary.AppendUvarint(wire, seq)
	wire = binary.AppendUvarint(wire, uint64(len(plaintext)))
	wire = binary.AppendUvarint(wire, uint64(records))
	wire = append(wire, body.Bytes()...)

	frame.Wire = wire
	frame.LiteralBytes = literals.Bytes()
	e.stats.Frames++
	e.stats.References += frame.References
	e.stats.Literals += frame.Literals
	e.stats.RawRecords += frame.RawRecords
	e.stats.BytesIn += int64(len(plaintext))
	e.stats.BytesOut += int64(len(wire))
	return frame, nil
}

// DecoderStats counts decoder activity over its lifetime.
type DecoderStats struct {
	Frames     int
	References int
	Literals   int
	RawRecords int
	Misses     int
	Malformed  int
}

// DecodeResult describes a successful decode. NewChunkIDs are the ids
// the receiver newly holds from this frame (cacheable literals, in
// frame order); Ack() turns them into the Ack the coordinator must
// deliver to the sender. A literal whose id collides with different
// cached content is correctly emitted but never appears here.
type DecodeResult struct {
	Seq         uint64
	NewChunkIDs []ChunkID
	References  int
	Literals    int
	RawRecords  int
	OutputLen   int
}

// Ack builds the ACK message for this decode result.
func (r *DecodeResult) Ack() Ack {
	return Ack{FrameSeq: r.Seq, ChunkIDs: r.NewChunkIDs}
}

// Decoder reconstructs plaintext from RE frames against its Cache.
// Decode is atomic per frame: either the whole frame decodes (all Refs
// resolved, literals inserted, output returned) or it fails with no
// output and no cache mutation beyond LRU refreshes.
type Decoder struct {
	mu    sync.Mutex
	cache *Cache
	stats DecoderStats
}

// NewDecoder builds a Decoder over cache. A nil cache gets a fresh
// default cache; each direction needs its own Decoder and Cache.
func NewDecoder(cache *Cache) *Decoder {
	if cache == nil {
		cache = NewCache(DefaultConfig())
	}
	return &Decoder{cache: cache}
}

// Cache exposes the decoder's cache for wiring and diagnostics.
func (d *Decoder) Cache() *Cache { return d.cache }

// Stats returns a copy of lifetime decoder counters.
func (d *Decoder) Stats() DecoderStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

// Decode reconstructs the plaintext for one RE frame. On a reference
// miss it returns a *MissError (see AsMiss) with nil output; on
// structural problems it returns ErrMalformedFrame (or
// ErrFrameTooLarge for an oversized declared output). A successful
// decode returns the plaintext and its DecodeResult; the coordinator
// must deliver result.Ack() to the sender.
func (d *Decoder) Decode(wire []byte) ([]byte, *DecodeResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	seq, records, originalLen, err := parseFrame(wire)
	if err != nil {
		d.stats.Malformed++
		return nil, nil, err
	}
	// Resolve phase: read-only except for LRU refreshes. Every Ref
	// must resolve before any byte is emitted or any literal inserted,
	// so a miss leaves no partial state behind.
	resolved := make([][]byte, len(records))
	for i, rec := range records {
		switch rec.Kind {
		case RecordReference:
			held, ok := d.cache.Lookup(rec.ID)
			if !ok || len(held) != rec.Len {
				d.stats.Misses++
				return nil, nil, &MissError{Seq: seq, ID: rec.ID}
			}
			resolved[i] = held
		default:
			resolved[i] = rec.Data
		}
	}
	out := make([]byte, 0, originalLen)
	result := &DecodeResult{Seq: seq, OutputLen: originalLen}
	for i, rec := range records {
		switch rec.Kind {
		case RecordLiteral:
			if _, held := d.cache.InsertReady(rec.Data); held {
				result.NewChunkIDs = append(result.NewChunkIDs, Fingerprint(rec.Data))
			}
			result.Literals++
		case RecordRaw:
			result.RawRecords++
		case RecordReference:
			result.References++
		}
		out = append(out, resolved[i]...)
	}
	if len(out) != originalLen {
		// Unreachable: parseFrame already proved the sum. Defensive.
		d.stats.Malformed++
		return nil, nil, ErrMalformedFrame
	}
	d.stats.Frames++
	d.stats.References += result.References
	d.stats.Literals += result.Literals
	d.stats.RawRecords += result.RawRecords
	return out, result, nil
}

// ParseFrame parses wire without touching any cache. It is the shared
// structural validator for Decode and a diagnostic hook for tests and
// the coordinator (e.g. asserting that every Reference in a frame was
// ACKed before encoding). Record Data slices are views of wire.
func ParseFrame(wire []byte) (seq uint64, records []Record, originalLen int, err error) {
	return parseFrame(wire)
}

func parseFrame(wire []byte) (uint64, []Record, int, error) {
	if len(wire) < 1 || wire[0] != frameVersion {
		return 0, nil, 0, fmt.Errorf("%w: bad version", ErrMalformedFrame)
	}
	rest := wire[1:]
	seq, n := binary.Uvarint(rest)
	if n <= 0 {
		return 0, nil, 0, fmt.Errorf("%w: truncated sequence", ErrMalformedFrame)
	}
	rest = rest[n:]
	orig, n := binary.Uvarint(rest)
	if n <= 0 {
		return 0, nil, 0, fmt.Errorf("%w: truncated length", ErrMalformedFrame)
	}
	rest = rest[n:]
	if orig > MaxFrameBytes {
		return 0, nil, 0, ErrFrameTooLarge
	}
	count, n := binary.Uvarint(rest)
	if n <= 0 {
		return 0, nil, 0, fmt.Errorf("%w: truncated record count", ErrMalformedFrame)
	}
	rest = rest[n:]
	// Every record yields at least one output byte, so the count can
	// never exceed the declared output length.
	if count > orig && !(orig == 0 && count == 0) {
		return 0, nil, 0, fmt.Errorf("%w: record count exceeds output length", ErrMalformedFrame)
	}
	if orig == 0 && count != 0 {
		return 0, nil, 0, fmt.Errorf("%w: records with zero output length", ErrMalformedFrame)
	}
	records := make([]Record, 0, count)
	total := 0
	for i := uint64(0); i < count; i++ {
		if len(rest) < 1 {
			return 0, nil, 0, fmt.Errorf("%w: truncated record", ErrMalformedFrame)
		}
		tag := rest[0]
		rest = rest[1:]
		switch tag {
		case recordLiteral, recordRaw:
			ln, n := binary.Uvarint(rest)
			if n <= 0 {
				return 0, nil, 0, fmt.Errorf("%w: truncated record length", ErrMalformedFrame)
			}
			rest = rest[n:]
			if ln == 0 || ln > MaxFrameBytes || uint64(len(rest)) < ln {
				return 0, nil, 0, fmt.Errorf("%w: bad record length", ErrMalformedFrame)
			}
			kind := RecordLiteral
			if tag == recordRaw {
				kind = RecordRaw
			}
			records = append(records, Record{Kind: kind, Len: int(ln), Data: rest[:ln], ID: Fingerprint(rest[:ln])})
			rest = rest[ln:]
			total += int(ln)
		case recordRef:
			if len(rest) < 8 {
				return 0, nil, 0, fmt.Errorf("%w: truncated reference id", ErrMalformedFrame)
			}
			var id ChunkID
			copy(id[:], rest[:8])
			rest = rest[8:]
			ln, n := binary.Uvarint(rest)
			if n <= 0 {
				return 0, nil, 0, fmt.Errorf("%w: truncated reference length", ErrMalformedFrame)
			}
			rest = rest[n:]
			if ln == 0 || ln > MaxChunkSize {
				return 0, nil, 0, fmt.Errorf("%w: bad reference length", ErrMalformedFrame)
			}
			records = append(records, Record{Kind: RecordReference, ID: id, Len: int(ln)})
			total += int(ln)
		default:
			return 0, nil, 0, fmt.Errorf("%w: unknown record tag %#x", ErrMalformedFrame, tag)
		}
		if total > int(orig) {
			return 0, nil, 0, fmt.Errorf("%w: records exceed declared length", ErrMalformedFrame)
		}
	}
	if len(rest) != 0 {
		return 0, nil, 0, fmt.Errorf("%w: trailing bytes", ErrMalformedFrame)
	}
	if total != int(orig) {
		return 0, nil, 0, fmt.Errorf("%w: record lengths do not sum to declared length", ErrMalformedFrame)
	}
	return seq, records, int(orig), nil
}
