# Throughput pack: redundancy-elimination (RE) layer — design

Prototype in `core/internal/redundancy/`. Config already committed, never touched here: `RE_ENABLED=false`, `RE_CACHE_MAX_MB=128` (clamp 1..512). Pure Go, stdlib only, no cgo, no model, no new dependency. One direction = one encoder + one decoder + one cache each; the coordinator wires two.

## 0. Position

Plaintext packed segment → **RE** → codec (`CompressPayload`) → FEC → DNS wire. RE exploits repetition *across* frames and time; the codec exploits repetition *within* the remainder. Neither assumes anything about the other except the contract in §7.

## 1. Wire framing (RE frame v1)

```
[0x01 version][uvarint seq][uvarint originalLen][uvarint recordCount]
  0x01 Literal : [uvarint len][bytes]        cacheable; id = hash(bytes)
  0x02 Ref     : [8-byte chunk id][uvarint len]
  0x03 Raw     : [uvarint len][bytes]        never cached, never referenced
```

A Literal carries no id: the receiver hashes the bytes to recover it, saving 8 B per literal. A Ref carries the expected length as a cross-check. Zero-length records, trailing bytes, or `originalLen` mismatch are malformed-frame errors. Max input/output per frame is 1 MiB. `seq` (from 1, per `Encode`) is ACK correlation only, never an ordering requirement (§6).

## 2. Chunking (content-defined, gear rolling hash)

Deviation from the research note (§5, "SampleByte-style"): SampleByte samples fixed positions, so a one-byte insertion shifts every later boundary. A gear rolling hash gives true content-defined chunking that survives insertions/deletions — the small-mutation traffic RE is built for — at the same O(n) cost, stdlib only:
`h = (h << 1) + byte`, cut when `(h & 0x7F) == 0x7F` after the minimum.

- Minimum 128 B: below this, reference overhead (8 B id + headers) eats
  the gain and the cache fills with rarely-repeating fragments.
- Maximum 512 B: forced cut bounds scan time, entry size, and the damage
  one mutation does (at most one ~256 B chunk spoiled).
- Target average ~256 B (128 minimum + 1/128 cut probability per byte):
  a header block yields 1–3 chunks; a 2 KiB packed segment ~8 records,
  so record overhead stays under ~5%. The final tail under 128 B is a
  Raw record, not cached.

## 3. Fingerprinting / chunk identity

Id = first 8 bytes of SHA-256 over the chunk (`crypto/sha256`). A truncated strong hash, not FNV/xxhash: a false identity would silently corrupt reconstruction; 64 bits makes accidental collision negligible (birthday bound ~2^32 chunks, unreachable at tunnel rates). On the astronomically unlikely collision (same id, different bytes): first-inserted content wins, the colliding chunk is never cached or referenced, and travels as Raw — reconstruction stays byte-exact. The collision branch is tested via an internal seam (a real SHA-256 collision cannot be constructed).

## 4. Cache (bounded LRU, byte-accounted)

One `Cache` type serves both ends. Accounting is deterministic: stored bytes + 64 B overhead per entry — never `runtime.MemStats`. Caps:
`MaxCacheBytes` (default 128 MiB from `RE_CACHE_MAX_MB`), `MaxEntries`
(default 524288 ≈ 128 MiB / 256 B). Eviction is LRU by last use. **Un-ACKed (pending) entries are never evicted** before their ACK or
`PendingTimeout` (30 s): eviction skips them, and if only pending
entries remain, new inserts are dropped instead. A dropped insert only costs a future reference, never correctness. The receiver has no pending entries, so its eviction is plain LRU; a reference to an evicted chunk is handled by the miss protocol (§5), not cache agreement.

## 5. ACK-gating protocol

Invariant: **the sender references only chunks the peer has ACKed.** Sender entries start pending on first literal send; `NoteAck` flips them to acked. ACK message (transport-agnostic, coordinator delivers):
`{FrameSeq, ChunkIDs[]}` — ids newly held after decoding that frame, in
frame order, emitted immediately after a successful decode (coalescing across frames only delays references). ACKs are idempotent; a lost ACK only delays compression, so the ACK channel needs no reliability. An encoder never references an un-ACKed chunk: it defensively emits a literal and counts the re-send (`HeldUnackedResends`, informational); gating is asserted by auditing emitted frames with `ParseFrame`, proving no Reference names an un-ACKed chunk.

Miss / fallback / resync (exact procedure): (1) Receiver finds an unknown Ref → decode fails atomically (no output, no inserts from that frame) and sends `Miss{FrameSeq, MissingID}`. (2) Sender on `NoteMiss` deletes the id and re-encodes the same plaintext; the chunk travels as a Literal, is re-inserted, and re-ACKed. (3) Coordinator caps fallback re-encodes at 3 per segment, then sends the plaintext bypassing RE. Every fallback terminates in literals, so byte-exact reconstruction is guaranteed regardless of cache state.

## 6. Loss-safety / per-frame independence

Invariant: **a frame's decodability depends only on its own bytes plus the chunks ACKed before it was encoded — never on any other frame's bytes.** Losing frame F only delays ACKs for F's literals; later frames reference older ACKed chunks or carry literals, so they decode without F. Decoding is atomic per frame (all Refs resolved before any byte is emitted) and stateless across frames except cache + ACK set. Duplicate delivery is harmless (idempotent inserts and ACKs). No cross-frame compression window, no resync handshake.

## 7. Composition with the codec (contract for the coordinator)

- RE runs first. `Encode` reports `HasReferences`.
- If false, the coordinator **discards the RE frame** and feeds the
  original plaintext to `CompressPayload` exactly as today: entropy
  gate, min-size gate, and size check see unmodified data.
- If true, the coordinator feeds the **RE frame bytes** to the codec
  with the entropy gate **bypassed** (evaluated, if at all, only over
  the literal bytes, exposed as `Frame.LiteralBytes`): Ref records are
  8-byte hash ids — near-maximum entropy — so sampling the frame would
  trip the ≥7.6 bits/byte gate and skip compression of the literal
  remainder. The size check (compressed ≥ input → raw) still applies.
  Bypassing the gate never affects correctness (it is an optimization).
  Until a gate-bypass codec entry point exists, feeding the frame
  through `CompressPayload` unmodified is correct but may forfeit codec
  gain on literal portions of reference-dense frames.
- Decode side is the mirror: codec-decode first, then RE-decode.

## 8. Resource caps (enforced)

Cache bytes: `RE_CACHE_MAX_MB` (128 default, 1..512). Entries: 524288 default. Chunk: 128 min / 512 max. Frame input/output: 1 MiB. Pending exemption: until ACK or 30 s. Fallback re-encodes: 3 per segment (coordinator). Memory on the 1 vCPU / 960 MB node is bounded by the cache cap plus one in-flight frame per direction; SHA-256 per ~256 B chunk is trivial at tunnel rates (≤ ~0.5 MB/s).

## 9. What stays unproven

RE sync under real resolver loss, server-side wiring, and interaction with trained-dictionary quality need the coordinator's session-path wiring plus live byte-exact tests from AWS. On unique bulk data RE gains ~0 by design; reference-free frames are discarded (§7), so the codec behaviour there is unchanged.

