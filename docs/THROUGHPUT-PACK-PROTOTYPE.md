# Nexounel throughput pack — prototype (local code + tests only)

Status: implemented locally on top of `2424e95` (+ config-surface
commit `91e4969`); NOT pushed, NOT deployed. Coordinator-reviewed
before any push or deployment. All new behavior is behind config
flags that default to the pre-pack behavior; with every new flag off,
encoding is byte-identical to `2424e95` (golden test).

Scope: maximize effective data per DNS request on a 1-vCPU / 960 MB
server, with latency explicitly irrelevant. Pure Go only
(`CGO_ENABLED=0` release builds); no new dependencies; no neural /
PAQ / CMIX / exotic codecs, per direction. Three pieces, built by
three implementers in isolated worktrees and merged by the
coordinator:

| Piece | Code | State |
|---|---|---|
| zstd-long + trained dictionaries | `core/internal/compression/` | Wired (Configure at startup, both binaries). Default-off. |
| Packing / coalescing | `core/internal/client/packer.go` + dispatcher gate | Engine built, gate admits NOTHING: live byte-packing is BLOCKED by the wire format (see below). Default-off, provably identical on/off. |
| Redundancy elimination (EndRE-style) | `core/internal/redundancy/` + `docs/throughput-pack-redundancy-design.md` | Library only, UNWIRED: needs an ACK-transport format (see below). Default-off. |

## What was built

- **Dictionaries + zstd** (`pack/dict`, `eae0a44`): two embedded
  versioned dictionaries (upload-v1 / download-v1, 49,261 B each,
  IDs 1/2, cap 64 KiB enforced by test), trained by
  `dicts/gen` from deterministic SYNTHETIC samples only (HTTP
  boilerplate, JSON, HTML; seed 42; `*.example.com` fixtures; never
  user traffic). `Configure(ZSTDOptions{DictEnabled, Level,
  LongEnabled})` rebuilds encoder/decoder pools; zero value =
  legacy behavior. `CompressPayload` signature and the compression
  nibble negotiation are untouched; with dicts on, the
  direction-blind seam encodes with both dicts and keeps the
  smaller frame (`CompressPayloadForDirection` exists for future
  direction-aware call sites). klauspost v1.18.5 has NO
  long-distance-matching option and NO numeric levels (only four
  buckets via `EncoderLevelFromZstd`); "long" is a 16 MiB window
  and measured ZERO ratio gain at every level/corpus. Decoder
  holds both dicts and selects by frame dict ID; a peer without
  dict config fails closed (packet dropped, never wrong bytes).
  Symmetric enablement on both ends is a hard operational
  requirement — there is no dict-version negotiation.
- **Packing** (`pack/packing`, `3136a93`): `Packer` engine
  (MTU-full pre-flush, delay expiry, buffer cap, close/drain,
  order-preserving, no goroutine owned, timer-leak tested) plus a
  dispatcher choke point (`emitOutboundTask`). The safety gate
  `segmentsMergeableForPacking` admits NO packet type: every
  payload-carrying segment carries StreamID/SequenceNum/FragmentID
  and ARQ accounting is keyed by sequence number, so naive
  concatenation would corrupt streams on loss (duplicate bytes on
  retransmit). There is no packed-*data* frame format today (only
  packed *control* blocks). Follow-up before any live gain: a
  packed-data wire format + server unpacker + ARQ ACK accounting +
  negotiation. The coordinator replaced the implementer's
  fail-loud `panic` in the unreachable branch with a loud log +
  fallthrough to the normal (unmerged, always-correct) send, so a
  future gate change can never crash the process.
- **Redundancy elimination** (`pack/redundancy`, `cc70b64` +
  `00a54f7`): design doc first, then a stdlib-only package
  (gear-hash content-defined chunking 128/512 B, SHA-256-truncated
  8 B chunk IDs, bounded LRU cache default 128 MB, ACK-gated
  references, literal fallback + resync, per-frame independence).
  Two-ended lossy simulation (5% and 25% frame+control loss):
  byte-exact reconstruction, bounded caches, no deadlock. The
  package is UNWIRED: ACKs have no transport format yet (no
  RE control packet type), and without ACKs the encoder can never
  emit a reference (ACK-gating), so wiring it without the ACK
  transport would be a no-op that only pays chunking cost.
  Follow-up: RE ACK transport + server-side wiring + ACK
  coalescing/timing policy. Composition contract (§7 of the
  design doc): RE first, then the codec on the remainder, with the
  entropy gate evaluated over literal bytes only — that
  gate-bypass entry point is still to be built in the codec.

## Wiring (coordinator, this milestone)

- Config surface (`91e4969`): `ZSTD_DICT_ENABLED`, `ZSTD_LEVEL`,
  `ZSTD_LONG_ENABLED`, `PACKING_ENABLED`, `PACKING_MAX_DELAY_MS`,
  `PACKING_MAX_BUFFER_BYTES`, `RE_ENABLED`, `RE_CACHE_MAX_MB`
  (client); `RE_ENABLED`, `RE_CACHE_MAX_MB`, plus the `ZSTD_*`
  keys (server). All default-off / legacy values.
- `compression.Configure` is called from both binary entry points
  (`cmd/nexounel-node`, `cmd/nexounel-server`) with the loaded
  config values. Library embedders must call it themselves.
- No server-side RE or packing wiring (blocked as above).

## Measured (1-core pinned, `taskset -c 0`, sandbox — re-benchmark on the target box)

- **Small frames are where dictionaries win:** a 696 B request
  frame: 114 B (L1, no dict) / 112 B (L9) → **42 B / 40 B with
  dict** (2.7–2.8× smaller). Wrong-dict costs +58% to +172%
  bytes; auto mode always picks correctly. On 1 MiB frames the
  dict gains ≤0.8% (nothing).
- **Levels:** 9 is the knee (bulk plaintext 0.0696 vs 0.0754 at
  L3 and 0.0684 at L19; L19 costs 5–7× time and, with the long
  window, ~10× heap: 220–337 MB vs ~25 MB baseline — too much
  for the 960 MB box). Long window: zero gain everywhere — OFF.
  Recommended when dict is enabled: `ZSTD_LEVEL=9` (explicit;
  level 0 still means legacy SpeedFastest — the code does not
  remap it).
- **Redundancy:** steady-state wire ratios (2 KiB segments):
  repetitive 0.049 (vs zstd-only 0.212), mixed 0.532 (vs 0.606),
  unique bulk 1.015 (worse than raw — neutralized in the wired
  path by discarding reference-free frames), partial 0.164
  stacked RE+zstd (best). Encode ~25 µs / 2 KiB (~82 MB/s,
  ~200× the download rate) — CPU negligible at tunnel rates.
- **Packing:** at the real 110 B fleet MTU, realistic mixed
  segments gain NOTHING (1.00× — most segments already fill one
  query); wins concentrate in uniformly tiny segments and larger
  budgets (8.8× at 1,200 B, 32× at 32 KiB budgets). Packer
  throughput ~87 MB/s worst case on the sandbox core.
- **Caps enforced:** dict ≤64 KiB each; RE cache ≤128 MB
  default (clamp 1–512 MB), 524,288 entries, 1 MiB frames;
  packing delay 0–1000 ms, buffer 1 KiB–1 MiB.

## Gates (this milestone)

- `go vet ./...` clean; `gofmt` clean on touched files; `go build`
  clean (incl. `CGO_ENABLED=0`).
- New/affected packages green: `compression`, `redundancy`,
  `config`, `vpnproto`, `client` (except the pre-existing
  sandbox-UDP failures, below).
- Full `go test ./...`: only the pre-existing sandbox-UDP
  failures, identical names to the clean-`2424e95` baseline run
  (temp worktree, removed). No new failures.
- No secrets/hardcoding: grep-verified — fixtures use reserved
  `*.example.com` domains and synthetic tokens only; dictionaries
  trained from synthetic templates only.

## What stays unproven until a field test

Live-tunnel behavior of every piece; dictionary quality on real
traffic (synthetic corpora only); RE sync under real resolver
loss and fallback frequency with a realistic 128 MB cache;
server-side RE/packing wiring (blocked on wire formats);
cold pool-init cost on the 1-vCPU node; combined
packing+dict+RE effect (each measured alone); `-race` runs
(require cgo for the detector — not run, flagged, not worked
around).
