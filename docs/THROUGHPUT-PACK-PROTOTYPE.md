# Nexounel throughput pack — prototype (local code + tests only)

Status: implemented locally on top of `2424e95` (+ config-surface
commit `91e4969`); NOT pushed, NOT deployed. Coordinator-reviewed
before any push or deployment. All new behavior is behind config
flags that default to the pre-pack behavior; with every new flag off,
encoding is byte-identical to `2424e95` (golden test).

Productionization (2026-11-03, this milestone): the dictionary
compression piece below is productionized — level-9 default when
dictionaries are enabled, fail-closed symmetric enablement proven
by codec-level tests, fresh 1-core-pinned benchmarks. The packing
and redundancy-elimination pieces remain prototype/blocked exactly
as described below; no wire-format work was done in this milestone.
See "Production settings" and "Operator checklist" below.

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
  Productionized 2026-11-03: `Configure` resolves
  `DictEnabled + Level == 0` to level 9 (`DefaultDictLevel`, the
  measured knee; explicit levels 1..22 always win, and Level 0
  with dictionaries OFF still means legacy SpeedFastest,
  byte-for-byte — golden test). Long window stays OFF by default
  and is retained as live flag-gated code, not removed. The
  entropy gate, min-size gate and size check are unchanged.
  Fail-closed behavior is proven at the codec level
  (`TestDictFramesFailClosedAtCodecLevel`: pooled decoder rejects
  every dict frame with an error and no output bytes, and stays
  usable afterwards) and for wrong dictionaries
  (`TestWrongDictionaryFailsClosed`: a decoder holding only the
  other dictionary rejects the frame — the version-mismatch
  path, since a retrained pair gets new IDs). Dictionary
  identity is by ID only (v1, IDs 1/2, versioned file names,
  asserted in `TestEmbeddedDictionaries`); reusing an ID with
  different dictionary bytes is forbidden — the library resolves
  duplicate IDs last-wins and selection is by ID alone, so a
  same-ID content change cannot be relied on to fail closed
  (probes: a byte mutated in unreferenced dictionary content
  decoded fine; fully swapped content failed with a CRC error —
  detection is incidental, not guaranteed). A retrained pair
  MUST get a new version, new file names and new IDs.
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

Fresh production run, 2026-11-03 (this milestone):
`taskset -c 0 GOMAXPROCS=1 go test ./internal/compression/ -run '^$'
-bench 'BenchmarkZSTDMatrix|BenchmarkSmallFrame|BenchmarkDictChoice|BenchmarkPeakHeap'
-benchmem -count=1` (single run; ratios are deterministic, ns/op
varies run to run on the shared sandbox — treat timings as
indicative, ratios as the signal). The codec is benchmarked
directly, bypassing the `CompressPayload` entropy/min-size gates,
so the incompressible corpus measures codec behavior, not the
gate short-circuit; in production the entropy gate returns such
payloads raw before any encode.

- **Small frames are where dictionaries win:** a 696 B request
  frame: 114 B (legacy SpeedFastest, no dict) / 112 B (L9, no
  dict) → **40 B with dict at the production default**
  (Level 0 + dict, resolved to 9; identical bytes to explicit
  L9 + dict in every corpus) — 2.85× smaller than legacy.
  Dict at L1 gives 42 B. Long window changes nothing: 40 B with
  or without it.
- **Production default vs legacy, 1 MiB corpora.** Decompose the
  gain honestly: most of the bulk-frame gain is the LEVEL
  (SpeedFastest → 9), not the dictionary. At the same level 9,
  dictionaries add ~0.1% on 1 MiB frames; dictionaries win on
  SMALL frames (above), where the window cannot see enough
  history to help. Dict default = `DictEnabled`, Level 0 → 9,
  long off; legacy = no dict, SpeedFastest.

  | Corpus | Legacy (ratio) | L9, no dict (ratio) | Dict default, L9 (ratio) |
  |---|---|---|---|
  | Plaintext HTTP/JSON/HTML | 89,210 (0.08508) | 73,050 (0.06967) | 72,969 (0.06959) |
  | Mixed (50% plaintext / 50% random) | 581,840 (0.5549) | 567,263 (0.5410) | 566,513 (0.5403) |
  | Random (TLS-bulk-like, incompressible) | 1,048,637 (1.000) | 1,048,613 (1.000) | 1,048,614 (1.000) |

  Legacy → dict default: plaintext −18.2%, mixed −2.6%,
  random none (codec-only; gates return raw live). Of the
  plaintext gain, −18.1 points are the level and −0.1 points
  are the dictionary. L19 + dict buys almost nothing more on
  these corpora (plaintext 71,720 vs 72,969, −1.7%; mixed
  565,302 vs 566,513, −0.2%) at 3–15× the encode time in this
  run. L1/L3 + dict are measurably worse than L9 + dict on
  mixed (581,155 / 571,654 vs 566,513). Long window:
  byte-identical output to the short window in EVERY
  level/corpus pair — zero gain, confirmed again.
  Heap (peak `HeapAlloc` sampled per iteration, rough gauge):
  legacy 24.8 MB, dict default (L9) 92.0 MB, L19 + long
  236.8 MB. The dict-default heap fits the 960 MB box with room
  to spare but is ~3.7× the legacy peak — re-measure on the
  target box before treating it as settled. (The heap figure
  covers the whole L9 + dict configuration, not the dictionary
  alone: larger encoder windows and two pooled dict encoders
  both contribute; the benchmark does not decompose them.)
- **Direction choice (plaintext, L9):** upload-only dict 0.06974,
  download-only 0.06959, auto-both 0.06959 (picks the best),
  no-dict 0.06967. Auto-both costs ~2× a single encode
  (~24 ms vs ~12–13 ms per 1 MiB here) because the
  direction-blind seam encodes twice; a direction-aware call
  site using `CompressPayloadForDirection` pays one encode.
  No such call site is wired in this milestone.

Earlier prototype measurements (kept for reference): wrong-dict
costs +58% to +172% bytes; auto mode always picks correctly.
On 1 MiB frames the dict gains ≤0.8% at a fixed level — the
fresh table above agrees (0.1% at L9); the larger
legacy→default deltas are the level-9 default doing its work.

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

## Production settings (dictionary compression, 2026-11-03)

- `ZSTD_DICT_ENABLED=true`, `ZSTD_LEVEL=9` (explicit),
  `ZSTD_LONG_ENABLED=false` (default; leave unset or false).
  `ZSTD_LEVEL=0` with dicts enabled now resolves to 9 in
  `compression.Configure`, but set 9 explicitly so the effective
  level is visible in the config file. `ZSTD_LEVEL` 1..22
  always overrides the default; `ZSTD_LEVEL=0` with dicts OFF
  still means legacy SpeedFastest, byte-for-byte.
- Guards unchanged: entropy gate (≥7.6 bits), min-size gate
  (default 100 B), size check (never emit a frame ≥ input).
  No wire-format change: the compression-type nibble is
  untouched, and dictionary frames are standard zstd frames
  carrying a dictionary ID.
- Symmetric enablement is a HARD requirement: the SAME binary
  version with the SAME three settings on both ends. There is
  no negotiation and no version fallback. A peer without dict
  config, or on a different dictionary version (different IDs),
  drops dictionary frames with an unknown-dictionary error —
  traffic does not silently corrupt, but it does not flow
  either. Enabling dicts on one end only is a misconfiguration
  that presents as packet loss on the dictionary direction.
- Dictionary versioning: v1, upload ID 1, download ID 2,
  files `upload-v1.dict` / `download-v1.dict` (49,261 B each).
  NEVER reuse an ID with different dictionary bytes. A
  retrained pair gets a new version, new file names and new
  IDs, shipped in a new binary on both ends together.
- Follow-ups, documented ONLY (no code in this milestone):
  RE ACK transport + server-side RE wiring, and the packed-data
  wire format + server unpacker + ARQ ACK accounting for
  packing (see "What was built" above). Neither changes any
  dictionary behavior.

## Operator checklist — enabling dictionaries on both ends

1. Confirm both ends run the SAME binary version (same
   embedded v1 dictionaries). Mixed versions with different
   dictionary IDs will drop dictionary frames.
2. Set on BOTH the server config and the node config:
   `ZSTD_DICT_ENABLED=true`, `ZSTD_LEVEL=9`,
   `ZSTD_LONG_ENABLED=false`. Keep the compression-type
   settings (`UPLOAD/DOWNLOAD_COMPRESSION_TYPE`) as they are;
   dictionaries apply to the zstd codec only.
3. Restart BOTH processes. `Configure` runs once at startup;
   changing the config file without a restart changes nothing.
   Restart one end, then the other — during the window, the
   restarted end's dictionary frames are dropped by the
   not-yet-restarted peer (fail-closed, visible as loss, not
   corruption). Keep the window short.
4. Verify: send small request-shaped traffic and confirm the
   tunnel still carries it end to end (a one-ended enablement
   shows up here as dropped frames, not garbled data). If
   available, check logs for unknown-dictionary / decompression
   failures — any such line after step 3 means the ends
   disagree on settings or version: stop and compare configs
   and binary versions, do not "fix" it by toggling one end.
5. Rollback: set `ZSTD_DICT_ENABLED=false` on BOTH ends and
   restart both. Dictionary-free frames decode under either
   config, so rollback traffic flows as soon as both ends are
   back on the legacy encoder; a half-rolled-back pair still
   drops the dict-enabled end's frames.
6. Do NOT enable `ZSTD_LONG_ENABLED`: it measured zero gain
   and costs heap. Do NOT set `ZSTD_LEVEL` above 9 without
   re-benchmarking on the target box: L19 buys ~0.2–1.7% on
   1 MiB corpora at several times the CPU and ~237 MB heap
   peak in the sandbox gauge.

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
around). For the productionized dict default specifically:
steady-state heap on the 960 MB target box (sandbox gauge
92 MB peak, single run), and one-ended-enablement behavior on a
live tunnel (fail-closed dropping is proven only in unit tests
with the real codec pools, not against a live peer).
