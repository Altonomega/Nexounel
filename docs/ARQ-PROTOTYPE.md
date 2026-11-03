# ARQ Repair Experiment — Prototype

Status: **flagged-off prototype, local only.** Nothing here is live.
The live A/B that measures this work is a separate step, run by the
operator against the deployed configs. This document is the contract
for that step: what each knob does, what "off" guarantees, and how the
result will be measured.

## The problem (from the read-only ARQ audit)

Selective-repeat ARQ is ~80% built and live for the download
direction: proactive duplication, Reed–Solomon FEC (download-only),
per-SN ACK + gap-triggered per-SN NACK + RTO resend
(`core/internal/arq/arq.go`, wired on both ends). The audit found
four gaps:

1. **Server-side NACKs disabled by default.** The server's
   `ARQ_DATA_NACK_MAX_GAP` defaults to 0, so upload repair is
   RTO-only (0.6s → ×1.35 → 3s cap), while the client already NACKs
   with a gap of 64. Possibly deliberate — server NACKs consume
   download response slots — so it must be measured, not flipped
   blindly.
2. **Every repair is multiplied by duplication.** A RESEND inherits
   the upload data duplication count (3 by default); ACK/NACK frames
   inherit the download data count (7 by default) — roughly 875
   queries per 1,000 download segments, the largest single query
   sink, larger than any SACK-bitmap saving.
3. **ACKs are per-SN, not cumulative; no SACK bitmap.** The bitmap
   gain is small (up to 8 segments pack into one query), so it is
   phase 2, only if measured.
4. **No budgets.** No global query budget, no retransmit budget cap,
   fixed windows (5000 client / 2000 server).

## Finding F-C1 (audit correction): queue-level dedup already exists

The audit's premise for one proposed knob was wrong, and the
prototype corrects it instead of building on it: identical
ACK/NACK frames pushed twice while the first is still queued are
**already** collapsed to one queued frame, on both the client
(`Stream_client.PushTXPacket`) and the server
(`Stream_server.PushTXPacket`), by the MLQ census keyed on
(stream, packet type, sequence number, fragment ID). This is pinned
by `TestPushTXPacketDedupsIdenticalAckNack` (client) and
`TestServerPushTXPacketDedupsIdenticalAckNack` (server). The
remaining per-frame multiplication is the **send-side duplication
count**, which is what the experiment pins. No new queue-dedup code
was needed; building it would have duplicated the census.

## The experiment: one master flag

`ARQ_EXPERIMENT_ENABLED` (bool, default `false`) exists in both the
client and the server config. **When off, every experiment knob is
inert and repair behavior is byte-for-byte the historical one.**
The numeric keys below are only read when the flag is on; setting
them with the flag off changes nothing. The flag never changes the
wire format: no new packet types, no new fields, no framing change.
SACK bitmaps, congestion windows, and session persistence are
explicitly out of scope.

### Knob 1 — server NACK gap (existing key)

The key already exists and is already settable:
`ARQ_DATA_NACK_MAX_GAP` (server default 0, client default 64,
clamped to window/4). The prototype adds one rule in server config
normalization: with the experiment on and the gap unset (0), the
gap becomes **64**, so the server starts sending gap-triggered
NACKs for the upload direction. An explicit value still wins.

Limitation, documented deliberately: after the defaults merge, an
explicit 0 is indistinguishable from unset, so with the experiment
on, 0 means 64. To force NACKs off, turn the experiment off. The
client gap is untouched (already 64), and the server-advertised
ceiling (`MAX_ALLOWED_CLIENT_ARQ_DATA_NACK_MAX_GAP`) is untouched.
The NACK emission mechanism itself is unchanged and already
covered by the gap tests in `arq_test.go`.

### Knob 2 — RESEND duplication (new key)

`ARQ_RESEND_DUPLICATION_COUNT` (client only, 0–8, default 0).
0 means "inherit the upload data count" (the historical behavior).
With the experiment on and the key unset, RESEND is sent **once**.
An explicit value wins. The pinned value still honors a
server-advertised duplication ceiling, and adaptive duplication
plus the FEC clamp are skipped for pinned packets: the experiment
arm must measure the pinned count, not a loss-driven one. DATA,
setup, and PING counts are untouched.

### Knob 3 — ACK/NACK duplication (new key)

`ARQ_ACK_NACK_DUPLICATION_COUNT` (client only, 0–8, default 0).
Same semantics as knob 2, applied to `DATA_ACK`/`DATA_NACK` only:
0 means "inherit the download data count"; with the experiment on
and the key unset, ACK/NACK are sent **once**. This is the knob
that attacks the ~875-queries-per-1,000-segments sink. It does not
touch queue-level dedup (finding F-C1: already present) and does
not touch CLOSE/RST/setup packets.

### Knob 4 — per-tick RTO retransmit budget

`ARQ_RETRANSMIT_BUDGET` (both configs, 0–1024, default 0). 0 means
unlimited (historical). With the experiment on and the key unset,
the budget is **64**. Each `checkRetransmits` tick enqueues at most
that many overdue data items, **oldest first** — greatest distance
from `sndNxt` under uint16 wraparound, which is "lowest sequence
number first" in stream order. Deferred items stay overdue in the
send buffer and are reconsidered on the next tick, so nothing is
starved: the deferred tail is the newest, and it ages into the
front. The budget applies to the data RTO path only, not to
control-packet retransmits and not to NACK-triggered resends
(`HandleDataNack`, already interval-gated). The virtual control
stream (client stream 0) is deliberately excluded: it is
constructed without the experiment fields and keeps NACK gap 0.

## Off-identical proof

- Config: with the flag off, `finalizeClientConfig` /
  `finalizeServerConfig` produce the historical normalized values
  (server gap 0, client gap 64, keys 0). Pinned by
  `TestFinalizeClientConfigExperimentDefaultsInert` and the
  off-case in `TestFinalizeServerConfigExperimentNackGap`.
- ARQ: `resolveRetransmitBudget` returns 0 unless the flag is on
  (`TestResolveRetransmitBudget`); with budget 0 the tick loop is
  byte-for-byte the old loop, proved by
  `TestRetransmitBudgetOffEnqueuesEverything` (an explicit budget
  key with the flag off enqueues everything).
- Duplication: with the flag off, explicit experiment keys change
  nothing (`TestRuntimePacketDuplicationCountExperiment`, "off
  ignores experiment keys").

## What is still unproven

Everything about live behavior. The lab proves the mechanics (cap
ordering including wraparound, pin values, inertness when off) and
nothing about the tunnel: no live goodput numbers, no loss-window
behavior, no interaction with FEC/adaptive duplication under real
resolver loss, no effect of server NACKs on download response
slots. The deployed configs' actual ARQ values were never read
during this work; the A/B step must read them (grep `^ARQ_` on the
deployed files) before flipping anything.

## The live A/B (operator step, not this prototype)

1. Read the deployed `ARQ_*` values on both ends; record them.
2. Control arm: current configs, unchanged. Treatment arm: set
   `ARQ_EXPERIMENT_ENABLED = true` on **both** ends (server +
   node), nothing else. Restart both, same fleet, same bench
   files, same method as the existing benchmarks.
3. Primary metric: **goodput per query** — byte-exact bytes
   delivered per DNS query issued, in both directions, under the
   same loss conditions. Secondary: bulk up/down throughput,
   session loss, NACK/RTO resend counts from logs.
4. Only if the bundle wins, isolate knobs one at a time (gap alone,
   dup pins alone, budget alone) before adopting any of them as a
   default. SACK bitmaps (phase 2) only if the measured gap
   justifies them.
5. Rollback is the control arm: flag off, restart. No config
   surgery beyond the flag.

## Discrepancies from the audit plan

- D-A1: queue-level ACK/NACK dedup was already shipped (F-C1
  above); the prototype pins it with tests instead of rebuilding
  it, and attacks the send-side duplication count instead.
- D-A2: the ACK/NACK pin is a duplication-count key, not a new
  dedup pass; there is no separate dedup flag — the master flag
  gates it, and the two numeric keys are the only per-knob
  controls.
- D-A3: explicit server gap 0 cannot be expressed while the
  experiment is on (see knob 1 limitation).
- D-A4: the RTO budget does not cover control retransmits or
  NACK-triggered resends (deliberate; see knob 4).
- D-A5: the virtual control stream is excluded from the
  experiment (deliberate; see knob 4).
- D-A6: no offline goodput-per-query harness was built. The
  existing test harnesses drive one ARQ end against a capturing
  enqueuer; a faithful two-ended loss harness is future work, and
  the live A/B is the honest measurement anyway. No lab number in
  this document should be read as a tunnel prediction.
