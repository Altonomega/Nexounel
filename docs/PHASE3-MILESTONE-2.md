# Nexounel Phase 3 — Milestone 2 (local code + tests only)

Status: implemented locally on branch `mesh-m2` on top of `394591a`;
NOT pushed, NOT deployed. Reviewed by TARS before any push or
deployment. No server was contacted; all verification is lab-only
(loopback + synthetic fixtures + fake UDP/control-socket harnesses).

Scope (per `phase3-spec-draft.md` §§0–14 and the Milestone 2 work
order): the startup-stall fix (prerequisite), enroll mode in the
node binary (§3.3), control streams (§4.2), peer control ports
(§8.3, default disabled), and the panel mesh UI + enrollment API
(§§3.2/3.4/4.4). Out of scope and untouched: dictionary
compression behavior, RE/packing wire formats, the ARQ prototype,
resolver fleet switching, the installer/offline bundle, any deploy,
any live probing.

## Step 1 — the startup stall: root cause and fix

The field symptom (2026-11-03, build `c75ebc4`): the node process
started, stayed ~idle in epoll/futex wait, bound zero forward
listeners, and its resolver-cache log grew slowly, then stalled —
across two process lifetimes.

Root cause: the multi-session probe pass re-ran the full MTU binary
search over the whole fleet on every restart, even when the client
was built from a fresh cache log. The F1a fast start (verify cached
capacities, re-probe only failures) lived in
`applyPreknownMTUsFromLog`, which only the single-session `Run`
loop called; the probe pass (`runMultiSession` →
`RunInitialMTUTests` → `runFullMTUTests`) discarded pre-filled MTUs
and paid the full scan at logs-mode parallelism 32 and retries 5 —
up to ~120 s per degraded resolver (5 attempts × 2 s timeout × 2
boundary checks × up to 6 query types). The F1b liveness pre-filter
only removes fully-dead resolvers; degraded resolvers (answer tiny
probes, fail MTU-sized ones) pass it and burn the full search. The
process looked idle because every exchange is deadline-bounded;
Phase 3 (forward listeners) binds only after the probe pass, hence
zero listeners. No deadlock was observed in code: no unbounded wait
exists on the probe path. The deployed 0.2.0 path was NOT
implicated (it never had `BootstrapFromLogs` wired in) and no
wire-format change was needed.

Fix (`core/internal/client/mtu.go`): in `RunInitialMTUTests`,
before the transport fallback chain, when connections carry
pre-known MTUs and `FastConnect` is off, try
`applyPreknownMTUsFromLog` and return on success; on failure clear
the flag, reset scan state, and fall through to the full scan —
exactly mirroring the single-session `Run` loop's fallback, so no
cached value is ever trusted blindly. A test seam
(`Client.queryTransportFactory`, following the injectable-prober
precedent) lets the regression test run a fake capacity-limited
resolver in-process, since the sandbox blocks UDP loopback.

Regression test (failed before the fix, passes after):
`TestProbePassVerifiesCachedMTUsWithoutFullScan`
(`core/internal/client/probe_pass_cache_test.go`) — 3 resolvers,
fresh cache, fake ceiling equal to cached values: 39 exchanges per
resolver before the fix, 2 (verify-scale, non-zero, proving verify
ran) after. Guard tests prove the fallbacks: stale caches are
re-measured, cold fleets still run the full scan. Cache fast-start
semantics (union, not replace), verify behavior, the panel cap,
and small-fleet behavior are preserved (existing tests).

## What was built

| Spec section | Code | Notes |
|---|---|---|
| §3.3 enroll mode | `core/cmd/nexounel-node/enroll.go`, `main.go` | `--enroll` / `--join-token` / `--join-token-file` (+ stdin, refused on a TTY). Requires `PROTOCOL_TYPE=TCP` and a valid `NODE_ID`. Retry with backoff (5 s doubling to 60 s) on transient failures; permanent token failures exit. Success writes key (0600) + mesh secret (0600) + validated config (config installed last, the commit point), then `syscall.Exec`s into a normal node. Forward ports are never opened in enroll mode. Post-enrollment local failures are fatal, never retried (token already burned). |
| §3.4 bootstrap sessions | `core/internal/udpserver/bootstrap.go`, `server_*.go`, `session.go` | Two-trial ingress, zero cost to normal traffic: node codecs first, bootstrap set only when no node codec authenticates, on both ingress paths. Bootstrap codecs live in a separate atomic snapshot (cap 64, expiry enforced at creation and by sweep), tried last, never attributed to a node. Sessions carry `Kind` + `BootstrapFingerprint`; bootstrap sessions are skipped by `SessionSummaries`. No wire-format change: the bootstrap key IS the capability (trial decryption), no label travels in the clear. |
| §3.4 enrollment handler | `core/internal/udpserver/enroll_handler.go`, `reserved_stream.go`, `core/internal/enroll/target.go` | Reserved-target framing (`NXCT` + version + name; shapes cannot collide with STREAM_SYN payloads). Dispatch is idempotent (re-SYN re-sends CONNECTED), fail-closed (`AllowedTarget` matrix), `net.Pipe` attach mirroring the forward path. The handler relays via `enroll.Issuer` (15 s issuer timeout in a 60 s budget), relays panel refusals verbatim, drops the bootstrap key on success (best-effort; the panel burn is authoritative), never logs key/config material, global 30/min rate limit. |
| §3.4 issuer transport | `core/internal/enroll/issuer.go` | `HTTPIssuer` POSTs `{fingerprint, request}` to a loopback URL only (refuses anything else); stamps version + capability itself; transport/non-200/malformed → transient `ErrIssuerUnavailable`; `PermanentErrorCode` classifies the five token codes. |
| §4.1 control socket | `core/internal/control/control.go` | Commands `list-mesh`, `add-bootstrap-key`, `remove-bootstrap-key` (fingerprint/key/expiry validated by the handler; removal idempotent). `Client.ListMesh` / `AddBootstrapKey` / `RemoveBootstrapKey`. |
| §4.2 framing + messages | `core/internal/mesh/control.go` | 4-byte length prefix + JSON envelope `{version, kind, payload}`, 64 KiB bound, version 1 only. Kinds: heartbeat, table, config, rotation, term, ack. |
| §4.2 coordinator (mother) | `core/internal/mesh/mesh.go` | `AddMember` (mother-only, registry-authenticated admission), `EnsureChief` (mother-only, new term — see D-7), `PublishMotherTable` (folds heartbeat liveness/capacity, recomputes weights, does not mutate the enforced table). |
| §4.2 server mesh state | `core/internal/udpserver/mesh_control.go` | `InitMesh` (registry-derived table, deterministic first chief, T1/v1), heartbeat intake (NodeID must equal session identity; unknown members admitted on session-key proof), signed-snapshot attach when a signing key is configured, `MeshSnapshot()` (control source), `MeshLoop` (10 s evaluation ticker), `serveControlStream` (90 s read / 30 s write timeouts, malformed frames end the stream). `MESH_SNAPSHOT_KEY_FILE` config key; unreadable/malformed → unsigned + loud log, never a startup failure. |
| §4.2 node agent | `core/cmd/nexounel-node/mesh_agent.go`, `probe_results.go` | Heartbeat every 30 s + immediate on change (a test caught the missing immediate heartbeat — spec gap, fixed with a poke channel). Single- and multi-session wiring (30 s per-attempt open timeouts). Config-push apply: stage → validate with the existing checker (+ invocation overrides) → refuse NodeID/NodeKeyFile changes → atomic rename → ack `RestartRequired=true` (see D-6). Rotation apply: wrong-node/malformed refused, atomic 0600 write, ack `RestartRequired=true` (see D-6). Term announcements honored (step-down via `Coordinator.StepDown`). Applied-version file `<config>.mesh-version`. |
| §8.3 peer control | `core/internal/peercontrol/`, `core/cmd/nexounel-node/mesh_agent.go` | HMAC-SHA256 envelopes (canonical encoding, constant-time verify), monotonic per-peer sequences, 5-minute skew, replay window, per-IP + concurrency limiters, silence on any authentication failure (no hint which check failed). Config: `MESH_PEER_CONTROL_PORT` (0 = disabled; non-zero without a readable secret refuses the port at startup), `MESH_PEERS` (`id=host:port`, operator-configured, malformed skipped loudly). Agent probes on the heartbeat cadence, caches reachability, pokes on state flips. `HandleAnnounce` verifies snapshots against the coordinator key — without one, every announcement is refused (see D-9). |
| §3.2/§3.4 panel enrollment | `core/internal/panel/enroll_service.go`, `enrollment_api.go`, `core/internal/enroll/enroll.go` | Panel-owned `PendingStore` + issuance records (node config values supplied at issuance; the enrollment request carries only identity + token). Issue pushes the derived bootstrap key via the control socket and rolls back exactly on push failure. Revoke drops the key (best-effort). Read-driven sweep (`SweepFingerprints`) drops expired/used/burned joins and their keys. Loopback API `POST /enroll` (see below) runs the atomic transaction: verify → key/config issue → registry write → reload (best-effort, restart fallback) → consume. Failed registry writes do NOT burn the token; post-verification failures count toward burn (D-3). Idempotent re-issue returns the SAME key for a registry node with an inline key; `key_file` nodes are refused transiently (panel cannot re-issue a key it does not hold). Mesh secret generated once (0600) from `mesh_secret_file`, issued to every node, never a data-plane key. |
| §3.4 loopback API wiring | `core/cmd/nexounel-panel/main.go`, `core/internal/panel/config.go` | Panel config key `enrollment_addr` (empty = disabled; non-empty must be loopback, validated at config load and again before bind). Bind failure is fatal (fail fast, like the main listener). The handler refuses non-loopback remotes. Pairing: the server's `ENROLLMENT_ISSUER_URL` must point at `http://127.0.0.1:<port>/enroll` on the same host. |
| §4.4 panel mesh UI | `core/internal/panel/service.go`, `server.go`, `templates.go`, `mesh_handlers.go` | Dashboard sections fed ONLY through the service layer + control socket: mesh card (term, version, chief, snapshot-signing state, member table with state/capacity/weight/loss/leg/streams/ports/config version/control-stream/heartbeat age/last ack) and join-token card (pending list + issue/revoke forms). Same session-cookie auth + CSRF; unavailable socket renders an explicit note, never an empty mesh. Issued tokens shown once, like generated keys. Routes: `POST /mesh/issue`, `POST /mesh/revoke` (both under the secret web path, `requireAuth` + form CSRF). |
| §4.4 agent JSON API | `core/internal/panel/api.go`, `docs/PANEL-AGENT-API.md` | `GET /api/mesh` (mesh view + pending joins), `POST /api/mesh` (`issue` / `revoke`, header CSRF, token shown once), `mesh` + `pending_joins` fields in `GET /api/status`. Same auth/JSON error semantics as the existing API. |

## Spec/code discrepancies found (continued from Milestone 1, D-1–D-4)

- **D-5 (bootstrap-key push model, §3.4).** The spec has the
  enrollment handler verify "with the panel's store". Implemented
  instead: the panel pushes derived bootstrap keys to the server
  over the control socket at issuance and removes them at
  consume/revoke/sweep. Behaviorally equivalent (the server
  trial-decrypts against exactly the outstanding joins); the store
  stays panel-owned, and the handler needs no store access. The
  server enforces key expiry independently, so a missed panel-side
  removal is cleanup-only.
- **D-6 (config-push / rotation live-apply subsets, §§4.3/8.2).**
  Pushes are staged, validated, installed, and acked with
  `RestartRequired=true`; the §4.3 session-layer restart (apply
  live what is possible, restart only the session layer) and the
  §8.2 live re-registration under a rotated key are future work.
  Rotation orders over control streams have no panel trigger yet:
  the server can deliver frames to open streams, but no control
  socket command or UI issues them. The milestone does not claim
  live apply.
- **D-7 (`EnsureChief` term, §6).** A chief change at equal term is
  refused by the term rule, so `EnsureChief` issues a NEW term (T1
  for a zero term, otherwise the next normal term, version reset
  to 1) rather than an equal-term chief change. A test caught the
  first implementation missing this.
- **D-8 (heartbeat capacity semantics, §4.2).** The heartbeat
  reports the RAW probe ceiling (per-resolver download MTUs summed
  over classes), NOT loss-discounted: the mother discounts once via
  `NodeWeight`; discounting on both sides would double-count.
  `Loss` is the MTU-weighted mean loss. `LegRTTMs` is 0
  (unmeasured, neutral) until peer probes measure legs; `LegOK`
  means session-ready (a heartbeating node is reachable through
  the tunnel by construction).
- **D-9 (snapshot signing / verification key, §6).** Tables are
  unsigned by default (`MESH_SNAPSHOT_KEY_FILE` unset), and the
  snapshot verification key is NOT issued at enrollment: the
  enrollment response carries no snapshot key, so nodes hold no
  verification key in this milestone, degraded derivation stays
  disabled everywhere, and all peer snapshot announcements are
  refused. Issuing the verification key (at enrollment or over the
  control stream) is future work; the mother-side signing path is
  built and tested.
- **D-10 (peer reachability scope, §5).** Reachability reports
  cover only the `peer-control` leg kind; `MESH_PEERS` is
  operator-configured, not mother-distributed; hairpin is
  deferred; the Xray sidecar is not built. The reachability matrix
  (§12) is unmeasured.
- **D-11 (enrollment config source + sweep cadence, §§3.2/3.4).**
  The spec does not say where the issued node config's
  domain/ports/range come from; the operator supplies them at
  token issuance (the wizard's fields, reused), recorded
  panel-side per fingerprint. The pending-join sweep runs on
  mesh/enroll reads, not on a ticker: expiry is enforced lazily
  by the store and server-side regardless, so read-driven sweep is
  cleanup and no background goroutine is owed a lifecycle.
- **D-12 (probe-pass fast start, carried from the stall fix).** The
  F1a fast start was wired only into the single-session path; the
  probe pass is the fix in this milestone (see Step 1).
- **Implementation choice, not a discrepancy (§3.4):** the
  loopback enrollment API is loopback HTTP (`POST /enroll`), one
  of the two transports the spec explicitly allows ("Unix socket
  or loopback TCP"). Loopback binding is its only authentication
  boundary, enforced at config validation, at bind, and per
  request (remote-address check).

## Gates (this milestone)

- `go vet ./...` clean; `gofmt` clean for all touched files (the
  wider tree is not gofmt-clean upstream; untouched files were
  left alone).
- `CGO_ENABLED=0 go build ./...` clean (all three binaries).
- No `go.mod` change: no new dependencies.
- Full `go test ./...`, 3 runs: the failure-name set is EXACTLY
  the 9 pre-existing sandbox-UDP failures from the `main@394591a`
  baseline (durations stripped, identical across runs, no new
  failures, no flakes in these runs):
  `TestAsyncWriterUsesIPv6Socket`,
  `TestEncryptedSessionHandshakeAfterReset`,
  `TestExchangeUDPQueryWithConnDrainsStaleResponsesBeforeSending`,
  `TestExchangeUDPQueryWithConnFailsAfterTooManyMismatches`,
  `TestExchangeUDPQueryWithConnReturnsMatchingResponseAfterMismatches`,
  `TestIPv6TunnelSocketCarriesDNSDatagram`,
  `TestProbeExchangeSkipsForgedNXDOMAIN`,
  `TestQueryOneUpstreamRetriesTruncatedUDPOverTCP`,
  `TestReusePortSocketsShareReplyAddress`.
- Secrets/hardcoding: grep-verified on the diff — test fixtures
  use reserved `*.example.com`/`example.invalid` domains,
  documentation-range and loopback IPs, and synthetic keys only;
  no real domains, IPs, ports, or names; no credential values.
- Every new behavior is covered by tests: probe-pass cache
  semantics, bootstrap trial-decryption, reserved-target
  dispatch, enrollment relay, control framing/coordinator
  surgery/server exchange/agent exchange, peer-control
  auth/replay/limits, mesh views, token issue/revoke/sweep,
  the atomic enrollment transaction (success, idempotent
  re-issue, key-file refusal, registry-failure retry, reload
  fallback, refusals, malformed envelopes, loopback-only
  enforcement), the `HTTPIssuer` round trip to the panel API,
  and the UI/API mesh flows (auth, CSRF, shown-once tokens).

## What stays unproven until a field test

Everything in spec §12, unchanged, plus the Milestone 2
additions: node-to-node reachability matrix (no second node
exists in this environment), VLESS reverse leg, aggregate
scaling vs resolver rate limits (the 1.6× criterion), control
stream overhead and election timing under real latency,
bootstrap enrollment through real resolvers, mother hairpin
(not required), Xray sidecar under load, two-level weight
stability. In addition: the control socket's `list-mesh` and
bootstrap-key commands have been proven only against a loopback
test server in this sandbox; the panel enrollment API has never
run against the live mother process; chief election, degraded
takeover, peer control ports between real nodes, config-push /
rotation behavior on a live node, and enrollment end-to-end
through real resolvers are all unproven. The resolver-rollback
decision (pending with Mahan since 2026-11-02) and the panel
live-stats restart timing are still his calls, unchanged by
this milestone. Dict compression on real traffic, target-box
heap, provisioning e2e, and live mirror probing remain unproven
as before.

## Operator notes (enrollment wiring)

1. Panel config: set `enrollment_addr = "127.0.0.1:18082"` (any
   loopback port; empty disables the API). Restart the panel.
2. Server config: set
   `ENROLLMENT_ISSUER_URL = "http://127.0.0.1:18082/enroll"`
   (the same port). Restart the server.
3. Optional: `MESH_SNAPSHOT_KEY_FILE` (64 hex chars, 0600) on the
   server enables signed tables; nodes still cannot derive a
   degraded chief until the verification key is distributed
   (D-9).
4. Issue a token from the dashboard (Mesh → Join tokens) with the
   node's connect address, listen port, and forward range. The
   token is shown once. On the node, run enroll mode with the
   token (`--enroll`, `--join-token` / `--join-token-file` / stdin).
   On success the node restarts itself as a normal node.
5. The mesh secret file (`mesh_secret_file`, default
   `/opt/nexounel/mesh-control-secret.key`) is created by the
   panel on first enrollment (0600). A present-but-short file
   fails enrollment loudly rather than enrolling nodes with a
   weak secret. The same secret is issued to every node; it is
   never a data-plane key.
