# Nexounel Phase 3 — Milestone 1 (local code + tests only)

Status: implemented locally on top of `665cc8b`; NOT pushed, NOT
deployed. Reviewed by TARS before any push or deployment.

Scope (per `phase3-spec-draft.md` §§0–14): the control-plane
libraries and the server-side seams. No transport integration yet:
no control streams (§4.2), no peer control ports (§8.3), no
enroll-mode in the node binary, no bootstrap-session interception
in the DNS session path, no Xray sidecar (§7 — coordinator-first,
per D3 and open question 1), no panel HTTP wiring, no installer
changes. Those are the next milestone; the seams below are built
for them.

## What was built

| Spec section | Code | Notes |
|---|---|---|
| §6 terms, snapshots, succession | `core/internal/mesh/` | Term comparison (normal always beats degraded; zero term loses to all), HMAC-signed snapshots, deterministic `RankSuccessor` (tenure → capacity → ID), `Coordinator` state machine (heartbeat aggregation, suspect/down, mother election, degraded derivation, step-down, forced re-election rate limit, weight publication). |
| §3 manual join | `core/internal/enroll/` | Single-use join tokens (256-bit), SHA-256 fingerprints, HKDF-SHA256 bootstrap session keys (golden vector cross-checked against an independent implementation), pending-join store (verify/consume/burn/revoke/sweep), versioned enrollment request/response framing, bootstrap session-target restriction (fail-closed). |
| §5 chooser | `core/internal/multisession/node_chooser.go` | `NodeWeight` (capacity × loss discount × 50 ms RTT discount; zero on collapse/unreachable/excluded), `ChooseNode` reusing `Choose`, warm-up ramp, two-probe republication hysteresis (10% band, sustained). |
| §4.1 control socket | `core/internal/control/` | NDJSON protocol v1 over a root-only (0600) Unix socket: `ping`, `reload-registry`, `add-node`, `remove-node`, `rotate-key`, `list-sessions`. `RegistryHandler` keeps the last-loaded node list; the panel writes the file first, then commands the socket. |
| §4.1 server seam | `core/internal/udpserver/` | Codec set moved behind an atomic pointer: `ReloadNodeCodecs` swaps under traffic, in-flight sessions keep their codecs, preferred-codec index resets. `SessionSummaries` for `list-sessions`. |
| §4.1 wiring | `cmd/nexounel-server`, `CONTROL_SOCKET_PATH` | Socket starts only in node-registry mode (fatal otherwise); empty path = disabled (Phase 2 restart flow unchanged). Template key added to `core/configs/nexounel-server.toml`. |

## Spec/code discrepancies found

- **D-1 (spec contradicts itself, §3.2 vs §3.4).** §3.2 says the
  panel stores "only a hash of the token", but §3.4 requires the
  bootstrap session key to be derived from the token — impossible
  from a hash alone. Resolution: the pending-join store holds the
  DERIVED bootstrap key (HKDF output) alongside the hash. The raw
  token is never stored or logged; the derived key is
  single-purpose, deleted on burn/expiry, and useless after the
  token dies. The spec's security intent (no recoverable token)
  holds; its letter ("hash only") cannot hold with token-bound
  encryption. Documented in `enroll.go`'s package comment.
- **D-2 (spec §5.2 vs existing code).** §5.2 requires a 10% move
  sustained over two probes before republication; the existing
  single-session rule (`ShouldAdoptOperatingPoint`) is 12.5% on
  one probe. The existing rule is intentionally unchanged; the
  spec's rule is implemented separately as
  `SustainedMoveTracker`. Both coexist, documented at the
  constant.
- **D-3 (spec §3.4 "five failures burn the token").** The spec
  does not define which event counts as a failure. Implemented
  as: failures of an enrollment attempt AFTER successful token
  verification (`RecordFailure`); lookups of unknown/expired
  tokens are unattributable and do not count. The handler must
  call `RecordFailure` on post-verification failure and `Consume`
  only after the registry write succeeds.
- **D-4 (pre-existing, not introduced here).** The shipped
  server template comment says relative registry paths resolve
  against the config file's directory; in code only
  `ENCRYPTION_KEY_FILE` is resolved that way —
  `NODE_REGISTRY_FILE` is used as-is (working-directory
  relative). Deployment runs with `WorkingDirectory` equal to
  the config directory, so this is latent, not live. Left
  untouched; flagged for a future cleanup.
- **Wire placement of reserved targets deferred.** The
  enrollment/control target identifiers (`enroll`, `control`)
  and the bootstrap capability label are defined with their
  restriction predicates, but their placement in SESSION_INIT /
  STREAM_SYN wire fields is NOT implemented — that touches the
  session-establishment path and belongs to the transport
  milestone with the loopback enrollment handler.

## What stays unproven until a field test

Everything in spec §12, unchanged: node-to-node reachability
matrix (no second node exists in this environment), VLESS reverse
leg, aggregate scaling vs resolver rate limits, control-stream
overhead and election timing under real latency, bootstrap
enrollment through real resolvers, mother hairpin (not required),
Xray sidecar under load, two-level weight stability. In addition:
the control socket has been proven only against a loopback test
server in this sandbox (registry reload + rotation + session
listing); it has never run against the live mother process, and
the panel-side client wiring (token issuance UI, control-socket
calls, restart fallback messaging) is not built yet.

## Gates (this milestone)

- `go vet ./...` clean; `gofmt` clean for all touched files
  (the wider tree is not gofmt-clean upstream; untouched files
  were left alone).
- New/affected packages green: `mesh`, `enroll`, `control`,
  `multisession`, `config`, `panel`, `security`, `udpserver`
  (new tests only; see below).
- Full `go test ./...`: only the 9 pre-existing sandbox-UDP
  failures in `internal/client` + `internal/udpserver`
  (loopback UDP blocked in the sandbox; identical names to the
  pre-change baseline run). No new failures.
- No secrets/hardcoding: grep-verified — test fixtures use
  reserved `*.example.com` domains and synthetic keys only; no
  real domains, IPs, ports, or names anywhere in the diff.
- No shell files touched; no push; no server actions; no binary
  runs against live infrastructure (loopback/lab tests only).
