# Scale hard blockers — startup probe, panel fleet view, cache-log retention

Fixes for the scale audit's hard blockers: a 100k-resolver fleet made every
node restart pay a full MTU probe over all resolvers, and made the panel
re-parse and re-ship the whole resolver fleet on every load. All changes
are local-only, pure Go, no new dependencies, no wire-format changes, and
no behavior change for small fleets unless noted.

## F1a — resolver-cache fast start wired into node startup

- `core/cmd/nexounel-node/main.go:bootstrapNodeClient` — when
  `STARTUP_MODE=logs` (the config default) and the log directory holds
  usable cache entries, the probe client and the single-session client
  start via `client.BootstrapFromLogs`; otherwise they use the plain
  `Bootstrap` (byte-for-byte current behavior). The scan-only path keeps
  the plain `Bootstrap`: its contract is a full scan.
- `core/internal/client/client.go:BootstrapFromLogs` — the resolver list
  is now the UNION of cached resolvers and configured resolvers (cached
  first, ranked order preserved), not a replacement. Replacing would
  silently drop configured resolvers with no cache entry; the hybrid
  scan exists to cover exactly those. A caller-pinned list
  (`overrides.Resolvers`) takes precedence over the file list.
- `core/internal/client/client.go:Run` — the preknown branch no longer
  requires `!logBasedMTUVerify`. With `LOG_BASED_MTU_VERIFY=false` the
  cached MTUs are trusted (prior behavior); with `true` (the default)
  they are verified — see below. The fallback to the full scan on error
  is unchanged.
- `core/internal/client/preknown_verify.go:verifyPreknownMTUs` — one
  probe per direction at the cached sizes (upload first, short-circuit;
  quiet, single attempt). Failures are reset and fully re-probed, never
  rejected outright. Dead failures are filtered by the F1b pre-filter
  before the re-probe. Verification runs at
  `max(MTUTestParallelism, 128)` workers: verification probes are single
  cheap queries, so the logs-mode parallelism (32) would needlessly
  serialize a 47k fleet.
- `core/internal/client/mtu.go:applyPreknownMTUsFromLog` — snapshots the
  preknown set before the hybrid scan (the hybrid scan marks fresh
  connections valid too), then verifies. `scanMTUIndices` is the
  extracted worker-pool core shared by the hybrid scan and the
  verify-failure re-probe.

Discrepancy from the audit's wording: the audit says "a single cheap
verification probe". Verification sends one probe PER DIRECTION (two
queries). Verifying only the upload would leave the session-limiting
download MTU unverified; two single probes are still ~20x cheaper than
the ~19-step binary searches they replace.

## F1b — liveness pre-filter before the binary search

- `core/internal/client/liveness_prefilter.go` — one minimal upload
  probe at the smallest testable size, retried once, at 512 workers.
  Dead resolvers never enter the binary-search pass. The probe reuses
  `sendUploadMTUProbe` verbatim (same query, same timeout).
- Hooked into `runAllMTUProbeWorkersWithLimit` (covers the full scan and
  FastConnect) and `scanConnectionsWithoutPreknownMTU` (the hybrid
  new-resolver scan). The skip set is computed fresh per scan call so
  transport fallback re-evaluates liveness on the new transport.
- Gated to fleets over 256 connections (`livenessPrefilterMinFleet`):
  smaller fleets run the exact current probe (no extra queries, no
  filtering). Cancellation passes the fleet through unfiltered; the
  full probe then applies the cancellation itself.

Honest limit: a resolver whose replies are lost on BOTH attempts is
filtered even though the full search (up to `MTUTestRetries` attempts
per candidate) might have accepted it. That corner needs sustained high
loss; healthy resolvers are unaffected. The live path (a resolver
answering) could not be exercised in the sandbox (UDP loopback is
blocked there); the dead path and the pool mechanics are tested.

## F1c — class clients reuse probe-pass measurements

- `core/internal/client/client.go:BootstrapWithMeasuredMTUs` — builds a
  client whose connections carry just-measured MTUs. Only valid entries
  with positive MTUs pre-fill; everything else is fully scanned by the
  hybrid path. `logBasedMTUVerify` is forced false: the measurements
  are seconds old and came from this process; verifying would re-probe
  and defeat the purpose.
- `core/cmd/nexounel-node/main.go:runMultiSession` — class clients are
  built with measurements capped at the class operating point
  (`min(member, operating)` per direction), reproducing what a clamped
  re-probe would find. The class overrides (`MaxUploadMTU` etc.) are
  kept: they still clamp any fallback full scan. Measured loss is the
  probe pass's collapsed loss (worse of the two directions) applied to
  both directions; it is advisory only and never changes selection.

Staleness note: a class member that died in the seconds between the
probe pass and its class start stays in the class pool with its
probe-pass MTU; the session's runtime resolver recheck evicts it if it
is truly dead. Previously the re-probe would have caught it at startup.

## F2 — panel fleet view: cap, cache, retention

- `core/internal/panel/status.go:LoadNodeResolverHealth` — the row list
  is capped at `MaxResolverHealthEntries` (100, top by download MTU);
  `TotalEntries` carries the full fleet size and the per-class
  aggregation still covers every entry. Results are cached on the
  identities (path, mtime, size) of the node config file and the newest
  log file, so repeat dashboard/API loads do not re-parse. Appends to
  the live log change its mtime/size and re-parse; same-mtime/same-size
  rewrites are not detected (the standard make-style limitation).
- `core/internal/panel/api.go:apiResolverFrom` — `total_resolvers` now
  reports the full fleet size via `EntryTotal()` (falls back to the row
  count for values built without the cap). The dashboard template shows
  the full count plus a "showing the top N" note when capped.
- `core/internal/client/resolver_cache_log.go:pruneResolverCacheLogs`
  — on opening a new session cache log, siblings beyond the newest 7
  are deleted, except files modified within the last 24 hours (so files
  concurrently starting sessions just created are never removed) and
  the just-opened file. Best-effort and silent; rotation never fails
  startup.

## F3 — operating-point floor deduplication (soft, with proof)

- `core/internal/client/mtu_cluster.go` — `selectMTUOperatingPoint` and
  `selectMTUOperatingPointPreferHigh` now iterate distinct
  (upload, download) floors (first-occurrence order preserved) while
  the inner pool scan still counts every connection. Cost drops from
  O(V^2) to O(D*V) where D is the number of distinct pairs (tiny for
  tiered fleets). Equivalence against verbatim copies of the naive
  loops is proved in `mtu_cluster_test.go` on crafted sets and 300
  seeded-random fleets (both functions, minPool 0/1/2/5/100).
- Honest limit: a fleet with all-distinct pairs stays quadratic
  (D == V). Dedup collapses the common tiered case, not the
  adversarial one.

## Not changed

- The domain-diverse-duplication path (`DUPLICATION_PREFER_DISTINCT_DOMAINS`)
  was not touched; it stays off by default.
- No wire-format change: cache entries, probe queries, panel JSON shapes
  (apart from `total_resolvers` now reporting the true total), and
  multisession clustering inputs are unchanged.
- No new TOML keys. All gates are constants or existing keys
  (`STARTUP_MODE`, `LOG_SCAN_MAX_DAYS`, `LOG_SCAN_MAX_RESOLVERS`,
  `LOG_BASED_MTU_VERIFY`).

## Unverifiable without a live 100k run

- Real probe wall-clock and heap on the 1-vCPU target at 99,544
  resolvers (verify pass, pre-filter, and class pass-through timings;
  connection-map and cache-parse memory).
- Dictionary/verify behavior against real resolvers under real loss
  (sandbox UDP loopback is blocked; all live-probe paths reuse the
  existing probe functions verbatim and are covered by the existing
  scan tests on a real network).
- Cache-file growth/rotation timing under the real multi-session
  startup (probe client + class sessions opening files concurrently).
