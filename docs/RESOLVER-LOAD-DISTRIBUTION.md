# Resolver load distribution, pruning, and ARQ — design and verification

## Incident (2026-11-06)

During a sustained user test on port 10101 (VLESS Reality over the DNS
tunnel), the tunnel session stayed alive but DNS transport loss climbed
**0% → 95% → 97.5% → 100%**, and usable resolvers dropped **874 → 868**.
The VLESS session then timed out. A node restart reset the loss to 0%,
but the usable count after restart was **730** (down from ~874), so the
fleet had shrunk and the loss would climb again under sustained load.

Root cause: the client concentrates queries on a small group of
high-MTU / lowest-loss resolvers, hammering them until they rate-limit,
then moves to the next group and suffocates them too. Three mechanisms
combined to produce this:

1. **Selection concentrates load.** The live node uses the default
   strategy `BalancingLeastLoss` (3). `GetBestConnection` picks the single
   lowest-loss resolver (winner-take-all); `GetUniqueConnections` picks the
   lowest-loss set. Among equally-healthy resolvers there was no
   least-loaded tie-break, so the same resolvers were picked repeatedly.
   The MTU-weighted strategy has the same shape
   (`weight = MTU × (1-loss)`, floor 1).
2. **The pacer cooldown was 200 ms.** `pacerMaxInterval = 200ms` is far
   too short for a rate-limited public resolver to recover, so a throttled
   resolver was rotated straight back in.
3. **Auto-disable only fired on 100% timeout.** `runResolverAutoDisable`
   required a mature timeout-only window, so a resolver that still
   answered while dropping most queries (the rate-limited state) was
   never pruned.
4. **The startup cache union defeated pruning.** `BootstrapFromLogs`
   unioned 30 days of cache entries with the configured list, so a
   deliberate fleet prune (to a 1000-resolver subset) was silently undone
   and the node re-probed ~3680 resolvers instead of 1000.
5. **ARQ wasted queries on duplication.** Every repair was multiplied by
   duplication (RESEND ×3 up; ACK/NACK frames ×7), the largest single
   query sink, because the ARQ experiment was flag-off by default.

## Design

Spread load across **all** valid resolvers, give every resolver recovery
time, prune resolvers that are actually losing queries, and stop wasting
queries on duplication. Every change is behind a safe default; the old
behaviour is restored by flipping the relevant flag off.

### 1. Fair-share selection (balancer)

- `selectLowestScore` (LeastLoss / LowestLatency) now sorts by
  **(loss score, recent sends)**: among equally-healthy resolvers the
  least-loaded wins. After a resolver is used its `sent` count rises, so
  the next pick rotates to a different resolver — round-robin-like
  spreading among the healthy pool, with loss still the dominant key.
- `bestScoredConnection` / `bestScoredConnectionExcluding` (single pick)
  use the same (score, sent) preference.
- `weightedByMTUConnection` (MTUWeighted) now uses
  `loadDiscountedWeight`: `weight = MTU-goodput / (1 + sent/100)`.
  A resolver with 100 recent sends is halved, 500 sends is cut to a
  sixth. At even load the discount is the same for everyone, so MTU
  still dominates; only concentration is penalised. Weight floor stays 1.
- The load signal is the balancer's existing `sent` counter (half-life
  decayed at 1000), so no new per-resolver state is introduced.
- The per-resolver query rate limiter (`queryRateLimiter`) is NOT enabled
  by default: turning it on triggers `finalizeClientConfig` side effects
  (duplication forced to 1, adaptive duplication off, racing/MTU
  parallelism to 1) that change the speed preset's behaviour. The
  selection-level fair-share achieves the spreading goal without those
  side effects; the hard cap remains an operator knob
  (`QUERY_RATE_LIMIT_PER_RESOLVER_PER_SECOND`).

### 2. Real cooldown / recovery (pacer)

- `pacerMaxInterval` raised **200 ms → 8 s**. Throttle is still
  multiplicative (×2), recovery still halves the interval, so a maxed
  resolver clears in ~10 successes (a handful, not hundreds) and is
  removed from active rotation during cooldown via the existing
  `orderByPacing` (paced resolvers move to the back). Rejoin is
  automatic: once the interval decays, the resolver is eligible again.
- The pacer recovery test bound was raised 10 → 12 successes to give
  margin for the larger cap (8 s needs 10 halvings to fall below the
  8 ms base).

### 3. Loss-based pruning (resolver health)

- `runResolverAutoDisable` now checks **two** criteria over every
  currently-valid resolver (not only ones with timeout events):
  - **Criterion 1 (existing):** 100% timeout over a mature window
    (`AutoDisableTimeoutWindowSeconds`, ≥ `AutoDisableMinObservations`).
  - **Criterion 2 (new):** sustained loss ≥ **80%** (`autoDisableLossPerMilleThreshold = 800`)
    over ≥ **20** observations (`autoDisableLossMinObservations = 20`).
    This catches resolvers that still answer but drop most queries —
    the rate-limited state. Loss is read from the balancer's send/ack
    counters (`resolverLossPerMille`).
- Pruning reuses the existing disable + cooldown + recheck + rejoin
  path (`disableResolverConnection` / `reactivateResolverConnection`),
  so a pruned resolver returns automatically after 1–2 successful
  rechecks. The `cause` field on the disable candidate records which
  criterion fired ("100% timeout window" / "sustained loss").
- The three-resolver safety floor and the all-valid-disabled transport
  recovery are unchanged.

### 4. ARQ on by default

- `ARQExperimentEnabled` is now **true** in both
  `defaultClientConfig()` and `defaultServerConfig()`. This enables the
  prototype mechanisms from `docs/ARQ-PROTOTYPE.md`: server NACK gap 64
  (raised from 0 when unset), RESEND duplication 1, ACK/NACK duplication
  1, retransmit budget 64 (oldest-first, data RTO only). Setting
  `ARQ_EXPERIMENT_ENABLED=false` restores the historical behaviour
  exactly (the off-identical proof in the ARQ doc still holds).

### 5. Startup cache scoping (core surgery)

- `BootstrapFromLogs` previously **unioned** the cache (30 days of logs)
  with the configured list. A deliberate fleet prune was silently
  undone: configuring a 1000-resolver subset still probed ~3680
  resolvers (the subset plus every cached resolver from the old fleet).
- Now the cache is **scoped to the configured list** via
  `scopeCacheEntriesToConfigured`: when the operator explicitly
  configures a list, only cache entries for resolvers IN that list are
  used (the cache accelerates, never expands). Configured resolvers with
  no cache entry are still included and fully scanned (the hybrid path),
  so nothing configured is dropped. When the configured list is empty
  the cache is the only fleet source, so the union is kept there. When
  no cache entry matches the configured fleet, the plain `Bootstrap`
  (full probe) runs instead.
- `BootstrapWithMeasuredMTUs` (the multi-session probe-pass path) does
  not union and needed no change: it only pre-fills MTUs for connections
  already in the configured list.

## What did NOT change

- Startup probe, session / capacity-class structure, and compression are
  untouched.
- No server-side code changed except the ARQ default in
  `defaultServerConfig()` (one line).
- No live server was touched, restarted, or deployed to. All work is in
  the sandbox clone, uncommitted.

## Files changed

| File | Change |
|---|---|
| `core/internal/client/balancer.go` | `sentByIndex`, `loadDiscountedWeight`; (score, sent) ordering in `selectLowestScore`, `bestScoredConnection`, `bestScoredConnectionExcluding`; load-discounted weight in `weightedByMTUConnection` |
| `core/internal/client/resolver_pacer.go` | `pacerMaxInterval` 200 ms → 8 s |
| `core/internal/client/resolver_health.go` | Loss-based pruning (criterion 2), `resolverLossPerMille`, `cause` on disable candidates, check over all valid resolvers |
| `core/internal/client/client.go` | `scopeCacheEntriesToConfigured`; `BootstrapFromLogs` scopes the cache and falls back to full probe on no match |
| `core/internal/config/client.go` | `ARQExperimentEnabled: true` in `defaultClientConfig()` |
| `core/internal/config/server.go` | `ARQExperimentEnabled: true` in `defaultServerConfig()` |
| `core/internal/client/resolver_fairshare_test.go` (new) | Fair-share, load-discount, pacer-cooldown, loss-prune, few-samples tests |
| `core/internal/client/bootstrap_cache_test.go` | Scoping tests (prune respected, no-match fallback, helper unit test) |
| `core/internal/client/resolver_pacer_recovery_test.go` | Recovery bound 10 → 12 successes |
| `core/internal/config/arq_experiment_test.go` | ARQ default-on assertions (flag on; explicit off stays off) |

## Verification

- `go vet ./...` — **clean** (exit 0).
- `go test ./...` — all packages pass **except the 9 pre-existing
  sandbox-UDP failures**, verified identical on the clean tree
  (`git stash` comparison): `internal/client` 7
  (TestProbeExchangeSkipsForgedNXDOMAIN, TestIPv6TunnelSocketCarriesDNSDatagram,
  TestAsyncWriterUsesIPv6Socket, TestEncryptedSessionHandshakeAfterReset,
  TestExchangeUDPQueryWithConn×3) and `internal/udpserver` 2
  (TestQueryOneUpstreamRetriesTruncatedUDPOverTCP,
  TestReusePortSocketsShareReplyAddress). The sandbox blocks UDP; these
  fail without any of these changes. **Zero new failures.**
- New regression tests (all passing):
  - `TestFairShareLeastLossPrefersLeastLoaded` — least-loaded order
    among equally-healthy resolvers; lossy resolver excluded.
  - `TestLoadDiscountedWeightReducesHotResolver` — hot 1000-MTU resolver
    weighs 166 vs cold 500-MTU resolver's 500.
  - `TestPacerCooldownLastsSeconds` — cap ≥ 2 s and pinned at the cap.
  - `TestResolverHealthAutoDisablesHighLossConnection` — 90% loss pruned,
    5% loss kept.
  - `TestResolverHealthDoesNotPruneOnFewLossSamples` — 5 samples, no prune.
  - `TestBootstrapFromLogsScopesCacheToConfiguredList` — cache-only
    resolver excluded; configured list intact; MTU pre-fill kept.
  - `TestScopeCacheEntriesToConfigured` — scoping incl. port mismatch.
  - `TestBootstrapFromLogsNoCacheMatchFallsBack` — full probe on no match.
- `gofmt` — all files touched by this change are clean (the repo has
  pre-existing gofmt drift in 18 unrelated files; untouched).

## Not verified (needs a live field test, not done here)

- The actual per-resolver query rate and loss curve under sustained
  load on the live node (requires the deployed node + a sustained
  bench; the sandbox cannot reproduce resolver rate-limiting).
- Whether the 8 s pacer ceiling and the 80%/20-observation prune
  threshold are the optimal values in production — they are safe
  defaults; tune from live metrics if the loss curve shows otherwise.
- The ARQ on-by-default goodput-per-query improvement (the live A/B
  from the earlier plan is now subsumed by the default-on change;
  measure goodput-per-query after deploy instead).
