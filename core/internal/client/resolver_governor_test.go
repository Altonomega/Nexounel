// Regression tests for the offered-rate governor (proposal 5, the missing
// piece of the spike fix) and the probationary-rejoin bug it exposed:
// the 80%-loss seed itself met the pruning criterion, so a re-activated
// resolver was re-disabled 0–1 s later, before the trickle ever ran.
// Proof's field test (2026-11-06): spike recurred at ~3,000 q/s offered,
// 151 disables / 112 re-activations, resolvers flapping on the seed.
package client

import (
	"context"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/config"
)

// The governor caps total offered q/s: a GCRA limiter at 100 q/s must space
// queries 10 ms apart, so booking 5 slots at one instant returns delays
// 0, 10, 20, 30, 40 ms — deterministic, no real sleeping.
func TestGovernorCapsOfferedRate(t *testing.T) {
	limiter := newQueryRateLimiter(100, 0, 0, 1, 0)
	if limiter == nil {
		t.Fatal("expected a limiter for a 100 q/s global cap")
	}
	if got := limiter.GlobalRate(); got != 100 {
		t.Fatalf("governor cap: got=%v want=100 q/s", got)
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	wantDelays := []time.Duration{0, 10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond}
	for i, want := range wantDelays {
		if got := limiter.schedule(now, "1.1.1.1", "example.com", true); got != want {
			t.Fatalf("slot %d delay: got=%v want=%v", i, got, want)
		}
	}
	// Every booked slot after the first waited on the global scope, so the
	// governor throttled 4 of the 5.
	if got := limiter.GlobalThrottled(); got != 4 {
		t.Fatalf("governor throttled count: got=%d want=4", got)
	}
}

// The governor actually paces in real time: 6 waits at 200 q/s (5 ms gap)
// take at least 20 ms (5 gaps) and the throttled counter grows.
func TestGovernorPacesInRealTime(t *testing.T) {
	limiter := newQueryRateLimiter(200, 0, 0, 1, 0)
	if limiter == nil {
		t.Fatal("expected a limiter for a 200 q/s global cap")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	for i := 0; i < 6; i++ {
		if !limiter.wait(ctx, "1.1.1.1", "example.com") {
			t.Fatal("governor wait ended early (context done)")
		}
	}
	elapsed := time.Since(start)
	if elapsed < 20*time.Millisecond {
		t.Fatalf("governor did not pace: 6 waits at 200 q/s took %v, want >=20ms", elapsed)
	}
	if got := limiter.GlobalThrottled(); got == 0 {
		t.Fatal("expected the governor to throttle at least one wait")
	}
}

// The effective global cap is the governor by default, and a stricter
// legacy QUERY_RATE_LIMIT_PER_SECOND still wins when set.
func TestEffectiveGlobalQueryRate(t *testing.T) {
	if got := effectiveGlobalQueryRate(config.ClientConfig{GlobalOfferedQPSMax: 2000}); got != 2000 {
		t.Fatalf("governor-only cap: got=%v want=2000", got)
	}
	if got := effectiveGlobalQueryRate(config.ClientConfig{GlobalOfferedQPSMax: 2000, QueryRateLimitPerSecond: 500}); got != 500 {
		t.Fatalf("stricter legacy cap must win: got=%v want=500", got)
	}
	if got := effectiveGlobalQueryRate(config.ClientConfig{GlobalOfferedQPSMax: 2000, QueryRateLimitPerSecond: 5000}); got != 2000 {
		t.Fatalf("governor must cap a looser legacy value: got=%v want=2000", got)
	}
}

// A probationary resolver is NOT auto-disabled on its seed counters.
// This is the field-test bug: the seed (100 sent / 20 acked = 80% loss)
// itself meets the pruning criterion (≥80% loss over ≥20 observations),
// so the resolver was re-disabled 0–1 s after reactivation, before the
// trickle ever ran. The pruner must judge the probation window (no sends
// yet → no evidence), not the seed.
func TestProbationaryResolverNotAutoDisabledOnSeed(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 90.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()
	c.balancer.SeedProbationaryStats("a")

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if !conn.IsValid {
		t.Fatal("probationary resolver must NOT be pruned on its seed counters (no trickle evidence yet)")
	}
	if c.isRuntimeDisabledResolver("a") {
		t.Fatal("probationary resolver must not be tracked as disabled on its seed")
	}
}

// A probationary resolver CAN be pruned when the trickle actually shows
// sustained high loss — the fix must not make probation a free pass.
func TestProbationaryResolverPrunedOnLossyTrickle(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 90.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()
	c.balancer.SeedProbationaryStats("a")

	// The trickle ran 20 sends at 90% loss (2 acks) — real evidence, well
	// above the 20-observation / 80%-loss bar. It does not graduate (needs
	// 50 sends at <20% loss).
	for i := 0; i < 20; i++ {
		c.balancer.ReportSend("a")
	}
	for i := 0; i < 2; i++ {
		c.balancer.ReportSuccess("a", time.Millisecond)
	}
	if !c.balancer.IsProbationary("a") {
		t.Fatal("expected the lossy resolver to still be probationary (no early graduation)")
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if conn.IsValid {
		t.Fatal("probationary resolver with a lossy trickle (90% over 20 sends) must be pruned")
	}
	if !c.isRuntimeDisabledResolver("a") {
		t.Fatal("expected the pruned resolver to be tracked for runtime recheck")
	}
}

// A probationary resolver that graduates on a healthy trickle is NOT
// re-pruned afterwards: its adopted counters are the real window (10%
// loss), not the 80% seed.
func TestProbationaryGraduationThenNoImmediateReprune(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 90.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()
	c.balancer.SeedProbationaryStats("a")

	// 50 sends at 10% loss (45 acks) — the graduation bar.
	for i := 0; i < 50; i++ {
		c.balancer.ReportSend("a")
	}
	for i := 0; i < 45; i++ {
		c.balancer.ReportSuccess("a", time.Millisecond)
	}
	if c.balancer.IsProbationary("a") {
		t.Fatal("expected graduation after 50 sends at <20% loss")
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if !conn.IsValid {
		t.Fatal("graduated resolver must NOT be re-pruned on the seed it already outgrew")
	}
}

// A time-expired probation adopts the trickle window, so a resolver that
// ran a healthy trickle (but not enough sends to graduate early) is not
// re-pruned on the stale seed when the window expires.
func TestProbationaryTimeExpiryAdoptsWindow(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 90.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()
	c.balancer.SeedProbationaryStats("a")

	// 30 sends at 10% loss (27 acks) — healthy, but below the 50-send
	// early-graduation bar, so it is still probationary.
	for i := 0; i < 30; i++ {
		c.balancer.ReportSend("a")
	}
	for i := 0; i < 27; i++ {
		c.balancer.ReportSuccess("a", time.Millisecond)
	}
	if !c.balancer.IsProbationary("a") {
		t.Fatal("expected the resolver to still be probationary below 50 sends")
	}

	// The window expires; the next send lazily graduates it, adopting the
	// healthy window (30/27) as the main counters.
	stats := c.balancer.statsForKey("a")
	stats.mu.Lock()
	stats.probationUntil = time.Now().Add(-time.Second)
	stats.mu.Unlock()
	c.balancer.ReportSend("a")
	if c.balancer.IsProbationary("a") {
		t.Fatal("expected probation to expire after the window")
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if !conn.IsValid {
		t.Fatal("time-expired resolver must NOT be re-pruned on the stale seed")
	}
}

// A probationary resolver whose trickle never ran (no sends at all) is not
// pruned when its window expires: with no evidence the adopted counters
// are 0/0, not the seed.
func TestProbationaryNoTrickleNoPruneOnExpiry(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 90.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()
	c.balancer.SeedProbationaryStats("a")

	stats := c.balancer.statsForKey("a")
	stats.mu.Lock()
	stats.probationUntil = time.Now().Add(-time.Second)
	stats.mu.Unlock()
	c.balancer.ReportSend("a")
	if c.balancer.IsProbationary("a") {
		t.Fatal("expected probation to expire after the window")
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if !conn.IsValid {
		t.Fatal("resolver with no trickle evidence must NOT be pruned on the seed")
	}
}
