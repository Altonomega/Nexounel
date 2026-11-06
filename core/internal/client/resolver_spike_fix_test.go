// Regression tests for the resolver spike fix (follow-up to 49198a1):
// probationary rejoin (rate-capped trickle, seeded bad), escalating disable
// cooldowns for repeat offenders, earlier pruning at extreme loss, and the
// timeout-window fix (three consecutive successes to clear). See the 17:20
// spike: a rejoined resolver seeded with a fake 20% loss looked like the
// best score in a degraded pool, took >=30 sends in <=2 s, and re-pruned
// in 1-15 s — the rejoin stampede.
package client

import (
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/config"
)

// Proposal (3): a rejoined resolver is seeded as BAD (80% loss), not good,
// so it starts at the back of the selection queue.
func TestProbationarySeedIsBad(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	b.SetConnections([]*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	})

	b.SeedProbationaryStats("a")

	snap := b.snapshot.Load()
	if snap == nil {
		t.Fatal("expected a balancer snapshot")
	}
	// Seeded 100 sent / 20 acked = 80% loss (score 800), not the old
	// 10/8 (fake 20% loss, score 200).
	if score := b.lossScore(snap, 0); score != 800 {
		t.Fatalf("probationary seed loss score: got=%d want=800", score)
	}
	if !b.IsProbationary("a") {
		t.Fatal("expected rejoined resolver to be probationary")
	}
	if b.IsProbationary("b") {
		t.Fatal("expected untouched resolver not to be probationary")
	}
	if got := b.probationaryCount.Load(); got != 1 {
		t.Fatalf("probationary count: got=%d want=1", got)
	}
}

// Proposal (2): a probationary resolver is NEVER picked by the scored
// selection (best pick or duplicate slots), even when its score would
// otherwise win — here it is the best score in a degraded pool (800 vs
// 850) and must still be excluded.
func TestProbationaryResolverExcludedFromSelection(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	b.SetConnections([]*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
		{Key: "c", IsValid: true},
		{Key: "d", IsValid: true},
	})
	b.SeedProbationaryStats("a")
	// b/c/d are lossy (85% loss, score 850) — worse than a's seeded 800,
	// so without the probation filter "a" would be picked first.
	for _, key := range []string{"b", "c", "d"} {
		for i := 0; i < 100; i++ {
			b.ReportSend(key)
		}
		for i := 0; i < 15; i++ {
			b.ReportSuccess(key, time.Millisecond)
		}
	}

	got := b.GetUniqueConnections(3)
	if len(got) != 3 {
		t.Fatalf("expected 3 connections, got %d", len(got))
	}
	for _, conn := range got {
		if conn.Key == "a" {
			t.Fatal("probationary resolver must never be selected by scored selection")
		}
	}
	best, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected a best connection")
	}
	if best.Key == "a" {
		t.Fatal("probationary resolver must never be the best pick")
	}
	// ... and the same for the excluding variant (preferred/failover path).
	bestEx, ok := b.GetBestConnectionExcluding("b")
	if !ok {
		t.Fatal("expected a best connection excluding b")
	}
	if bestEx.Key == "a" {
		t.Fatal("probationary resolver must never be the preferred/failover pick")
	}
}

// Proposal (2): the trickle picker returns a probationary resolver at most
// once per probationMinPickInterval (~2 q/s), so it can prove itself
// without being hammered.
func TestProbationaryTrickleRateCap(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	b.SetConnections([]*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	})
	b.SeedProbationaryStats("a")

	trickle, ok := b.ProbationaryTricklePick()
	if !ok || trickle.Key != "a" {
		t.Fatalf("expected first trickle pick to be a, got ok=%v key=%q", ok, trickle.Key)
	}
	// An immediate second pick must be rate-capped.
	if trickle, ok := b.ProbationaryTricklePick(); ok {
		t.Fatalf("second trickle pick within the interval must be rate-capped, got %q", trickle.Key)
	}
	// After the interval elapses it is due again.
	stats := b.statsForKey("a")
	stats.mu.Lock()
	stats.probationLastPick = time.Now().Add(-probationMinPickInterval - time.Second)
	stats.mu.Unlock()
	trickle, ok = b.ProbationaryTricklePick()
	if !ok || trickle.Key != "a" {
		t.Fatalf("expected trickle pick after the interval, got ok=%v key=%q", ok, trickle.Key)
	}
}

// Proposal (2): the trickle picker returns nothing when no resolver is
// probationary (fast path, no scan).
func TestProbationaryTricklePickEmptyWhenNoneProbationary(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	b.SetConnections([]*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	})
	if _, ok := b.ProbationaryTricklePick(); ok {
		t.Fatal("expected no trickle pick when nothing is probationary")
	}
}

// Proposal (2): a probationary resolver graduates early once it sustains
// enough sends at low loss.
func TestProbationaryGraduationOnSustainedLowLoss(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	b.SetConnections([]*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	})
	b.SeedProbationaryStats("a")
	if !b.IsProbationary("a") {
		t.Fatal("expected rejoined resolver to be probationary")
	}

	// 50 sends at 10% loss (45 acks) — the graduation bar is 50 sends at
	// under 20% loss.
	for i := 0; i < 50; i++ {
		b.ReportSend("a")
	}
	for i := 0; i < 45; i++ {
		b.ReportSuccess("a", time.Millisecond)
	}
	if b.IsProbationary("a") {
		t.Fatal("expected graduation after 50 sends at <20% loss")
	}
	if got := b.probationaryCount.Load(); got != 0 {
		t.Fatalf("probationary count after graduation: got=%d want=0", got)
	}
	// After graduation its real loss (10%) is the score, not the 80% seed.
	snap := b.snapshot.Load()
	if score := b.lossScore(snap, 0); score != 100 {
		t.Fatalf("graduated resolver loss score: got=%d want=100", score)
	}
}

// Proposal (2): a probationary resolver that stays lossy does NOT graduate
// early — it keeps its trickle cap until the window expires.
func TestProbationaryNoGraduationWhileLossy(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	b.SetConnections([]*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	})
	b.SeedProbationaryStats("a")

	// 50 sends at 90% loss (5 acks) — far above the 20% graduation bar.
	for i := 0; i < 50; i++ {
		b.ReportSend("a")
	}
	for i := 0; i < 5; i++ {
		b.ReportSuccess("a", time.Millisecond)
	}
	if !b.IsProbationary("a") {
		t.Fatal("expected a lossy probationary resolver NOT to graduate early")
	}
}

// Proposal (2): probation expires on the wall-clock window even without
// enough sends, and the count is cleaned up lazily on the next send.
func TestProbationaryGraduationOnTimeout(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	b.SetConnections([]*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	})
	b.SeedProbationaryStats("a")

	stats := b.statsForKey("a")
	stats.mu.Lock()
	stats.probationUntil = time.Now().Add(-time.Second)
	stats.mu.Unlock()
	if b.IsProbationary("a") {
		t.Fatal("expected probation to expire after the window")
	}
	// The count is cleaned up lazily on the next send.
	b.ReportSend("a")
	if got := b.probationaryCount.Load(); got != 0 {
		t.Fatalf("probationary count after lazy expiry cleanup: got=%d want=0", got)
	}
}

// Proposal (1): the disable cooldown escalates for repeat offenders —
// 30 s, then 2 min, then 10 min — instead of the old fixed ~5 s that let
// a rate-limited resolver flap on an ~8 s cycle.
func TestEscalatingDisableCooldown(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 10.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
		RecheckServerIntervalSeconds:    1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	base := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return base }

	disableAndRejoin := func() time.Duration {
		if !c.disableResolverConnection("a", "sustained loss") {
			t.Fatal("expected disable to succeed")
		}
		c.resolverHealthMu.RLock()
		nextAt := c.resolverRecheck["a"].NextAt
		c.resolverHealthMu.RUnlock()
		// Simulate the rejoin (recheck succeeded): mark valid again and
		// clear the disabled tracking, as reactivation would.
		if !c.balancer.SetConnectionValidity("a", true) {
			t.Fatal("expected rejoin to succeed")
		}
		c.resolverHealthMu.Lock()
		delete(c.runtimeDisabled, "a")
		c.resolverHealthMu.Unlock()
		return nextAt.Sub(base)
	}

	if got := disableAndRejoin(); got != resolverOffenseCooldownFirst {
		t.Fatalf("first-prune cooldown: got=%v want=%v", got, resolverOffenseCooldownFirst)
	}
	if got := disableAndRejoin(); got != resolverOffenseCooldownSecond {
		t.Fatalf("second-prune cooldown: got=%v want=%v", got, resolverOffenseCooldownSecond)
	}
	if got := disableAndRejoin(); got != resolverOffenseCooldownRepeat {
		t.Fatalf("third-prune cooldown: got=%v want=%v", got, resolverOffenseCooldownRepeat)
	}
	// A fourth prune stays at the repeat tier.
	if got := disableAndRejoin(); got != resolverOffenseCooldownRepeat {
		t.Fatalf("fourth-prune cooldown: got=%v want=%v", got, resolverOffenseCooldownRepeat)
	}

	c.resolverHealthMu.RLock()
	record := c.resolverOffenseHistory["a"]
	c.resolverHealthMu.RUnlock()
	if record == nil || record.DisableCount != 4 {
		t.Fatalf("offense count: got=%v want=4", record)
	}
}

// Proposal (1): the offense count resets after an hour without an offense,
// so a resolver that was bad once long ago is not punished forever.
func TestOffenseCountResetsAfterQuietHour(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 10.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
		RecheckServerIntervalSeconds:    1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	base := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	now := base
	c.nowFn = func() time.Time { return now }

	if !c.disableResolverConnection("a", "sustained loss") {
		t.Fatal("expected first disable to succeed")
	}
	// More than an hour later the resolver is disabled again: the old
	// offense has expired, so this is a fresh first offense (30 s).
	now = base.Add(61 * time.Minute)
	if !c.balancer.SetConnectionValidity("a", true) {
		t.Fatal("expected rejoin to succeed")
	}
	c.resolverHealthMu.Lock()
	delete(c.runtimeDisabled, "a")
	c.resolverHealthMu.Unlock()
	if !c.disableResolverConnection("a", "sustained loss") {
		t.Fatal("expected second disable to succeed")
	}
	c.resolverHealthMu.RLock()
	nextAt := c.resolverRecheck["a"].NextAt
	record := c.resolverOffenseHistory["a"]
	c.resolverHealthMu.RUnlock()
	if got := nextAt.Sub(now); got != resolverOffenseCooldownFirst {
		t.Fatalf("cooldown after a quiet hour: got=%v want=%v", got, resolverOffenseCooldownFirst)
	}
	if record == nil || record.DisableCount != 1 {
		t.Fatalf("offense count after a quiet hour: got=%v want=1", record)
	}
}

// Proposal (1): the auto-disable cap holds at most 5% of the pool
// disabled at once, so a bad sweep cannot disable the whole fleet.
func TestAutoDisableCapLimitsConcurrentDisables(t *testing.T) {
	keys := make([]string, 0, 21)
	for i := 0; i < 21; i++ {
		keys = append(keys, string(rune('a'+i)))
	}
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 10.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, keys...)
	c.initResolverRecheckMeta()

	// Five resolvers are at 100% loss (20 sends, 0 acks) — all would be
	// pruned without the cap. Pool is 21, so the cap is max(3, 21*5/100)
	// = max(3, 1) = 3. (Only five are lossy so the "all active resolvers"
	// transport-recovery path does not fire.)
	for _, key := range keys[:5] {
		for i := 0; i < 20; i++ {
			c.balancer.ReportSend(key)
		}
	}
	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.runResolverAutoDisable(now)

	disabled := 0
	for _, key := range keys {
		if c.isRuntimeDisabledResolver(key) {
			disabled++
		}
	}
	if disabled != 3 {
		t.Fatalf("disabled count under the cap: got=%d want=3", disabled)
	}
}

// Proposal (4): total loss (100%, zero acks) is pruned on far fewer
// observations than the sustained-loss threshold.
func TestExtremeLossPrunesOnFewObservations(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 10.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	// "a": 100% loss on only 10 sends — below the 20-observation
	// sustained-loss bar, but the extreme-loss bar (10) is met.
	for i := 0; i < 10; i++ {
		c.balancer.ReportSend("a")
	}
	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if conn.IsValid {
		t.Fatal("expected 100%-loss resolver to be pruned on 10 observations")
	}
	if !c.isRuntimeDisabledResolver("a") {
		t.Fatal("expected pruned resolver to be tracked for runtime recheck")
	}
}

// Proposal (4): the extreme-loss bar still needs its minimum observations.
func TestExtremeLossDoesNotPruneBelowThreshold(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 10.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	// "a": 100% loss but only 9 sends — below the extreme-loss bar (10).
	for i := 0; i < 9; i++ {
		c.balancer.ReportSend("a")
	}
	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if !conn.IsValid {
		t.Fatal("resolver must not be pruned below the extreme-loss observation bar")
	}
}

// Proposal (2): the probationary trickle flows through the control-packet
// path (selectUniqueRuntimeConnections) — the only path that picks a
// probationary resolver — and is rate-capped there.
func TestSelectUniqueRuntimeConnectionsUsesProbationaryTrickle(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverBalancingStrategy: BalancingLeastLoss,
	}, "a", "b")
	c.balancer.SeedProbationaryStats("a")

	// First control pick carries the trickle: "a" is due, so it is the
	// target even though scored selection would never pick it.
	got, err := c.selectUniqueRuntimeConnections(1)
	if err != nil {
		t.Fatalf("expected a control connection, got error %v", err)
	}
	if len(got) != 1 || got[0].Key != "a" {
		t.Fatalf("expected trickle pick [a], got %v", keysOf(got))
	}
	// An immediate second pick is rate-capped: the trickle is spent, so
	// the normal pick ("b") is returned.
	got, err = c.selectUniqueRuntimeConnections(1)
	if err != nil {
		t.Fatalf("expected a control connection, got error %v", err)
	}
	if len(got) != 1 || got[0].Key != "b" {
		t.Fatalf("expected rate-capped pick [b], got %v", keysOf(got))
	}
}

func keysOf(conns []Connection) []string {
	out := make([]string, len(conns))
	for i, conn := range conns {
		out[i] = conn.Key
	}
	return out
}

// Proposal (2): a probationary resolver is never pinned as a stream's
// preferred resolver, and a pinned preferred that becomes probationary is
// treated as invalid (forcing a re-pin to a healthy resolver).
func TestPreferredConnectionSkipsProbationary(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverBalancingStrategy: BalancingLeastLoss,
	}, "a", "b", "c")
	c.balancer.SeedProbationaryStats("a")
	// "b" and "c" are healthy so there is a real best pick.
	for _, key := range []string{"b", "c"} {
		for i := 0; i < 10; i++ {
			c.balancer.ReportSend(key)
			c.balancer.ReportSuccess(key, time.Millisecond)
		}
	}

	selected, ok := c.selectAlternateStreamConnection("")
	if !ok {
		t.Fatal("expected an alternate connection")
	}
	if selected.Key == "a" {
		t.Fatal("probationary resolver must never be selected as preferred")
	}

	// A stream pinned to the probationary resolver is invalid and must
	// re-pin to a healthy one.
	stream := testStream(7)
	stream.PreferredServerKey = "a"
	if _, ok := c.getValidStreamPreferredConnection(stream); ok {
		t.Fatal("probationary pinned preferred must be treated as invalid")
	}
	pinned, ok := c.ensureStreamPreferredConnection(stream)
	if !ok {
		t.Fatal("expected a re-pinned preferred connection")
	}
	if pinned.Key == "a" {
		t.Fatal("re-pin must not choose the probationary resolver")
	}
	if stream.PreferredServerKey == "a" {
		t.Fatal("stream must not stay pinned to the probationary resolver")
	}
}

// Proposal (8): abnormal stream-close reasons are the ones that mean the
// stream died, not a clean close.
func TestAbnormalStreamCloseReason(t *testing.T) {
	clean := []string{
		"close handshake completed",
		"client local disconnect completed",
		"RST acknowledged",
		"close acknowledged",
	}
	for _, reason := range clean {
		if isAbnormalStreamCloseReason(reason) {
			t.Fatalf("expected clean close reason %q to be non-abnormal", reason)
		}
	}
	abnormal := []string{
		"Max retransmissions exceeded",
		"Local App Write Error: broken pipe",
		"Local connection missing for writer",
		"Inbound data received after local writer closed",
		"timeout",
	}
	for _, reason := range abnormal {
		if !isAbnormalStreamCloseReason(reason) {
			t.Fatalf("expected abnormal close reason %q to be abnormal", reason)
		}
	}
	if isAbnormalStreamCloseReason("") {
		t.Fatal("expected an empty reason to be non-abnormal")
	}
}
