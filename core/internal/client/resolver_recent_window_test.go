package client

import (
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/config"
)

// The recent-window loss tracker is the fast pruning signal for established
// resolvers. The half-life counters dilute a new loss burst: a resolver
// with a long healthy history needs 50–300 s for its half-life loss to
// reach the 80% prune bar. The recent window (last ~32 sends) shows a
// sustained loss burst within seconds, so the resolver is pruned quickly.
// It uses the same >=80% loss / >=20-observation bar as the sustained-loss
// pruner, so a single bad sample cannot prune a healthy resolver.

// A resolver with a healthy half-life history that goes bad is pruned via
// the recent window, even though its half-life loss is still far below the
// 80% bar — that is the whole point of the tracker.
func TestRecentWindowPrunesEstablishedResolverWithHealthyHalfLifeHistory(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 90.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	// Healthy history: 100 sends, 95 acks (5% loss). The half-life loss
	// is 5% — far below the 80% prune bar.
	for i := 0; i < 100; i++ {
		c.balancer.ReportSend("a")
	}
	for i := 0; i < 95; i++ {
		c.balancer.ReportSuccess("a", time.Millisecond)
	}
	if loss, _, ok := c.resolverLossPerMille("a"); !ok || loss >= 800 {
		t.Fatalf("expected healthy half-life loss (<80%%), got loss=%d%% ok=%v", loss/10, ok)
	}

	// The resolver goes bad: 32 sends, 0 acks. The half-life loss after
	// this is (132-95)/132 = 28% — still below the 80% bar, so the
	// sustained-loss criterion (criterion 2) must NOT fire. But the recent
	// window (last 32 sends, 0 acked) shows 100% loss, so criterion 3
	// must prune it.
	for i := 0; i < 32; i++ {
		c.balancer.ReportSend("a")
	}
	if loss, _, ok := c.resolverLossPerMille("a"); !ok || loss >= 800 {
		t.Fatalf("expected half-life loss still below 80%% (so only the recent window can prune), got loss=%d%% ok=%v", loss/10, ok)
	}
	if loss, sent, ok := c.balancer.RecentWindowLossPerMille("a", c.recentWindowSends()); !ok || sent < 20 || loss < 800 {
		t.Fatalf("expected recent-window loss >=80%% over >=20 sends, got loss=%d%% sent=%d ok=%v", loss/10, sent, ok)
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if conn.IsValid {
		t.Fatal("established resolver with a lossy recent window (100% over 32 sends) must be pruned, even though its half-life loss is only ~28%")
	}
	if !c.isRuntimeDisabledResolver("a") {
		t.Fatal("expected the pruned resolver to be tracked for runtime recheck")
	}
}

// A few bad samples must NOT prune a healthy resolver — the window needs
// >=20 observations at >=80% loss, so a brief burst is tolerated.
func TestRecentWindowDoesNotPruneOnFewBadSamples(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 90.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	// Healthy history: 100 sends, 95 acks (5% loss).
	for i := 0; i < 100; i++ {
		c.balancer.ReportSend("a")
	}
	for i := 0; i < 95; i++ {
		c.balancer.ReportSuccess("a", time.Millisecond)
	}

	// A brief burst: 5 sends, 0 acks. The recent window (last 32 sends)
	// is mostly healthy — ~27 of 32 acked, ~15% loss — far below 80%.
	for i := 0; i < 5; i++ {
		c.balancer.ReportSend("a")
	}
	if loss, _, ok := c.balancer.RecentWindowLossPerMille("a", c.recentWindowSends()); !ok || loss >= 800 {
		t.Fatalf("expected recent-window loss below 80%% after only 5 bad samples, got loss=%d%% ok=%v", loss/10, ok)
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if !conn.IsValid {
		t.Fatal("a healthy resolver must NOT be pruned on only 5 bad samples")
	}
	if c.isRuntimeDisabledResolver("a") {
		t.Fatal("a healthy resolver must not be tracked as disabled on only 5 bad samples")
	}
}

// Total loss over the last 10 sends prunes via the recent-window extreme
// fast path (criterion 3b), even though the sustained bar needs 20 sends.
func TestRecentWindowExtremeLossPrunesOnTenSends(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 90.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	// Healthy history: 100 sends, 95 acks (5% loss).
	for i := 0; i < 100; i++ {
		c.balancer.ReportSend("a")
	}
	for i := 0; i < 95; i++ {
		c.balancer.ReportSuccess("a", time.Millisecond)
	}

	// The resolver goes completely dead: 10 sends, 0 acks. The half-life
	// loss is (110-95)/110 = 13% — far below any bar. The recent window
	// over the last 10 sends shows 100% loss, so criterion 3b must prune.
	for i := 0; i < 10; i++ {
		c.balancer.ReportSend("a")
	}
	if loss, sent, ok := c.balancer.RecentWindowLossPerMille("a", autoDisableExtremeLossMinObservations); !ok || sent < autoDisableExtremeLossMinObservations || loss < 1000 {
		t.Fatalf("expected recent-window 100%% loss over >=10 sends, got loss=%d%% sent=%d ok=%v", loss/10, sent, ok)
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if conn.IsValid {
		t.Fatal("a resolver with 100% loss over the last 10 sends must be pruned via the recent-window extreme fast path")
	}
	if !c.isRuntimeDisabledResolver("a") {
		t.Fatal("expected the pruned resolver to be tracked for runtime recheck")
	}
}

// The recent window must NOT second-guess probation: a probationary
// resolver is judged on its trickle window, not the recent window. The
// RecentWindowLossPerMille accessor returns ok=false for probationary
// resolvers, and a probationary resolver with a healthy trickle graduates
// normally instead of being pruned.
func TestRecentWindowNotUsedForProbationaryResolver(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 90.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()
	c.balancer.SeedProbationaryStats("a")

	// The accessor must refuse probationary resolvers outright.
	if _, _, ok := c.balancer.RecentWindowLossPerMille("a", c.recentWindowSends()); ok {
		t.Fatal("RecentWindowLossPerMille must return ok=false for a probationary resolver")
	}

	// A healthy trickle (50 sends, 45 acks, 10% loss) graduates the
	// resolver. It must NOT be pruned — neither by the probation window
	// (10% loss, below the bar) nor by the recent window (gated off).
	for i := 0; i < 50; i++ {
		c.balancer.ReportSend("a")
	}
	for i := 0; i < 45; i++ {
		c.balancer.ReportSuccess("a", time.Millisecond)
	}
	if c.balancer.IsProbationary("a") {
		t.Fatal("expected the healthy trickle to graduate the resolver")
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if !conn.IsValid {
		t.Fatal("a probationary resolver that graduated on a healthy trickle must NOT be pruned")
	}
	if c.isRuntimeDisabledResolver("a") {
		t.Fatal("a graduated resolver must not be tracked as disabled")
	}
}

// The recent window rebuilds after the half-life halves the counters: the
// ring is cleared on halving (its snapshots are on the pre-halving scale),
// and the window is trusted again once >=20 fresh sends accumulate.
func TestRecentWindowRebuildsAfterHalfLife(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 90.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	// Drive the counters past the half-life threshold (1000) with a
	// healthy pattern, so the half-life fires and clears the ring.
	for i := 0; i < 1100; i++ {
		c.balancer.ReportSend("a")
	}
	for i := 0; i < 1050; i++ {
		c.balancer.ReportSuccess("a", time.Millisecond)
	}
	// The ring was cleared by the halving, so the window has no evidence
	// yet and must not be trusted.
	if _, _, ok := c.balancer.RecentWindowLossPerMille("a", c.recentWindowSends()); ok {
		t.Fatal("recent window must not be trusted right after the half-life cleared the ring")
	}

	// Fresh sends rebuild the window. After 32 healthy sends the window
	// shows ~0% loss and the resolver is fine.
	for i := 0; i < 32; i++ {
		c.balancer.ReportSend("a")
	}
	for i := 0; i < 32; i++ {
		c.balancer.ReportSuccess("a", time.Millisecond)
	}
	if loss, sent, ok := c.balancer.RecentWindowLossPerMille("a", c.recentWindowSends()); !ok || sent < 20 || loss >= 800 {
		t.Fatalf("expected a healthy rebuilt window (loss <80%%), got loss=%d%% sent=%d ok=%v", loss/10, sent, ok)
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if !conn.IsValid {
		t.Fatal("a healthy resolver must NOT be pruned after the window rebuilds")
	}
}
