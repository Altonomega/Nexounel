// Regression tests for the intelligent resolver load-distribution fix:
// fair-share selection (least-loaded tie-break + load-discounted MTU weight),
// the seconds-scale pacer cooldown, and loss-based pruning of rate-limited
// resolvers. See the incident where loss climbed 0% -> 100% under sustained
// load because selection concentrated queries on a small group of resolvers.
package client

import (
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/config"
)

// Fair-share: among equally-healthy resolvers (same loss) the least-loaded
// (fewest recent sends) must be picked first, so the load spreads across the
// whole healthy pool instead of hammering the same "best" resolver.
func TestFairShareLeastLossPrefersLeastLoaded(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
		{Key: "c", IsValid: true},
		{Key: "d", IsValid: true},
	}
	b.SetConnections(connections)

	// All three of a/b/c stay lossless (sent == acked), but with very
	// different load: a has carried 100 sends, c 50, b 10. (A resolver needs
	// at least 5 sends for a real loss score; below that it is scored 500
	// as "unknown", so b gets 10 sends to be a proven-healthy resolver.)
	for i := 0; i < 100; i++ {
		b.ReportSend("a")
		b.ReportSuccess("a", time.Millisecond)
	}
	for i := 0; i < 10; i++ {
		b.ReportSend("b")
		b.ReportSuccess("b", time.Millisecond)
	}
	for i := 0; i < 50; i++ {
		b.ReportSend("c")
		b.ReportSuccess("c", time.Millisecond)
	}
	// "d" is lossy (50% loss), which provides the loss signal that makes
	// LeastLoss use the scored selection instead of round-robin, and which
	// must rank below every lossless resolver.
	for i := 0; i < 10; i++ {
		b.ReportSend("d")
	}
	for i := 0; i < 5; i++ {
		b.ReportSuccess("d", time.Millisecond)
	}

	got := b.GetUniqueConnections(3)
	if len(got) != 3 {
		t.Fatalf("expected 3 connections, got %d", len(got))
	}
	// Least-loaded first: b (10 sends), then c (50), then a (100). The lossy
	// resolver d must not be among the top 3.
	if got[0].Key != "b" || got[1].Key != "c" || got[2].Key != "a" {
		t.Fatalf("expected least-loaded order b,c,a, got %q,%q,%q", got[0].Key, got[1].Key, got[2].Key)
	}

	// The single-best pick must also be the least-loaded among equals.
	best, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected a best connection")
	}
	if best.Key != "b" {
		t.Fatalf("expected best connection to be least-loaded b, got %q", best.Key)
	}
}

// Fair-share: the MTU weight is discounted by recent send load, so a hot
// high-MTU resolver weighs less than a cold lower-MTU one.
func TestLoadDiscountedWeightReducesHotResolver(t *testing.T) {
	snap := &balancerSnapshot{
		connections: []Connection{
			{Key: "hot", DownloadMTUBytes: 1000},
			{Key: "cold", DownloadMTUBytes: 500},
		},
		valid:      []int{0, 1},
		indexByKey: map[string]int{"hot": 0, "cold": 1},
		stats: []*connectionStats{
			{sent: 500}, // hot: 500 recent sends
			{sent: 0},   // cold: no recent sends
		},
	}
	// hot: 1000 / (1 + 500/100) = 1000/6 = 166; cold: 500 (no discount).
	hot := loadDiscountedWeight(snap, 0)
	cold := loadDiscountedWeight(snap, 1)
	if hot != 166 {
		t.Fatalf("hot resolver weight: got=%d want=166", hot)
	}
	if cold != 500 {
		t.Fatalf("cold resolver weight: got=%d want=500", cold)
	}
	if hot >= cold {
		t.Fatalf("hot high-MTU resolver (%d) should weigh less than cold lower-MTU one (%d)", hot, cold)
	}
	// A resolver with no sends keeps its full MTU as weight.
	if w := loadDiscountedWeight(snap, 1); w != 500 {
		t.Fatalf("cold resolver should keep full weight 500, got %d", w)
	}
}

// The pacer ceiling must be seconds (not 200ms) so a rate-limited resolver
// actually gets recovery time before it is rotated back in.
func TestPacerCooldownLastsSeconds(t *testing.T) {
	if pacerMaxInterval < 2*time.Second {
		t.Fatalf("pacer ceiling too short to let a rate-limited resolver recover: %v", pacerMaxInterval)
	}
	p := newResolverPacer(true)
	now := time.Now()
	for i := 0; i < 20; i++ {
		p.throttle("r1", now)
	}
	if s := p.states["r1"]; s == nil || s.interval != pacerMaxInterval {
		t.Fatalf("expected interval pinned at cap %v, got %v", pacerMaxInterval, intervalOf(s))
	}
}

// Loss-based pruning: a resolver that still answers but drops most queries
// (sustained high loss) must be pruned, while a healthy resolver is kept.
func TestResolverHealthAutoDisablesHighLossConnection(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 10.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	// "a": 90% sustained loss (100 sends, 10 acks) — a rate-limited resolver
	// that still answers, so no timeout-only window ever forms.
	for i := 0; i < 100; i++ {
		c.balancer.ReportSend("a")
	}
	for i := 0; i < 10; i++ {
		c.balancer.ReportSuccess("a", time.Millisecond)
	}
	// "b": healthy (100 sends, 95 acks, 5% loss).
	for i := 0; i < 100; i++ {
		c.balancer.ReportSend("b")
	}
	for i := 0; i < 95; i++ {
		c.balancer.ReportSuccess("b", time.Millisecond)
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected disabled connection to still exist")
	}
	if conn.IsValid {
		t.Fatal("expected high-loss resolver to be pruned")
	}
	if c.balancer.ValidCount() != 3 {
		t.Fatalf("unexpected valid count after prune: got=%d want=3", c.balancer.ValidCount())
	}
	if !c.isRuntimeDisabledResolver("a") {
		t.Fatal("expected pruned resolver to be tracked for runtime recheck")
	}

	// The healthy resolver must survive the same sweep.
	healthy, ok := c.GetConnectionByKey("b")
	if !ok {
		t.Fatal("expected healthy connection to still exist")
	}
	if !healthy.IsValid {
		t.Fatal("healthy resolver must not be pruned")
	}
}

// Loss-based pruning must not fire on too few observations (a short loss
// burst is not sustained loss).
func TestResolverHealthDoesNotPruneOnFewLossSamples(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 10.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	// "a": 100% loss but only 5 sends — below the minimum observation count.
	for i := 0; i < 5; i++ {
		c.balancer.ReportSend("a")
	}

	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected connection to still exist")
	}
	if !conn.IsValid {
		t.Fatal("resolver must not be pruned on too few loss samples")
	}
}
