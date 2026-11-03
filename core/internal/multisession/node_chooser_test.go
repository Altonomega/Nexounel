package multisession

import (
	"math"
	"testing"
)

func TestNodeWeight(t *testing.T) {
	base := NodeCapacity{ID: "n1", CapacityBps: 400000, LegOK: true}
	if got := NodeWeight(base); got != 400000 {
		t.Errorf("healthy node weight = %v, want 400000", got)
	}
	// Loss discounts linearly: 25% loss → 75% weight.
	lost := base
	lost.Loss = 0.25
	if got := NodeWeight(lost); got != 300000 {
		t.Errorf("25%% loss weight = %v, want 300000", got)
	}
	// Leg RTT discounts hyperbolically against 50 ms: 50 ms halves.
	slow := base
	slow.LegRTTMs = 50
	if got := NodeWeight(slow); got != 200000 {
		t.Errorf("50ms leg weight = %v, want 200000", got)
	}
	// Clamping: negative loss and >100% loss.
	neg := base
	neg.Loss = -0.5
	if got := NodeWeight(neg); got != 400000 {
		t.Errorf("negative loss must clamp to 0: weight = %v", got)
	}
	dead := base
	dead.Loss = 1.5
	if got := NodeWeight(dead); got != 0 {
		t.Errorf("loss > 1 must clamp to zero weight, got %v", got)
	}
	// Weight-to-zero on collapse / unreachable / excluded.
	for name, n := range map[string]NodeCapacity{
		"collapsed": {ID: "n", CapacityBps: 0, LegOK: true},
		"no-leg":    {ID: "n", CapacityBps: 400000, LegOK: false},
		"excluded":  {ID: "n", CapacityBps: 400000, LegOK: true, Excluded: true},
		"negative":  {ID: "n", CapacityBps: -5, LegOK: true},
		"nan":       {ID: "n", CapacityBps: math.NaN(), LegOK: true},
	} {
		if got := NodeWeight(n); got != 0 {
			t.Errorf("%s: weight = %v, want 0", name, got)
		}
	}
}

func TestChooseNodeCapacityProportional(t *testing.T) {
	nodes := []NodeCapacity{
		{ID: "big", CapacityBps: 300000, LegOK: true},
		{ID: "small", CapacityBps: 100000, LegOK: true},
		{ID: "dead", CapacityBps: 0, LegOK: true}, // never picked
	}
	ws := NodeWeights(nodes)
	if ws[2] != 0 {
		t.Fatalf("collapsed node weight = %v, want 0", ws[2])
	}
	// Deterministic draws over the weight line: [0,300k) → big, [300k,400k) → small.
	if got := ChooseNode(ws, 0); got != 0 {
		t.Errorf("r=0 → %d, want 0", got)
	}
	if got := ChooseNode(ws, 299999); got != 0 {
		t.Errorf("r=299999 → %d, want 0", got)
	}
	if got := ChooseNode(ws, 300000); got != 1 {
		t.Errorf("r=300000 → %d, want 1", got)
	}
	if got := ChooseNode(ws, 399999); got != 1 {
		t.Errorf("r=399999 → %d, want 1", got)
	}
	// Statistical check: shares follow capacity within tolerance.
	counts := [3]int{}
	const draws = 20000
	for i := 0; i < draws; i++ {
		// Deterministic pseudo-random draws in [0, total).
		r := math.Mod(float64(i)*7919.0, 400000)
		counts[ChooseNode(ws, r)]++
	}
	if counts[2] != 0 {
		t.Errorf("collapsed node picked %d times, want 0", counts[2])
	}
	share := float64(counts[0]) / draws
	if share < 0.70 || share > 0.80 {
		t.Errorf("big-node share = %.3f, want ~0.75", share)
	}
	// All weights zero → no node.
	if got := ChooseNode([]float64{0, 0}, 0); got != -1 {
		t.Errorf("all-zero weights → %d, want -1", got)
	}
}

func TestApplyWarmUp(t *testing.T) {
	ws := []float64{300000, 100000}
	warmed := ApplyWarmUp(ws, map[int]bool{1: true})
	if warmed[0] != 300000 || warmed[1] != 50000 {
		t.Errorf("warmed weights = %v, want [300000 50000]", warmed)
	}
	// Input untouched (no aliasing).
	if ws[1] != 100000 {
		t.Error("ApplyWarmUp must not mutate its input")
	}
	untouched := ApplyWarmUp(ws, nil)
	if untouched[0] != 300000 || untouched[1] != 100000 {
		t.Errorf("no warming map must pass weights through: %v", untouched)
	}
}

func TestSustainedMoveTracker(t *testing.T) {
	tr := NewSustainedMoveTracker()
	// First observation adopts with no republication.
	if tr.Observe("n1", 1000, 2000) {
		t.Error("first observation must not republish")
	}
	// In-band move (5%) never republishes, even twice.
	if tr.Observe("n1", 1050, 2000) || tr.Observe("n1", 1050, 2000) {
		t.Error("in-band moves must not republish")
	}
	// Single beyond-band spike arms but does not republish...
	if tr.Observe("n1", 1200, 2000) {
		t.Error("first beyond-band probe must only arm")
	}
	// ...and a revert disarms without republishing.
	if tr.Observe("n1", 1000, 2000) {
		t.Error("revert must disarm without republishing")
	}
	// Two consecutive beyond-band probes republish and adopt.
	if tr.Observe("n1", 1200, 2000) {
		t.Error("first beyond-band probe must only arm")
	}
	if !tr.Observe("n1", 1200, 2000) {
		t.Error("second consecutive beyond-band probe must republish")
	}
	// Adopted point is now 1200: a further 5% move is in-band.
	if tr.Observe("n1", 1250, 2000) {
		t.Error("post-adoption in-band move must not republish")
	}
	// Downward moves beyond band also count (capacity loss).
	if tr.Observe("n1", 1000, 2000) {
		t.Error("first downward beyond-band probe must only arm")
	}
	if !tr.Observe("n1", 1000, 2000) {
		t.Error("second consecutive downward probe must republish")
	}
	// Exactly 10% is NOT beyond band (strictly greater required).
	tr2 := NewSustainedMoveTracker()
	tr2.Observe("n2", 1000, 2000)
	if tr2.Observe("n2", 1100, 2000) || tr2.Observe("n2", 1100, 2000) {
		t.Error("exactly-10% move must not republish")
	}
	// Collapse (to zero) and recovery both need two probes.
	tr3 := NewSustainedMoveTracker()
	tr3.Observe("n3", 1000, 2000)
	if tr3.Observe("n3", 0, 0) {
		t.Error("first collapse probe must only arm")
	}
	if !tr3.Observe("n3", 0, 0) {
		t.Error("sustained collapse must republish (weight to zero)")
	}
	if tr3.Observe("n3", 1000, 2000) {
		t.Error("first recovery probe must only arm")
	}
	if !tr3.Observe("n3", 1000, 2000) {
		t.Error("sustained recovery must republish")
	}
	// Nodes are independent.
	tr4 := NewSustainedMoveTracker()
	tr4.Observe("a", 1000, 2000)
	tr4.Observe("b", 1000, 2000)
	tr4.Observe("a", 1200, 2000)
	if tr4.Observe("b", 1000, 2000) {
		t.Error("node b must not republish on node a's movement")
	}
	// Nil tracker is safe.
	var nilTr *SustainedMoveTracker
	if nilTr.Observe("x", 1, 1) {
		t.Error("nil tracker must not republish")
	}
}
