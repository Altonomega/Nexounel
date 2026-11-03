package multisession

import (
	"math"
)

// Node-level capacity weighting is the second distribution level
// (§5.1). When a user connection arrives at any mesh node, the entry
// node picks a destination node by weighted-random selection over the
// membership table. The pick is per connection — the whole stream goes
// to the picked node (no byte-striping) — and reuses exactly the
// weighted selection math of the class-level chooser (Choose), so both
// levels share one proven shape and one set of discount rules.

// NodeCapacity is one node's measured capacity as reported on its
// heartbeat: the minimum of its probe ceiling and its observed
// goodput, with the loss and leg-health observations that discount it.
type NodeCapacity struct {
	ID string
	// CapacityBps is measured capacity in bytes/second. Zero means
	// collapsed (resolver collapse, §8.4): the node takes no new
	// distributed streams but keeps serving its own direct users.
	CapacityBps float64
	// Loss is the measured loss fraction (0..1) on the node's own
	// tunnel sessions.
	Loss float64
	// LegRTTMs is the measured entry-to-node leg RTT in
	// milliseconds. Zero means unmeasured (neutral).
	LegRTTMs float64
	// LegOK reports whether any working leg (§5.3) reaches this
	// node as a distribution target. A node with no working leg
	// stays ACTIVE for its own direct users but is unreachable as
	// a target.
	LegOK bool
	// Excluded removes the node from new picks regardless of
	// capacity (SUSPECT/DOWN/REVOKED states, §5.5). Existing
	// streams are untouched: exclusion never migrates a stream.
	Excluded bool
}

// NodeWeight computes one node's share of new streams. Capacity
// dominates; loss discounts linearly and leg latency discounts
// hyperbolically against the same 50 ms reference as the class
// chooser, so both levels speak the same discount language.
// Collapsed, unreachable, or excluded nodes weigh zero and are never
// picked.
func NodeWeight(n NodeCapacity) float64 {
	if n.Excluded || !n.LegOK || n.CapacityBps <= 0 || math.IsNaN(n.CapacityBps) || math.IsInf(n.CapacityBps, 0) {
		return 0
	}
	loss := n.Loss
	if loss < 0 {
		loss = 0
	}
	if loss > 1 {
		loss = 1
	}
	latencyFactor := 1 + n.LegRTTMs/50
	if latencyFactor <= 0 {
		latencyFactor = 1
	}
	return n.CapacityBps * (1 - loss) / latencyFactor
}

// NodeWeights returns one weight per node, in input order.
func NodeWeights(nodes []NodeCapacity) []float64 {
	ws := make([]float64, len(nodes))
	for i, n := range nodes {
		ws[i] = NodeWeight(n)
	}
	return ws
}

// ChooseNode picks a node index by weighted random selection over
// node weights. r must be in [0, totalWeight); the caller draws it.
// It is Choose with node semantics: zero-weight nodes are never
// picked, and -1 means no node can carry the stream.
func ChooseNode(weights []float64, r float64) int {
	return Choose(weights, r)
}

// WarmUpFactor is the weight fraction a re-admitted node carries for
// its first probe cycle (§5.5): half its measured share, so
// re-admission ramps instead of stepping and cannot thundering-herd
// a just-recovered node.
const WarmUpFactor = 0.5

// ApplyWarmUp scales the weights of warming nodes by WarmUpFactor.
// warming maps node indexes (positions in weights) that are in their
// first cycle after re-admission. Non-warming weights pass through
// untouched. The caller recomputes shares from the returned weights,
// so warming one node implicitly raises the others' shares — that is
// the ramp working as intended.
func ApplyWarmUp(weights []float64, warming map[int]bool) []float64 {
	out := make([]float64, len(weights))
	copy(out, weights)
	for i := range out {
		if warming[i] {
			out[i] *= WarmUpFactor
		}
	}
	return out
}

// RepublishHysteresis is the §5.2 republication band: a class's
// operating point must move by more than this fraction in either MTU
// direction before the table is republished. 10% matches the spec;
// the single-session 12.5% rule (ShouldAdoptOperatingPoint) is a
// different, per-session rule and is intentionally left unchanged.
const RepublishHysteresis = 0.10

// moveTracker holds one node's pending republication state: the
// adopted operating point and whether one beyond-band observation is
// already armed.
type moveTracker struct {
	adoptedUp, adoptedDown int
	armed                  bool
}

// SustainedMoveTracker implements the §5.2 two-probe rule: a fresh
// operating point is adopted only when it moves beyond the
// hysteresis band sustained over two consecutive probes. A single
// beyond-band probe arms the tracker; a second consecutive
// beyond-band probe republishes and adopts; an in-band probe
// disarms. This is per node (keyed by the caller's node ID) and
// single-threaded by contract.
type SustainedMoveTracker struct {
	states map[string]*moveTracker
}

// NewSustainedMoveTracker builds an empty tracker.
func NewSustainedMoveTracker() *SustainedMoveTracker {
	return &SustainedMoveTracker{states: make(map[string]*moveTracker)}
}

// Observe records one probe's operating point for nodeID and reports
// whether the table must be republished (adopted point moved).
// The first observation for a node adopts immediately with no
// republication (there is no table yet to republish).
func (t *SustainedMoveTracker) Observe(nodeID string, uploadMTU, downloadMTU int) bool {
	if t == nil {
		return false
	}
	if t.states == nil {
		t.states = make(map[string]*moveTracker)
	}
	st, ok := t.states[nodeID]
	if !ok {
		t.states[nodeID] = &moveTracker{adoptedUp: uploadMTU, adoptedDown: downloadMTU}
		return false
	}
	if beyondBand(st.adoptedUp, uploadMTU) || beyondBand(st.adoptedDown, downloadMTU) {
		if st.armed {
			st.adoptedUp, st.adoptedDown = uploadMTU, downloadMTU
			st.armed = false
			return true
		}
		st.armed = true
		return false
	}
	st.armed = false
	return false
}

// beyondBand reports whether next moved more than the hysteresis
// fraction away from adopted, in either direction. A zero adopted
// point treats any positive measurement as beyond band (recovery
// from collapse republishes as soon as it is sustained).
func beyondBand(adopted, next int) bool {
	if adopted <= 0 {
		return next > 0
	}
	if next <= 0 {
		return true
	}
	return math.Abs(float64(next-adopted)) > RepublishHysteresis*float64(adopted)
}
