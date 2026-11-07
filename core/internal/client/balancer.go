// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the CottenDns client.
// This file (balancer.go) handles connection balancing strategies.
// ==============================================================================
package client

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	BalancingRoundRobinDefault = 0
	BalancingRandom            = 1
	BalancingRoundRobin        = 2
	BalancingLeastLoss         = 3
	BalancingLowestLatency     = 4
	// BalancingMTUWeighted selects active-pool resolvers with probability
	// proportional to their download MTU, so a resolver that can carry 4000-byte
	// downloads receives proportionally more traffic than one capped at 1000.
	BalancingMTUWeighted = 5
	BalancingHighestMTU  = 6
)

type Balancer struct {
	strategy   int
	familyMode string
	rrCounter  atomic.Uint64
	rngState   atomic.Uint64
	version    atomic.Uint64
	// probationaryCount is the number of resolvers currently in post-rejoin
	// probation. It is a fast-path guard for the trickle picker: when it is
	// zero no scan is needed. It is maintained under each resolver's own
	// stats lock (incremented on probation start, decremented on graduation),
	// so it stays consistent with the per-resolver probation state.
	probationaryCount atomic.Int64

	mu       sync.Mutex
	sources  []*Connection
	snapshot atomic.Pointer[balancerSnapshot]
}

type connectionStats struct {
	mu           sync.RWMutex
	sent         uint64
	acked        uint64
	rttMicrosSum uint64
	rttCount     uint64
	// Probation (post-rejoin) state. probationUntil is zero when the
	// resolver is not probationary. probationSent/probationAcked count
	// sends/acks since probation started (the clean post-rejoin loss
	// signal, free of the seed); probationLastPick is the last time this
	// resolver was picked while probationary (the rate-cap clock).
	probationUntil    time.Time
	probationSent     uint64
	probationAcked    uint64
	probationLastPick time.Time
	// Recent-window loss tracker. recentAckedRing is a ring of the acked
	// count recorded at each send (one entry per send), so the loss over
	// the last N sends is (N - (ackedNow - ackedNago)) / N. It is the
	// fast signal the half-life counters lack: an established resolver
	// with a long healthy history takes 50–300 s for its half-life loss
	// to reach the prune bar, but the recent window shows a sustained
	// loss burst within seconds. recentRingHead is the next slot to
	// write; recentRingCount is the number of valid entries (<= ring
	// size). The ring is cleared whenever the counters are reset or
	// halved, because its snapshots are on the pre-reset scale.
	recentAckedRing [recentWindowRingSize]uint64
	recentRingHead  int
	recentRingCount int
}

const connectionStatsHalfLifeThreshold = 1000

// Post-rejoin probation: a reactivated resolver is rate-capped and kept out
// of the preferred/duplicate slots until it proves itself, so a just-rejoined
// resolver cannot be stampeded the way the 17:20 spike showed (a rejoined
// resolver seeded with a fake 20% loss looked like the best score in a
// degraded pool and took >=30 sends in <=2 s, then re-pruned in 1-15 s).
const (
	// probationDuration is the maximum wall-clock probation after reactivation.
	// A resolver graduates earlier once it sustains enough sends at low loss;
	// after this long it graduates regardless (by then its seed has washed
	// out into real measurements, so its score is honest).
	probationDuration = 60 * time.Second
	// probationGraduationSends is the number of post-rejoin sends a
	// probationary resolver must sustain before graduating early.
	probationGraduationSends = 50
	// probationGraduationMaxLossPerMille is the maximum post-rejoin loss
	// (parts per 1000) for early graduation: <20% loss over the window.
	probationGraduationMaxLossPerMille = 200
	// probationMinPickInterval caps a probationary resolver to at most one
	// pick per interval (<=2 q/s), enforced by the trickle picker. This is
	// the rate cap that stops the rejoin stampede.
	probationMinPickInterval = 500 * time.Millisecond
	// probationSeedSent/probationSeedAcked seed a rejoined resolver as BAD
	// (80% loss) instead of good, so it starts at the BACK of the selection
	// queue, not the front. The old 10/8 seed (fake 20% loss) was the best
	// score in a degraded pool and caused the stampede.
	probationSeedSent  = 100
	probationSeedAcked = 20
)

// recentWindowRingSize is the number of send-time acked snapshots the
// recent-window tracker keeps per resolver. The window itself is
// configurable (RESOLVER_RECENT_WINDOW_SENDS, default 32) but never larger
// than the ring. A 64-entry ring is 512 bytes per resolver — ~0.5 MB for a
// 1,000-resolver pool.
const recentWindowRingSize = 64

// defaultRecentWindowSends is the recent-window size (sends) used when the
// client config carries no value (unfinalized test configs). It must match
// defaultRecentWindowSends in the config package.
const defaultRecentWindowSends = 32

type balancerSnapshot struct {
	version     uint64
	connections []Connection
	valid       []int
	indexByKey  map[string]int
	stats       []*connectionStats
}

func NewBalancer(strategy int) *Balancer {
	b := &Balancer{strategy: strategy, familyMode: "dual"}
	b.rngState.Store(seedRNG())
	return b
}

// SetFamilyMode changes the active address-family policy without discarding
// resolver statistics. In auto mode IPv4 is the primary carrier and IPv6 is a
// ready fallback; discovery and health checking remain outside the balancer and
// continue to probe both families.
func (b *Balancer) SetFamilyMode(mode string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if mode == "" {
		mode = "auto"
	}
	b.familyMode = mode
	snap := b.snapshot.Load()
	if snap == nil {
		return
	}
	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: snap.connections,
		valid:       rebuildValidIndicesWithFamily(snap.connections, b.familyMode),
		indexByKey:  snap.indexByKey,
		stats:       snap.stats,
	})
}

func (b *Balancer) SetConnections(connections []*Connection) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.sources = connections
	size := len(connections)
	indexByKey := make(map[string]int, size)
	stats := make([]*connectionStats, size)
	copied := make([]Connection, size)

	for idx, conn := range connections {
		if conn == nil {
			continue
		}
		copied[idx] = *conn
		indexByKey[conn.Key] = idx
		stats[idx] = &connectionStats{}
	}

	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: copied,
		valid:       rebuildValidIndicesWithFamily(copied, b.familyMode),
		indexByKey:  indexByKey,
		stats:       stats,
	})
}

func (b *Balancer) ValidCount() int {
	snap := b.snapshot.Load()
	if snap == nil {
		return 0
	}
	return len(snap.valid)
}

func (b *Balancer) GetConnectionByKey(key string) (Connection, bool) {
	snap := b.snapshot.Load()
	if snap == nil || key == "" {
		return Connection{}, false
	}

	idx, ok := snap.indexByKey[key]
	if !ok {
		return Connection{}, false
	}

	return derefConnection(snap.connections, idx)
}

func (b *Balancer) SetConnectionValidity(key string, valid bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	snap := b.snapshot.Load()
	if snap == nil {
		return false
	}

	idx, ok := snap.indexByKey[key]
	if !ok {
		return false
	}

	if idx < 0 || idx >= len(snap.connections) {
		return false
	}
	conn := snap.connections[idx]
	if conn.IsValid == valid {
		return ok
	}

	if idx < len(b.sources) && b.sources[idx] != nil {
		b.sources[idx].IsValid = valid
		conn = *b.sources[idx]
	} else {
		conn.IsValid = valid
	}

	connections := append([]Connection(nil), snap.connections...)
	connections[idx] = conn
	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: connections,
		valid:       rebuildValidIndicesWithFamily(connections, b.familyMode),
		indexByKey:  snap.indexByKey,
		stats:       snap.stats,
	})
	return true
}

func (b *Balancer) SetConnectionMTU(key string, uploadBytes int, uploadChars int, downloadBytes int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	snap := b.snapshot.Load()
	if snap == nil {
		return false
	}

	idx, ok := snap.indexByKey[key]
	if !ok || idx < 0 || idx >= len(snap.connections) {
		return false
	}

	conn := snap.connections[idx]
	conn.UploadMTUBytes = uploadBytes
	conn.UploadMTUChars = uploadChars
	conn.DownloadMTUBytes = downloadBytes

	if idx < len(b.sources) && b.sources[idx] != nil {
		b.sources[idx].UploadMTUBytes = uploadBytes
		b.sources[idx].UploadMTUChars = uploadChars
		b.sources[idx].DownloadMTUBytes = downloadBytes
		conn = *b.sources[idx]
	}

	connections := append([]Connection(nil), snap.connections...)
	connections[idx] = conn
	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: connections,
		valid:       rebuildValidIndicesWithFamily(connections, b.familyMode),
		indexByKey:  snap.indexByKey,
		stats:       snap.stats,
	})
	return true
}

func (b *Balancer) RefreshValidConnections() {
	b.mu.Lock()
	defer b.mu.Unlock()

	snap := b.snapshot.Load()
	if snap == nil {
		return
	}

	connections := make([]Connection, len(snap.connections))
	copy(connections, snap.connections)
	for idx, source := range b.sources {
		if source == nil || idx >= len(connections) {
			continue
		}
		connections[idx] = *source
	}

	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: connections,
		valid:       rebuildValidIndicesWithFamily(connections, b.familyMode),
		indexByKey:  snap.indexByKey,
		stats:       snap.stats,
	})
}

func (b *Balancer) SnapshotVersion() uint64 {
	snap := b.snapshot.Load()
	if snap == nil {
		return 0
	}
	return snap.version
}

func (b *Balancer) ReportSend(serverKey string) {
	if stats := b.statsForKey(serverKey); stats != nil {
		stats.mu.Lock()
		// Record the acked count at this send, for the recent-window loss
		// tracker (one ring entry per send). The snapshot is taken before
		// the send is counted, so it is the acked count just before this
		// send was made.
		stats.recentAckedRing[stats.recentRingHead] = stats.acked
		stats.recentRingHead = (stats.recentRingHead + 1) % recentWindowRingSize
		if stats.recentRingCount < recentWindowRingSize {
			stats.recentRingCount++
		}
		stats.sent++
		if !stats.probationUntil.IsZero() {
			stats.probationSent++
		}
		stats.applyHalfLifeLocked()
		graduated := stats.maybeGraduateProbationLocked(time.Now())
		stats.mu.Unlock()
		if graduated {
			b.probationaryCount.Add(-1)
		}
	}
}

func (b *Balancer) ReportSuccess(serverKey string, rtt time.Duration) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.mu.Lock()
	stats.acked++
	if !stats.probationUntil.IsZero() {
		stats.probationAcked++
	}
	if rtt > 0 {
		stats.rttMicrosSum += uint64(rtt / time.Microsecond)
		stats.rttCount++
	}
	stats.applyHalfLifeLocked()
	graduated := stats.maybeGraduateProbationLocked(time.Now())
	stats.mu.Unlock()
	if graduated {
		b.probationaryCount.Add(-1)
	}
}

func (b *Balancer) ResetServerStats(serverKey string) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.mu.Lock()
	wasProbationary := !stats.probationUntil.IsZero()
	stats.sent = 0
	stats.acked = 0
	stats.rttMicrosSum = 0
	stats.rttCount = 0
	stats.probationUntil = time.Time{}
	stats.probationSent = 0
	stats.probationAcked = 0
	stats.probationLastPick = time.Time{}
	stats.recentRingHead = 0
	stats.recentRingCount = 0
	stats.mu.Unlock()
	if wasProbationary {
		b.probationaryCount.Add(-1)
	}
}

// SeedProbationaryStats initialises a re-activated resolver as BAD and
// starts its post-rejoin probation. The seed is sent=100/acked=20 (80%
// loss), so the resolver starts at the BACK of the selection queue — the
// old 10/8 seed (fake 20% loss) was the best score in a degraded pool and
// caused the rejoin stampede. Probation rate-caps it (at most one pick per
// probationMinPickInterval, via the trickle picker) and keeps it out of the
// preferred/duplicate slots until it sustains probationGraduationSends at
// under probationGraduationMaxLossPerMille loss, or probationDuration
// elapses. Stats were zeroed when the resolver was disabled, so the seed
// is the only history it carries.
func (b *Balancer) SeedProbationaryStats(serverKey string) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.mu.Lock()
	wasProbationary := !stats.probationUntil.IsZero()
	stats.sent = probationSeedSent
	stats.acked = probationSeedAcked
	stats.rttMicrosSum = 0
	stats.rttCount = 0
	stats.probationUntil = time.Now().Add(probationDuration)
	stats.probationSent = 0
	stats.probationAcked = 0
	stats.probationLastPick = time.Time{}
	stats.recentRingHead = 0
	stats.recentRingCount = 0
	stats.mu.Unlock()
	if !wasProbationary {
		b.probationaryCount.Add(1)
	}
}

// SeedConservativeStats is kept as a thin alias for SeedProbationaryStats so
// existing callers keep working; new code should call SeedProbationaryStats.
func (b *Balancer) SeedConservativeStats(serverKey string) {
	b.SeedProbationaryStats(serverKey)
}

// IsProbationary reports whether the resolver is currently in post-rejoin
// probation (and the probation window has not yet expired). A resolver whose
// window expired counts as graduated even if its fields have not been
// cleared yet (they are cleared lazily on the next send/success/trickle).
func (b *Balancer) IsProbationary(serverKey string) bool {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return false
	}
	stats.mu.RLock()
	defer stats.mu.RUnlock()
	return !stats.probationUntil.IsZero() && time.Now().Before(stats.probationUntil)
}

// ProbationaryTricklePick returns a probationary resolver that is due for
// its rate-capped trickle pick (at most one pick per
// probationMinPickInterval), choosing the first due one in snapshot order.
// The rate cap is the mechanism that stops the rejoin stampede: a rejoined
// resolver can only be picked this way, at most ~2 q/s, and never as a
// preferred or duplicate target. When a resolver is returned its pick is
// recorded, so a second call within the interval will not return it again.
// Expired probations found during the scan are graduated (their counters
// cleared) so the fast-path count stays accurate. It returns false when no
// probationary resolver is due.
func (b *Balancer) ProbationaryTricklePick() (Connection, bool) {
	if b.probationaryCount.Load() <= 0 {
		return Connection{}, false
	}
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}
	now := time.Now()
	for _, idx := range snap.valid {
		stats := statsByIndex(snap, idx)
		if stats == nil {
			continue
		}
		stats.mu.Lock()
		if stats.probationUntil.IsZero() {
			stats.mu.Unlock()
			continue
		}
		// Lazily graduate expired probations so the fast-path count
		// converges even for resolvers that receive no further sends.
		// Time-expiry is not a proven graduation, so the counters (the
		// seed) are left alone and the resolver keeps ranking at the back.
		if !now.Before(stats.probationUntil) {
			if stats.graduateProbationLocked() {
				stats.mu.Unlock()
				b.probationaryCount.Add(-1)
			} else {
				stats.mu.Unlock()
			}
			continue
		}
		if !stats.probationLastPick.IsZero() && now.Sub(stats.probationLastPick) < probationMinPickInterval {
			stats.mu.Unlock()
			continue
		}
		stats.probationLastPick = now
		stats.mu.Unlock()
		return derefConnection(snap.connections, idx)
	}
	return Connection{}, false
}

// ProbationLossPerMille returns the post-rejoin loss (parts per 1000) over
// the probation window, and whether the resolver carries probation state.
// The probation window is the clean post-rejoin loss signal, free of the
// 80%-loss seed in the main counters. It is what the auto-disable pruner
// must judge a probationary resolver on: the seed itself meets the pruning
// criterion (80% loss over 100 sends), so judging the main counters would
// re-prune the resolver 0–1 s after reactivation, before the trickle ever
// ran. ok is false when the resolver has no probation state
// (probationUntil is zero). Note this deliberately ignores the window's
// expiry: a resolver whose window expired but has not yet been graduated
// (lazy graduation) still carries only the seed in its main counters, so
// it is still judged on the probation window until graduation adopts it.
func (b *Balancer) ProbationLossPerMille(serverKey string) (lossPerMille uint64, sent uint64, ok bool) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return 0, 0, false
	}
	stats.mu.RLock()
	defer stats.mu.RUnlock()
	if stats.probationUntil.IsZero() {
		return 0, 0, false
	}
	sent = stats.probationSent
	if sent == 0 {
		return 0, 0, true
	}
	if stats.probationAcked >= sent {
		return 0, sent, true
	}
	return (sent - stats.probationAcked) * 1000 / sent, sent, true
}

// probationLossPerMilleLocked reports the post-rejoin loss (parts per 1000)
// over the probation window. The caller must hold s.mu.
func (s *connectionStats) probationLossPerMilleLocked() (uint64, bool) {
	if s.probationSent == 0 {
		return 0, false
	}
	if s.probationAcked >= s.probationSent {
		return 0, true
	}
	return (s.probationSent - s.probationAcked) * 1000 / s.probationSent, true
}

// recentWindowLossLocked reports the loss rate (parts per 1000) over the
// last windowSends sends, from the ring of send-time acked counts. The
// caller must hold s.mu. ok is false when fewer than windowSends sends
// have been recorded (not enough evidence yet). The window is the fast
// signal the half-life counters lack: an established resolver with a long
// healthy history needs 50–300 s for its half-life loss to reach the
// prune bar, but a sustained loss burst shows up in the recent window
// within seconds. Acks for sends from before the window (in-flight
// completions) can only make the window look healthier, never worse, and
// a healthy resolver's in-flight count is a small fraction of a >=20-send
// window, so this cannot falsely prune a healthy resolver — a single bad
// sample, or a few, cannot push a >=20-send window to 80% loss.
func (s *connectionStats) recentWindowLossLocked(windowSends int) (lossPerMille uint64, sent uint64, ok bool) {
	if windowSends < 1 || s.recentRingCount < windowSends {
		return 0, 0, false
	}
	// The entry windowSends ago is at (head - windowSends). The acks that
	// arrived since that send are the current acked count minus the acked
	// count recorded then.
	idx := (s.recentRingHead - windowSends + recentWindowRingSize*2) % recentWindowRingSize
	ackedWago := s.recentAckedRing[idx]
	acksInWindow := s.acked - ackedWago
	if acksInWindow >= uint64(windowSends) {
		return 0, uint64(windowSends), true
	}
	return (uint64(windowSends) - acksInWindow) * 1000 / uint64(windowSends), uint64(windowSends), true
}

// RecentWindowLossPerMille returns the loss rate (parts per 1000) over the
// last windowSends sends for a resolver, and whether enough sends have
// been recorded to trust it. It is the fast pruning signal for established
// (non-probationary) resolvers: probationary resolvers are judged on their
// probation window instead (ProbationLossPerMille), so this deliberately
// returns ok=false for them — the caller must not use the recent window to
// second-guess probation. ok is also false when the resolver has no stats
// or fewer than windowSends sends recorded.
func (b *Balancer) RecentWindowLossPerMille(serverKey string, windowSends int) (lossPerMille uint64, sent uint64, ok bool) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return 0, 0, false
	}
	stats.mu.RLock()
	defer stats.mu.RUnlock()
	if !stats.probationUntil.IsZero() {
		return 0, 0, false
	}
	return stats.recentWindowLossLocked(windowSends)
}

// graduateProbationLocked clears probation state. The caller must hold s.mu
// and must have already decided the resolver graduates. The main counters
// are ALWAYS reset to the probation window — the resolver's score becomes
// the loss it actually proved, not the bad seed it started with. This holds
// for a time-expiry graduation too: leaving the seed would keep the main
// counters at 80% loss over 100 sends, and the next auto-disable sweep
// would re-prune the resolver on stale counters before it ever carried real
// traffic (the 0–1 s re-disable churn). A time-expired resolver that ran a
// lossy trickle still graduates with its real (lossy) window, so the
// pruner can act on that evidence if it meets the bar — the adoption does
// not hide a bad trickle, it only replaces the seed with what was measured.
// It returns true if the resolver was probationary.
func (s *connectionStats) graduateProbationLocked() bool {
	if s.probationUntil.IsZero() {
		return false
	}
	s.sent = s.probationSent
	s.acked = s.probationAcked
	s.probationUntil = time.Time{}
	s.probationSent = 0
	s.probationAcked = 0
	s.probationLastPick = time.Time{}
	return true
}

// maybeGraduateProbationLocked graduates the resolver when it has proven
// itself (enough post-rejoin sends at low loss) or when the probation
// window expired. The caller must hold s.mu. It returns true if the
// resolver graduated (so the caller decrements the balancer's count).
func (s *connectionStats) maybeGraduateProbationLocked(now time.Time) bool {
	if s.probationUntil.IsZero() {
		return false
	}
	if !now.Before(s.probationUntil) {
		return s.graduateProbationLocked()
	}
	if s.probationSent >= probationGraduationSends {
		if loss, ok := s.probationLossPerMilleLocked(); ok && loss < probationGraduationMaxLossPerMille {
			return s.graduateProbationLocked()
		}
	}
	return false
}

func (b *Balancer) GetBestConnection() (Connection, bool) {
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}

	switch b.strategy {
	case BalancingRandom:
		idx := snap.valid[b.nextRandom()%uint64(len(snap.valid))]
		return derefConnection(snap.connections, idx)
	case BalancingMTUWeighted:
		return b.weightedByMTUConnection(snap)
	case BalancingHighestMTU:
		return b.bestHighestMTUConnection(snap)
	case BalancingLeastLoss:
		if !b.hasLossSignal(snap) {
			return b.roundRobinBestConnection(snap)
		}
		return b.bestScoredConnection(snap, b.lossScore)
	case BalancingLowestLatency:
		if !b.hasLatencySignal(snap) {
			return b.roundRobinBestConnection(snap)
		}
		return b.bestScoredConnection(snap, b.latencyScore)
	default:
		return b.roundRobinBestConnection(snap)
	}
}

func (b *Balancer) GetBestConnectionExcluding(excludeKey string) (Connection, bool) {
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}

	switch b.strategy {
	case BalancingRandom, BalancingMTUWeighted:
		ordered := b.rotatedValidIndices(snap, 1)
		for _, idx := range ordered {
			conn, ok := derefConnection(snap.connections, idx)
			if !ok || conn.Key == excludeKey {
				continue
			}
			return conn, true
		}
		return Connection{}, false
	case BalancingHighestMTU:
		return b.bestHighestMTUConnectionExcluding(snap, excludeKey)
	case BalancingLeastLoss:
		if !b.hasLossSignal(snap) {
			return b.roundRobinBestConnectionExcluding(snap, excludeKey)
		}
		return b.bestScoredConnectionExcluding(snap, b.lossScore, excludeKey)
	case BalancingLowestLatency:
		if !b.hasLatencySignal(snap) {
			return b.roundRobinBestConnectionExcluding(snap, excludeKey)
		}
		return b.bestScoredConnectionExcluding(snap, b.latencyScore, excludeKey)
	default:
		return b.roundRobinBestConnectionExcluding(snap, excludeKey)
	}
}

func (b *Balancer) GetUniqueConnections(requiredCount int) []Connection {
	snap := b.snapshot.Load()
	if snap == nil {
		return nil
	}

	count := normalizeRequiredCount(len(snap.valid), requiredCount, 1)
	if count <= 0 {
		return nil
	}

	if count == 1 {
		best, ok := b.GetBestConnection()
		if !ok {
			return nil
		}
		return []Connection{best}
	}

	switch b.strategy {
	case BalancingRandom:
		return b.selectRandom(snap, count)
	case BalancingMTUWeighted:
		return b.selectRoundRobin(snap, count)
	case BalancingHighestMTU:
		return b.selectHighestMTU(snap, count)
	case BalancingLeastLoss:
		if !b.hasLossSignal(snap) {
			return b.selectRoundRobin(snap, count)
		}
		return b.selectLowestScore(snap, count, b.lossScore)
	case BalancingLowestLatency:
		if !b.hasLatencySignal(snap) {
			return b.selectRoundRobin(snap, count)
		}
		return b.selectLowestScore(snap, count, b.latencyScore)
	default:
		return b.selectRoundRobin(snap, count)
	}
}

func (b *Balancer) GetAllValidConnections() []Connection {
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return nil
	}
	return snapshotConnections(snap.connections, snap.valid)
}

// AllValidConnectionsIncludingBackup returns a copy of every IsValid connection
// regardless of tier (primary and backup). Unlike GetAllValidConnections — which
// returns only the active selection set — this exposes the full surviving pool so
// the adaptive-MTU layer can re-derive the operating point over all resolvers
// that are still reachable.
func (b *Balancer) AllValidConnectionsIncludingBackup() []Connection {
	snap := b.snapshot.Load()
	if snap == nil {
		return nil
	}
	out := make([]Connection, 0, len(snap.connections))
	for _, conn := range snap.connections {
		if conn.IsValid {
			out = append(out, conn)
		}
	}
	return out
}

// ReclassifyBackups recomputes every connection's Backup flag from the predicate
// (true => backup/reserve) under the balancer lock and rebuilds the active
// selection set. It updates both the snapshot and the backing sources so the
// change is race-free with the health loop and visible to the rest of the client.
func (b *Balancer) ReclassifyBackups(isBackup func(Connection) bool) {
	if isBackup == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	snap := b.snapshot.Load()
	if snap == nil {
		return
	}
	connections := make([]Connection, len(snap.connections))
	copy(connections, snap.connections)
	for idx := range connections {
		if idx < len(b.sources) && b.sources[idx] != nil {
			connections[idx] = *b.sources[idx]
		}
		backup := connections[idx].IsValid && isBackup(connections[idx])
		connections[idx].Backup = backup
		if idx < len(b.sources) && b.sources[idx] != nil {
			b.sources[idx].Backup = backup
		}
	}

	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: connections,
		valid:       rebuildValidIndicesWithFamily(connections, b.familyMode),
		indexByKey:  snap.indexByKey,
		stats:       snap.stats,
	})
}

func (b *Balancer) AverageRTT(serverKey string) (time.Duration, bool) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return 0, false
	}

	_, _, sum, count := stats.snapshot()
	if count == 0 {
		return 0, false
	}

	return time.Duration(sum/count) * time.Microsecond, true
}

// rebuildValidIndices returns the balancer's active selection set. Primary
// resolvers (valid and not Backup) are preferred; backup resolvers are included
// only when no primary is available, so the session normally runs entirely on
// the active pool but slow reserves still take over if every primary fails.
func rebuildValidIndices(connections []Connection) []int {
	return rebuildValidIndicesWithFamily(connections, "dual")
}

func rebuildValidIndicesWithFamily(connections []Connection, familyMode string) []int {
	all := make([]int, 0, len(connections))
	for idx := range connections {
		if connections[idx].IsValid {
			all = append(all, idx)
		}
	}
	if familyMode == "dual" {
		return selectResolverTier(connections, all)
	}
	v4, v6 := splitResolverFamilies(connections, all)
	switch familyMode {
	case "ipv4":
		return selectResolverTier(connections, v4)
	case "ipv6":
		return selectResolverTier(connections, v6)
	case "auto":
		if len(v4) > 0 {
			return selectResolverTier(connections, v4)
		}
		return selectResolverTier(connections, v6)
	default:
		return selectResolverTier(connections, all)
	}
}

func splitResolverFamilies(connections []Connection, indices []int) (v4, v6 []int) {
	v4 = make([]int, 0, len(indices))
	v6 = make([]int, 0, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx >= len(connections) {
			continue
		}
		if resolverAddressIsIPv6(connections[idx].Resolver) {
			v6 = append(v6, idx)
		} else {
			v4 = append(v4, idx)
		}
	}
	return v4, v6
}

func selectResolverTier(connections []Connection, indices []int) []int {
	primary := make([]int, 0, len(indices))
	backup := make([]int, 0, len(indices))
	for _, idx := range indices {
		if connections[idx].Backup {
			backup = append(backup, idx)
		} else {
			primary = append(primary, idx)
		}
	}
	if len(primary) > 0 {
		return primary
	}
	return backup
}

func (b *Balancer) statsForKey(serverKey string) *connectionStats {
	snap := b.snapshot.Load()
	if snap == nil {
		return nil
	}
	idx, ok := snap.indexByKey[serverKey]
	if !ok || idx < 0 || idx >= len(snap.stats) {
		return nil
	}
	return snap.stats[idx]
}

func normalizeRequiredCount(validCount, requiredCount, defaultIfInvalid int) int {
	if validCount <= 0 {
		return 0
	}

	if requiredCount <= 0 {
		requiredCount = defaultIfInvalid
	}

	if requiredCount > validCount {
		return validCount
	}

	return requiredCount
}

func (b *Balancer) selectRoundRobin(snap *balancerSnapshot, count int) []Connection {
	n := len(snap.valid)
	start := roundRobinStartIndex(b.rrCounter.Add(uint64(count))-uint64(count), n)
	selected := make([]Connection, count)
	for i := 0; i < count; i++ {
		conn, ok := derefConnection(snap.connections, snap.valid[(start+i)%n])
		if ok {
			selected[i] = conn
		}
	}
	return selected
}

func (b *Balancer) selectRandom(snap *balancerSnapshot, count int) []Connection {
	n := len(snap.valid)
	if count <= 0 || n == 0 {
		return nil
	}

	// Optimization for small count selection to avoid large allocations
	if count == 1 {
		idx := snap.valid[b.nextRandom()%uint64(n)]
		conn, ok := derefConnection(snap.connections, idx)
		if ok {
			return []Connection{conn}
		}
		return nil
	}

	indices := make([]int, n)
	copy(indices, snap.valid)

	for i := 0; i < count; i++ {
		j := i + int(b.nextRandom()%uint64(n-i))
		indices[i], indices[j] = indices[j], indices[i]
	}

	return snapshotConnections(snap.connections, indices[:count])
}

// sentByIndex returns a resolver's recent send count (half-life decayed) from
// the balancer stats. It is the load signal for fair-share selection: a
// resolver that has recently carried many queries is "hot" and should be
// picked less often until its count decays.
func sentByIndex(snap *balancerSnapshot, idx int) uint64 {
	stats := statsByIndex(snap, idx)
	if stats == nil {
		return 0
	}
	sent, _, _, _ := stats.snapshot()
	return sent
}

// loadDiscountedWeight returns a resolver's MTU-goodput weight discounted by
// its recent send load, so a resolver that has recently carried many queries
// is picked less often and the load spreads across the pool instead of
// concentrating on the same high-MTU resolvers. The discount is 1/(1+sent/100):
// a resolver with 100 recent sends is halved, 500 sends is cut to a sixth.
// At even load the discount is the same for everyone, so MTU still dominates
// and the weight never drops below the floor of 1.
func loadDiscountedWeight(snap *balancerSnapshot, idx int) uint64 {
	w := mtuGoodputWeight(&snap.connections[idx])
	sent := sentByIndex(snap, idx)
	if sent == 0 {
		return w
	}
	w = w / (1 + sent/100)
	if w < 1 {
		w = 1
	}
	return w
}

func (b *Balancer) selectLowestScore(snap *balancerSnapshot, count int, scorer func(*balancerSnapshot, int) uint64) []Connection {
	n := len(snap.valid)
	if count <= 0 || n == 0 {
		return nil
	}

	if count == 1 {
		conn, ok := b.bestScoredConnection(snap, scorer)
		if ok {
			return []Connection{conn}
		}
		return nil
	}

	type scoredIdx struct {
		idx   int
		score uint64
		sent  uint64
	}

	ordered := b.rotatedValidIndices(snap, count)
	scored := make([]scoredIdx, 0, n)
	for _, idx := range ordered {
		// Probationary resolvers never take a duplicate slot: they are
		// re-proving themselves via the rate-capped trickle only.
		if isProbationaryByIndex(snap, idx) {
			continue
		}
		scored = append(scored, scoredIdx{idx: idx, score: scorer(snap, idx), sent: sentByIndex(snap, idx)})
	}
	n = len(scored)
	if n == 0 {
		return nil
	}

	// Simple selection sort for small 'count'. Sort by (score, sent):
	// prefer the lowest loss, and among equally-healthy resolvers prefer
	// the least-loaded, so the pick spreads across the whole healthy pool
	// instead of hammering the same "best" resolver until it rate-limits.
	for i := 0; i < count && i < n; i++ {
		minIdx := i
		for j := i + 1; j < n; j++ {
			if scored[j].score < scored[minIdx].score ||
				(scored[j].score == scored[minIdx].score && scored[j].sent < scored[minIdx].sent) {
				minIdx = j
			}
		}
		scored[i], scored[minIdx] = scored[minIdx], scored[i]
	}

	// Clamp to the eligible set: probation filtering can shrink the pool
	// below the requested count, and returning fewer (never a duplicate
	// or a zero entry) is the correct answer then.
	if count > n {
		count = n
	}
	indices := make([]int, count)
	for i := 0; i < count; i++ {
		indices[i] = scored[i].idx
	}

	return snapshotConnections(snap.connections, indices)
}

func (b *Balancer) selectHighestMTU(snap *balancerSnapshot, count int) []Connection {
	if snap == nil || count <= 0 || len(snap.valid) == 0 {
		return nil
	}
	if count > len(snap.valid) {
		count = len(snap.valid)
	}
	selected := make([]int, 0, count)
	used := make(map[int]struct{}, count)
	for len(selected) < count {
		best := -1
		for _, idx := range snap.valid {
			if _, ok := used[idx]; ok {
				continue
			}
			if best == -1 || higherMTUFirst(snap.connections[idx], snap.connections[best]) {
				best = idx
			}
		}
		if best == -1 {
			break
		}
		used[best] = struct{}{}
		selected = append(selected, best)
	}
	return snapshotConnections(snap.connections, selected)
}

func (b *Balancer) bestHighestMTUConnection(snap *balancerSnapshot) (Connection, bool) {
	selected := b.selectHighestMTU(snap, 1)
	if len(selected) == 0 {
		return Connection{}, false
	}
	return selected[0], true
}

func (b *Balancer) bestHighestMTUConnectionExcluding(snap *balancerSnapshot, excludeKey string) (Connection, bool) {
	for _, conn := range b.selectHighestMTU(snap, len(snap.valid)) {
		if conn.Key != "" && conn.Key != excludeKey {
			return conn, true
		}
	}
	return Connection{}, false
}

func higherMTUFirst(a, b Connection) bool {
	if a.DownloadMTUBytes != b.DownloadMTUBytes {
		return a.DownloadMTUBytes > b.DownloadMTUBytes
	}
	if a.UploadMTUBytes != b.UploadMTUBytes {
		return a.UploadMTUBytes > b.UploadMTUBytes
	}
	if a.MTUResolveTime != b.MTUResolveTime {
		if a.MTUResolveTime <= 0 {
			return false
		}
		if b.MTUResolveTime <= 0 {
			return true
		}
		return a.MTUResolveTime < b.MTUResolveTime
	}
	return a.Key < b.Key
}

func snapshotConnections(connections []Connection, indices []int) []Connection {
	selected := make([]Connection, len(indices))
	for i, idx := range indices {
		if idx < 0 || idx >= len(connections) {
			continue
		}
		selected[i] = connections[idx]
	}
	return selected
}

func (b *Balancer) bestScoredConnection(snap *balancerSnapshot, scorer func(*balancerSnapshot, int) uint64) (Connection, bool) {
	ordered := b.rotatedValidIndices(snap, 1)
	bestIndex := -1
	var bestScore uint64
	var bestSent uint64
	for _, idx := range ordered {
		// Probationary resolvers are never the single best pick: they
		// re-prove themselves via the rate-capped trickle only.
		if isProbationaryByIndex(snap, idx) {
			continue
		}
		score := scorer(snap, idx)
		sent := sentByIndex(snap, idx)
		// Prefer the lowest score; among equal scores prefer the
		// least-loaded, so a single "best" resolver is not hammered.
		if bestIndex == -1 || score < bestScore || (score == bestScore && sent < bestSent) {
			bestIndex = idx
			bestScore = score
			bestSent = sent
		}
	}
	if bestIndex < 0 {
		return Connection{}, false
	}
	return derefConnection(snap.connections, bestIndex)
}

func (b *Balancer) bestScoredConnectionExcluding(snap *balancerSnapshot, scorer func(*balancerSnapshot, int) uint64, excludeKey string) (Connection, bool) {
	ordered := b.rotatedValidIndices(snap, 1)
	bestIndex := -1
	var bestScore uint64
	var bestSent uint64
	for _, idx := range ordered {
		conn, ok := derefConnection(snap.connections, idx)
		if !ok || conn.Key == excludeKey {
			continue
		}
		// Probationary resolvers are never the single best pick (and so
		// never a stream's preferred resolver): they re-prove themselves
		// via the rate-capped trickle only.
		if isProbationaryByIndex(snap, idx) {
			continue
		}
		score := scorer(snap, idx)
		sent := sentByIndex(snap, idx)
		if bestIndex == -1 || score < bestScore || (score == bestScore && sent < bestSent) {
			bestIndex = idx
			bestScore = score
			bestSent = sent
		}
	}
	if bestIndex < 0 {
		return Connection{}, false
	}
	return derefConnection(snap.connections, bestIndex)
}

func derefConnection(connections []Connection, idx int) (Connection, bool) {
	if idx < 0 || idx >= len(connections) {
		return Connection{}, false
	}
	return connections[idx], true
}

func (b *Balancer) lossScore(snap *balancerSnapshot, idx int) uint64 {
	stats := statsByIndex(snap, idx)
	if stats == nil {
		return 500
	}
	sent, acked, _, _ := stats.snapshot()
	if sent < 5 {
		return 500
	}

	if acked >= sent {
		return 0
	}
	// loss ratio in per 1000 for integer math (a/b -> a*1000/b)
	return (sent - acked) * 1000 / sent
}

// AggregateLossPerMille returns the mean observed packet loss (parts per 1000)
// across valid connections that have enough samples, or 0 when there is no loss
// signal yet. It drives tier-1 adaptive duplication.
func (b *Balancer) AggregateLossPerMille() uint64 {
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return 0
	}
	var total, n uint64
	for _, idx := range snap.valid {
		stats := statsByIndex(snap, idx)
		if stats == nil {
			continue
		}
		sent, acked, _, _ := stats.snapshot()
		if sent < 5 {
			continue
		}
		loss := uint64(0)
		if acked < sent {
			loss = (sent - acked) * 1000 / sent
		}
		total += loss
		n++
	}
	if n == 0 {
		return 0
	}
	return total / n
}

func (b *Balancer) latencyScore(snap *balancerSnapshot, idx int) uint64 {
	stats := statsByIndex(snap, idx)
	if stats == nil {
		return 999000
	}
	_, _, sum, count := stats.snapshot()
	if count < 5 {
		return 999000
	}
	return sum / count
}

// mtuGoodputWeight returns the selection weight for a resolver as its effective
// download *goodput* — the download MTU discounted by the fraction of packets it
// actually delivers at that MTU (1 - measured loss). Weighting by goodput instead
// of raw MTU makes transport selection robust against resolvers whose nominal MTU
// overstates what they can carry: a resolver that was assigned a high MTU but
// drops a large share of packets at it is automatically weighted down toward the
// throughput it can really sustain, rather than being over-favored for its size.
// Resolvers with an unknown (≤0) MTU get a unit weight so they stay reachable.
func mtuGoodputWeight(conn *Connection) uint64 {
	mtu := conn.DownloadMTUBytes
	if mtu <= 0 {
		return 1
	}
	loss := conn.DownloadMTULoss
	if loss < 0 {
		loss = 0
	}
	if loss > 1 {
		loss = 1
	}
	weight := uint64(float64(mtu)*(1.0-loss) + 0.5)
	if weight < 1 {
		// Even a near-fully-lossy resolver keeps a floor weight so it is not starved
		// entirely and can recover if its loss estimate improves.
		weight = 1
	}
	return weight
}

// weightedByMTUConnection picks an active-pool resolver with probability
// proportional to its effective download goodput (MTU × delivery rate),
// discounted by its recent send load so the pick spreads across the pool
// instead of concentrating on the same high-MTU resolvers. Falls back to
// round-robin when there is no usable weight signal.
func (b *Balancer) weightedByMTUConnection(snap *balancerSnapshot) (Connection, bool) {
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}
	total := uint64(0)
	for _, idx := range snap.valid {
		// Probationary resolvers are never picked by weight either: they
		// re-prove themselves via the rate-capped trickle only.
		if isProbationaryByIndex(snap, idx) {
			continue
		}
		total += loadDiscountedWeight(snap, idx)
	}
	if total == 0 {
		return b.roundRobinBestConnection(snap)
	}

	r := b.nextRandom() % total
	for _, idx := range snap.valid {
		if isProbationaryByIndex(snap, idx) {
			continue
		}
		w := loadDiscountedWeight(snap, idx)
		if r < w {
			return derefConnection(snap.connections, idx)
		}
		r -= w
	}
	return derefConnection(snap.connections, snap.valid[len(snap.valid)-1])
}

func (b *Balancer) roundRobinBestConnection(snap *balancerSnapshot) (Connection, bool) {
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}
	pos := roundRobinStartIndex(b.rrCounter.Add(1)-1, len(snap.valid))
	return derefConnection(snap.connections, snap.valid[pos])
}

func (b *Balancer) roundRobinBestConnectionExcluding(snap *balancerSnapshot, excludeKey string) (Connection, bool) {
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}
	ordered := b.rotatedValidIndices(snap, 1)
	for _, idx := range ordered {
		conn, ok := derefConnection(snap.connections, idx)
		if !ok || conn.Key == excludeKey {
			continue
		}
		return conn, true
	}
	return Connection{}, false
}

func (b *Balancer) rotatedValidIndices(snap *balancerSnapshot, step int) []int {
	if snap == nil || len(snap.valid) == 0 {
		return nil
	}
	if step < 1 {
		step = 1
	}

	start := roundRobinStartIndex(b.rrCounter.Add(uint64(step))-uint64(step), len(snap.valid))
	ordered := make([]int, len(snap.valid))
	for i := range snap.valid {
		ordered[i] = snap.valid[(start+i)%len(snap.valid)]
	}
	return ordered
}

func roundRobinStartIndex(counter uint64, n int) int {
	if n <= 0 {
		return 0
	}
	return int(counter % uint64(n))
}

func (b *Balancer) hasLossSignal(snap *balancerSnapshot) bool {
	if snap == nil {
		return false
	}
	for _, idx := range snap.valid {
		stats := statsByIndex(snap, idx)
		if stats == nil {
			continue
		}
		sent, _, _, _ := stats.snapshot()
		if sent >= 5 {
			return true
		}
	}
	return false
}

func (b *Balancer) hasLatencySignal(snap *balancerSnapshot) bool {
	if snap == nil {
		return false
	}
	for _, idx := range snap.valid {
		stats := statsByIndex(snap, idx)
		if stats == nil {
			continue
		}
		_, _, _, count := stats.snapshot()
		if count >= 5 {
			return true
		}
	}
	return false
}

func statsByIndex(snap *balancerSnapshot, idx int) *connectionStats {
	if snap == nil || idx < 0 || idx >= len(snap.stats) {
		return nil
	}
	return snap.stats[idx]
}

// isProbationaryByIndex reports whether the resolver at idx is in post-rejoin
// probation (and the window has not expired). Probationary resolvers are
// excluded from the scored selection paths (best pick and duplicate slots)
// so a just-rejoined resolver can never be hammered again; its only picks
// come from the rate-capped trickle picker.
func isProbationaryByIndex(snap *balancerSnapshot, idx int) bool {
	stats := statsByIndex(snap, idx)
	if stats == nil {
		return false
	}
	stats.mu.RLock()
	defer stats.mu.RUnlock()
	return !stats.probationUntil.IsZero() && time.Now().Before(stats.probationUntil)
}

func (s *connectionStats) snapshot() (sent uint64, acked uint64, rttMicrosSum uint64, rttCount uint64) {
	if s == nil {
		return 0, 0, 0, 0
	}

	s.mu.RLock()
	sent = s.sent
	acked = s.acked
	rttMicrosSum = s.rttMicrosSum
	rttCount = s.rttCount
	s.mu.RUnlock()
	return sent, acked, rttMicrosSum, rttCount
}

func (s *connectionStats) applyHalfLifeLocked() {
	if s == nil {
		return
	}
	if s.sent <= connectionStatsHalfLifeThreshold &&
		s.acked <= connectionStatsHalfLifeThreshold &&
		s.rttCount <= connectionStatsHalfLifeThreshold {
		return
	}

	s.sent /= 2
	s.acked /= 2
	s.rttMicrosSum /= 2
	s.rttCount /= 2
	// The recent-window ring records acked counts on the pre-halving
	// scale; after halving those snapshots are meaningless (the
	// difference would underflow or overcount loss). Clear the ring so
	// the window rebuilds from fresh sends. An active resolver
	// accumulates the >=20 sends the window needs to be trusted within
	// seconds, so the tracker is only briefly blind after a halving —
	// and the half-life counters still judge the resolver meanwhile.
	s.recentRingHead = 0
	s.recentRingCount = 0
}

func (b *Balancer) nextRandom() uint64 {
	for {
		current := b.rngState.Load()
		next := xorshift64(current)
		if b.rngState.CompareAndSwap(current, next) {
			return next
		}
	}
}

func seedRNG() uint64 {
	seed := uint64(time.Now().UnixNano())
	if seed == 0 {
		return 0x9e3779b97f4a7c15
	}
	return seed
}

func xorshift64(v uint64) uint64 {
	if v == 0 {
		v = 0x9e3779b97f4a7c15
	}
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	return v
}
