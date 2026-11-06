// Package mesh implements the Nexounel multi-node mesh control plane:
// membership terms, mother-signed snapshots, deterministic chief
// succession, the membership table and its acceptance rules, and the
// coordinator state machine (heartbeat aggregation, election,
// degraded mode, step-down).
//
// The package is transport-free: it never opens sockets, never touches
// the DNS carrier, and never reads credentials. Control streams, peer
// control ports, and the panel wiring consume the decisions this
// package makes (tables, terms, events) and deliver them; this package
// only decides. That separation is what makes the election rules
// unit-testable without any network.
//
// Trust model (see the Phase 3 spec, §§6/8): the mother is the trust
// anchor and single registry writer. Terms issued by the mother always
// beat degraded terms derived from a signed snapshot, regardless of
// number, so a partitioned mesh can never outrank the mother on
// reunion. Degraded terms derive deterministically from one signed
// snapshot with one fixed ranking rule, so every correct node computes
// the same successor with no voting and no quorum messages.
package mesh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/multisession"
)

// TermClass separates mother-issued terms from degraded terms. A
// normal term always outranks a degraded term, regardless of number:
// degraded leadership is provisional by construction and must yield
// the moment the mother speaks again.
type TermClass int

const (
	// TermNormal is issued by the mother.
	TermNormal TermClass = iota
	// TermDegraded is derived from the last mother-signed snapshot
	// while the mother link is down.
	TermDegraded
)

// Term is one leadership term: a monotonically increasing number
// within its class. The zero Term (number 0, normal) is the
// "no table yet" term and loses to every real term.
type Term struct {
	Number   uint64
	Degraded bool
}

// Class returns the term's class.
func (t Term) Class() TermClass {
	if t.Degraded {
		return TermDegraded
	}
	return TermNormal
}

// CompareTerms orders terms: the zero term ("no table yet") loses to
// every real term; normal beats degraded at any number; within a
// class the higher number wins; equal terms compare equal.
// It is a pure function so the rule is identical on every node.
func CompareTerms(a, b Term) int {
	if a.IsZero() || b.IsZero() {
		switch {
		case a.IsZero() && b.IsZero():
			return 0
		case a.IsZero():
			return -1
		default:
			return 1
		}
	}
	ca, cb := a.Class(), b.Class()
	if ca != cb {
		if ca == TermNormal {
			return 1
		}
		return -1
	}
	switch {
	case a.Number < b.Number:
		return -1
	case a.Number > b.Number:
		return 1
	default:
		return 0
	}
}

// NextNormal returns the term that follows t in the normal class. It
// is the mother's term-issuance step: the new term is always strictly
// greater than any term the mother has issued before.
func (t Term) NextNormal() Term {
	return Term{Number: t.Number + 1, Degraded: false}
}

// DegradedFrom derives the degraded term that follows a snapshot term:
// snapshot term + 1, marked degraded. Every node deriving from the
// same snapshot computes the same degraded term.
func DegradedFrom(snapshotTerm Term) Term {
	return Term{Number: snapshotTerm.Number + 1, Degraded: true}
}

// IsZero reports whether t is the "no table yet" term.
func (t Term) IsZero() bool { return t.Number == 0 && !t.Degraded }

// String renders a term for logs: "T7" for normal terms,
// "T7(degraded)" for degraded terms.
func (t Term) String() string {
	if t.Degraded {
		return fmt.Sprintf("T%d(degraded)", t.Number)
	}
	return fmt.Sprintf("T%d", t.Number)
}

// NodeState is one node's membership state as tracked by the mother
// (Phase 3 spec §2).
type NodeState string

const (
	// StatePending: join token issued, node not yet enrolled.
	StatePending NodeState = "PENDING"
	// StateActive: enrolled, keyed, heartbeating, in the table.
	StateActive NodeState = "ACTIVE"
	// StateSuspect: heartbeats missed past the suspect threshold;
	// excluded from new distributions, existing streams untouched.
	StateSuspect NodeState = "SUSPECT"
	// StateDown: missed past the down threshold or explicitly
	// removed; out of the table, key still valid until revoked.
	StateDown NodeState = "DOWN"
	// StateRevoked: key revoked by the mother; the node can never
	// rejoin without a fresh join token.
	StateRevoked NodeState = "REVOKED"
)

// Member is one mesh member as carried in a membership table. Loss,
// LegRTTMs, and LegOK describe the entry-to-member leg (§5.3) and the
// member's own health as last reported; TenureSeq is assigned by the
// mother at enrollment and increases monotonically, so the smallest
// TenureSeq is the longest continuously-ACTIVE member. CapacityBps is
// the member's measured capacity: the minimum of its probe ceiling
// and observed goodput, as reported on its heartbeat.
type Member struct {
	ID          string
	State       NodeState
	CapacityBps float64
	Loss        float64
	LegRTTMs    float64
	LegOK       bool
	// TenureSeq orders members by continuous ACTIVE tenure: smaller
	// is longer-tenured. It is assigned by the mother, never by
	// peers, so the succession ranking is identical everywhere.
	TenureSeq uint64
}

// Table is one versioned membership table: the unit of agreement in
// the mesh. Members carry states; Weights carries the distribution
// weight per member ID (zero is a valid weight: reserve, §5.5).
// ChiefID names the chief; it is "" when the mesh has a single
// member and no election is active.
type Table struct {
	Term    Term
	Version uint64
	ChiefID string
	Members []Member
	Weights map[string]float64
}

// Clone returns a deep copy of t.
func (t Table) Clone() Table {
	out := t
	out.Members = append([]Member(nil), t.Members...)
	if t.Weights != nil {
		out.Weights = make(map[string]float64, len(t.Weights))
		for k, v := range t.Weights {
			out.Weights[k] = v
		}
	}
	return out
}

// Find returns the member with the given ID, if present.
func (t Table) Find(id string) (Member, bool) {
	for _, m := range t.Members {
		if m.ID == id {
			return m, true
		}
	}
	return Member{}, false
}

// Snapshot is a signed membership table: the artifact degraded-mode
// derivation trusts. The signature is an HMAC-SHA256 over the
// canonical encoding of the table, keyed by the snapshot-signing key
// the mother issues to nodes at enrollment. The signature proves the
// table came from the mother; it does not prove freshness (a stale
// snapshot is still mother-signed, which is why degraded terms always
// lose to mother-issued terms on reunion).
//
// Trust note: the signing key is shared with every enrolled node, so a
// compromised node could forge a snapshot. The blast radius is
// bounded by design: a forged snapshot can only influence degraded
// derivation, never outrank a mother-issued term, and distribution is
// stateless per connection, so the worst case is suboptimal weighting
// — never corruption. A compromised mother compromises the mesh,
// exactly as in Phase 2.
type Snapshot struct {
	Table     Table
	Signature string // hex-encoded HMAC-SHA256 over the canonical table
}

// canonicalEncoding renders a table deterministically for signing:
// members sorted by ID, fields in fixed order, no map iteration.
func canonicalEncoding(t Table) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "term=%d,degraded=%v,version=%d,chief=%s\n",
		t.Term.Number, t.Term.Degraded, t.Version, t.ChiefID)
	members := append([]Member(nil), t.Members...)
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })
	for _, m := range members {
		fmt.Fprintf(&b, "member=%s,%s,%.6f,%.6f,%.3f,%v,%d,weight=%.6f\n",
			m.ID, m.State, m.CapacityBps, m.Loss, m.LegRTTMs, m.LegOK, m.TenureSeq, t.Weights[m.ID])
	}
	return []byte(b.String())
}

// SignSnapshot signs t with key and returns the snapshot. An empty key
// is refused: an unsigned snapshot must never circulate as signed.
func SignSnapshot(t Table, key []byte) (Snapshot, error) {
	if len(key) == 0 {
		return Snapshot{}, errors.New("snapshot signing key is empty")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canonicalEncoding(t))
	return Snapshot{Table: t.Clone(), Signature: hex.EncodeToString(mac.Sum(nil))}, nil
}

// Verify reports whether s carries a valid signature under key and
// the table decodes sanely. Verification is constant-time in the
// signature comparison; the table itself is not secret.
func (s Snapshot) Verify(key []byte) bool {
	if len(key) == 0 || s.Signature == "" {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canonicalEncoding(s.Table))
	want, err := hex.DecodeString(s.Signature)
	if err != nil {
		return false
	}
	return hmac.Equal(want, mac.Sum(nil))
}

// RankSuccessor picks the successor chief from members by the single
// deterministic ranking (§6.2): longest continuous ACTIVE tenure
// first, then highest measured capacity, then lexicographically
// smallest node ID. Only ACTIVE members are eligible; excludeID
// (usually the lost chief) is skipped. The ranking uses only
// table-carried state, so every node computing it from the same
// snapshot picks the same successor — no voting, no quorum. It
// returns "" when no member is eligible.
func RankSuccessor(members []Member, excludeID string) string {
	var eligible []Member
	for _, m := range members {
		if m.State != StateActive || m.ID == excludeID {
			continue
		}
		eligible = append(eligible, m)
	}
	if len(eligible) == 0 {
		return ""
	}
	sort.Slice(eligible, func(i, j int) bool {
		a, b := eligible[i], eligible[j]
		if a.TenureSeq != b.TenureSeq {
			return a.TenureSeq < b.TenureSeq
		}
		if a.CapacityBps != b.CapacityBps {
			return a.CapacityBps > b.CapacityBps
		}
		return a.ID < b.ID
	})
	return eligible[0].ID
}

// Timeouts carries the §6.3 detection timeouts. All values are config
// keys in deployment, never constants; the defaults below are the
// spec's reasoned values. Timeouts are deliberately slow: DNS-carried
// control traffic has high, variable latency, and a flapping election
// is worse than a slow one.
type Timeouts struct {
	HeartbeatInterval     time.Duration
	SuspectAfter          time.Duration
	DownAfter             time.Duration
	ChiefLossAfter        time.Duration
	MotherLinkLossAfter   time.Duration
	DegradedTakeoverAfter time.Duration
}

// DefaultTimeouts returns the §6.3 decided values.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		HeartbeatInterval:     30 * time.Second,
		SuspectAfter:          60 * time.Second,
		DownAfter:             120 * time.Second,
		ChiefLossAfter:        60 * time.Second,
		MotherLinkLossAfter:   120 * time.Second,
		DegradedTakeoverAfter: 60 * time.Second,
	}
}

// Validate rejects non-positive timeouts and orderings that would
// make detection fire before the signal it watches for exists
// (suspect must allow at least one missed heartbeat; down must
// follow suspect).
func (to Timeouts) Validate() error {
	if to.HeartbeatInterval <= 0 || to.SuspectAfter <= 0 || to.DownAfter <= 0 ||
		to.ChiefLossAfter <= 0 || to.MotherLinkLossAfter <= 0 || to.DegradedTakeoverAfter <= 0 {
		return errors.New("mesh timeouts must all be positive")
	}
	if to.SuspectAfter < to.HeartbeatInterval {
		return errors.New("suspect timeout must allow at least one heartbeat interval")
	}
	if to.DownAfter <= to.SuspectAfter {
		return errors.New("down timeout must be greater than the suspect timeout")
	}
	return nil
}

// EventKind names one coordinator decision.
type EventKind string

const (
	// EventNodeSuspect: a member missed heartbeats past the suspect
	// threshold; excluded from new picks.
	EventNodeSuspect EventKind = "node-suspect"
	// EventNodeDown: a member missed heartbeats past the down
	// threshold; removed from the table.
	EventNodeDown EventKind = "node-down"
	// EventNodeRecovered: a SUSPECT member heartbeated again.
	EventNodeRecovered EventKind = "node-recovered"
	// EventChiefLost: the chief missed heartbeats past the chief-loss
	// threshold (mother perspective: elect a successor).
	EventChiefLost EventKind = "chief-lost"
	// EventDegradedMode: the mother link is lost; the last table
	// keeps being enforced, no reconfiguration.
	EventDegradedMode EventKind = "degraded-mode"
	// EventDegradedTakeover: chief and mother are both silent; the
	// deterministic successor from the signed snapshot takes over
	// as degraded chief.
	EventDegradedTakeover EventKind = "degraded-takeover"
	// EventMotherResync: mother contact resumed; the mother's table
	// wins by the term rule and any degraded chief steps down.
	EventMotherResync EventKind = "mother-resync"
	// EventStepDown: this node stepped down as chief.
	EventStepDown EventKind = "step-down"
)

// Event is one coordinator decision, emitted by Evaluate/ApplyTable
// for the caller to act on (publish, log, alert). Events carry the
// IDs they concern; they never carry secrets.
type Event struct {
	Kind      EventKind
	NodeID    string // member concerned, if any
	Successor string // elected successor, for chief-lost/takeover
	Term      Term   // term of the decision, for chief-lost/takeover
}

func (e Event) String() string {
	switch e.Kind {
	case EventChiefLost, EventDegradedTakeover:
		return fmt.Sprintf("%s successor=%s term=%s", e.Kind, e.Successor, e.Term)
	case EventNodeSuspect, EventNodeDown, EventNodeRecovered:
		return fmt.Sprintf("%s node=%s", e.Kind, e.NodeID)
	default:
		return string(e.Kind)
	}
}

// memberState is the coordinator's live view of one member between
// tables: liveness and last-reported capacity.
type memberState struct {
	member   Member
	lastSeen time.Time
	everSeen bool
}

// Coordinator is the mesh control-plane state machine. It is shared
// by both perspectives: the mother (isMother=true) aggregates
// heartbeats and issues elections; a node (isMother=false) enforces
// tables and falls back to degraded derivation when the mother link
// is lost. Perspective only gates which decisions Evaluate emits;
// the term rule and the ranking rule are identical everywhere.
//
// The zero value is unusable: use NewCoordinator. All methods are
// single-threaded by contract; the caller serializes access (the
// node binary's coordinator goroutine, the panel's mesh loop).
type Coordinator struct {
	ownID       string
	isMother    bool
	timeouts    Timeouts
	snapshotKey []byte

	current      Table
	lastSnapshot Snapshot
	haveSnapshot bool

	members map[string]*memberState
	// lastMotherAnnouncement is the last time a mother table or
	// announcement arrived (node perspective).
	lastMotherAnnouncement time.Time
	// lastChiefContact is the last time the current chief was heard
	// from over the peer path (node perspective).
	lastChiefContact time.Time
	// degraded is set once mother-link loss is declared; it clears
	// on mother resync.
	degraded bool
	// degradedChief is set when this node took over as degraded
	// chief from the snapshot.
	degradedChief bool
	// lastReElection is the last operator-forced re-election, for
	// the 5-minute rate limit (§6.6).
	lastReElection time.Time
	// lastPublishedVersion tracks routine republication.
}

// NewCoordinator builds a coordinator. ownID is this node's ID
// ("" for the mother, which is not a member). snapshotKey is the
// snapshot verification key (nil disables degraded derivation:
// without a verified snapshot there is nothing safe to derive
// from). timeouts must validate; zero Timeouts means defaults.
func NewCoordinator(ownID string, isMother bool, timeouts Timeouts, snapshotKey []byte) (*Coordinator, error) {
	if timeouts == (Timeouts{}) {
		timeouts = DefaultTimeouts()
	}
	if err := timeouts.Validate(); err != nil {
		return nil, err
	}
	return &Coordinator{
		ownID:       ownID,
		isMother:    isMother,
		timeouts:    timeouts,
		snapshotKey: append([]byte(nil), snapshotKey...),
		members:     make(map[string]*memberState),
	}, nil
}

// Current returns the enforced table (a copy).
func (c *Coordinator) Current() Table { return c.current.Clone() }

// Degraded reports whether the coordinator is in degraded mode.
func (c *Coordinator) Degraded() bool { return c.degraded }

// IsChief reports whether ownID is the chief of the enforced table.
func (c *Coordinator) IsChief() bool {
	return c.ownID != "" && c.current.ChiefID == c.ownID
}

// ApplyTable enforces t by the §6.1 term rule: a higher term always
// wins; an equal term with a higher version from the same chief is a
// routine republication and is accepted; anything else is ignored.
// It returns whether the table was accepted. Applying a
// mother-issued (normal) table while degraded clears degraded mode
// and emits the resync fact via the returned bool: callers that need
// the event should check Degraded() before and after.
func (c *Coordinator) ApplyTable(t Table) bool {
	cmp := CompareTerms(t.Term, c.current.Term)
	if cmp < 0 {
		return false
	}
	if cmp == 0 {
		if t.Version <= c.current.Version || t.ChiefID != c.current.ChiefID {
			return false
		}
	}
	c.current = t.Clone()
	c.syncMembersFromTable(t)
	if !t.Term.Degraded {
		c.lastMotherAnnouncement = time.Now()
		if c.degraded {
			c.degraded = false
			c.degradedChief = false
		}
	}
	return true
}

// NoteSignedSnapshot records a verified mother-signed snapshot: the
// derivation input for degraded mode. Unverifiable snapshots are
// refused and never become derivation input.
func (c *Coordinator) NoteSignedSnapshot(s Snapshot) bool {
	if !s.Verify(c.snapshotKey) {
		return false
	}
	c.lastSnapshot = Snapshot{Table: s.Table.Clone(), Signature: s.Signature}
	c.haveSnapshot = true
	return true
}

// NoteMotherAnnouncement records mother contact at now (a table, a
// heartbeat response, any mother-originated control traffic). It is
// the liveness signal for the mother link.
func (c *Coordinator) NoteMotherAnnouncement(now time.Time) {
	c.lastMotherAnnouncement = now
	if c.degraded {
		c.degraded = false
		c.degradedChief = false
	}
}

// NoteChiefContact records peer contact with the current chief.
func (c *Coordinator) NoteChiefContact(now time.Time) {
	c.lastChiefContact = now
}

// NoteHeartbeat applies one member heartbeat: liveness, capacity,
// and leg health. Heartbeats from DOWN members are ignored (a DOWN
// member re-enters only through a mother table); heartbeats from
// unknown members are ignored (membership comes from tables, never
// from self-assertion). A heartbeat from a SUSPECT member recovers
// it. It returns whether the member was known and applied.
func (c *Coordinator) NoteHeartbeat(id string, capacityBps, loss, legRTTMs float64, legOK bool, now time.Time) bool {
	st, ok := c.members[id]
	if !ok || st.member.State == StateDown || st.member.State == StateRevoked {
		return false
	}
	recovered := st.member.State == StateSuspect
	st.member.CapacityBps = capacityBps
	st.member.Loss = loss
	st.member.LegRTTMs = legRTTMs
	st.member.LegOK = legOK
	st.lastSeen = now
	st.everSeen = true
	if recovered {
		st.member.State = StateActive
	}
	return true
}

// syncMembersFromTable rebuilds the live member view from a table,
// preserving liveness for members the table still lists.
func (c *Coordinator) syncMembersFromTable(t Table) {
	next := make(map[string]*memberState, len(t.Members))
	for _, m := range t.Members {
		if prev, ok := c.members[m.ID]; ok {
			prev.member.State = m.State
			prev.member.TenureSeq = m.TenureSeq
			next[m.ID] = prev
			continue
		}
		next[m.ID] = &memberState{member: m}
	}
	c.members = next
}

// Evaluate advances time-based decisions at now and returns the
// events the caller must act on. It mutates coordinator state to
// match the events (a SUSPECT member is marked SUSPECT, a degraded
// takeover installs the degraded table). It is idempotent between
// heartbeats: repeated evaluation without new input emits each
// transition once.
func (c *Coordinator) Evaluate(now time.Time) []Event {
	var events []Event

	// Member liveness (both perspectives).
	for id, st := range c.members {
		if st.member.State == StateDown || st.member.State == StateRevoked || !st.everSeen {
			continue
		}
		silent := now.Sub(st.lastSeen)
		switch st.member.State {
		case StateActive:
			if silent >= c.timeouts.SuspectAfter {
				st.member.State = StateSuspect
				events = append(events, Event{Kind: EventNodeSuspect, NodeID: id})
			}
		case StateSuspect:
			if silent >= c.timeouts.DownAfter {
				st.member.State = StateDown
				events = append(events, Event{Kind: EventNodeDown, NodeID: id})
			}
		}
	}

	// Mother-side chief election.
	if c.isMother {
		chief := c.current.ChiefID
		if chief != "" {
			if st, ok := c.members[chief]; ok {
				silent := time.Duration(0)
				if st.everSeen {
					silent = now.Sub(st.lastSeen)
				}
				if silent >= c.timeouts.ChiefLossAfter {
					if successor, term, ok := c.electFromCurrent(chief); ok {
						events = append(events, Event{Kind: EventChiefLost, NodeID: chief, Successor: successor, Term: term})
					}
				}
			}
		}
		return events
	}

	// Node-side mother-link loss → degraded mode.
	if !c.lastMotherAnnouncement.IsZero() && now.Sub(c.lastMotherAnnouncement) >= c.timeouts.MotherLinkLossAfter && !c.degraded {
		c.degraded = true
		events = append(events, Event{Kind: EventDegradedMode})
	}
	if c.degraded {
		// Degraded takeover: chief silent AND mother silent.
		chiefSilent := c.current.ChiefID == "" ||
			now.Sub(c.lastChiefContact) >= c.timeouts.DegradedTakeoverAfter
		if chiefSilent && !c.degradedChief {
			if successor, term, ok := c.electDegraded(); ok {
				events = append(events, Event{Kind: EventDegradedTakeover, Successor: successor, Term: term})
				if successor == c.ownID {
					c.installDegradedTable(term, successor)
					c.degradedChief = true
				}
			}
		}
	}
	return events
}

// electFromCurrent picks the successor from the current table
// (mother perspective) and computes the fresh normal term.
func (c *Coordinator) electFromCurrent(excludeChief string) (string, Term, bool) {
	members := make([]Member, 0, len(c.members))
	for _, st := range c.members {
		members = append(members, st.member)
	}
	successor := RankSuccessor(members, excludeChief)
	if successor == "" {
		return "", Term{}, false
	}
	return successor, c.current.Term.NextNormal(), true
}

// electDegraded derives the successor from the last verified
// snapshot (node perspective). It returns false when there is no
// verified snapshot or no eligible successor.
func (c *Coordinator) electDegraded() (string, Term, bool) {
	if !c.haveSnapshot {
		return "", Term{}, false
	}
	successor := RankSuccessor(c.lastSnapshot.Table.Members, c.current.ChiefID)
	if successor == "" {
		return "", Term{}, false
	}
	return successor, DegradedFrom(c.lastSnapshot.Table.Term), true
}

// installDegradedTable installs the degraded table for a takeover by
// this node: same membership and weights as the snapshot, new
// degraded term, this node as chief, version reset to 1 for the new
// term. Weight churn on handover is forbidden (§6.7 step 3): the
// table is the snapshot's table, re-termed.
func (c *Coordinator) installDegradedTable(term Term, chiefID string) {
	t := c.lastSnapshot.Table.Clone()
	t.Term = term
	t.Version = 1
	t.ChiefID = chiefID
	c.current = t
	c.syncMembersFromTable(t)
}

// PublishTable computes the next table for the chief to publish:
// same membership, weights recomputed from the latest reported
// capacities via the node-level chooser math, term unchanged,
// version bumped. Only the current chief may publish; anything
// else is refused. The caller delivers the table (via the mother
// when reachable, peer-to-peer otherwise).
func (c *Coordinator) PublishTable() (Table, error) {
	if !c.IsChief() {
		return Table{}, errors.New("only the current chief may publish the membership table")
	}
	t := c.current.Clone()
	t.Version++
	t.Weights = ComputeWeights(tableMembers(t))
	return t, nil
}

// AddMember admits a member to the enforced table (mother
// perspective only). Admission follows registry authentication —
// the caller has already verified the node's session key — never
// self-assertion. The new member starts ACTIVE with the next
// tenure sequence (newest) and zero weight until its first
// heartbeat reports capacity. The change goes through ApplyTable
// (equal term, version bumped, same chief), so the term rule stays
// the single gate. It returns false when the member is already
// present or the caller is not the mother.
func (c *Coordinator) AddMember(m Member) bool {
	if !c.isMother {
		return false
	}
	for _, existing := range c.current.Members {
		if existing.ID == m.ID {
			return false
		}
	}
	var maxTenure uint64
	for _, existing := range c.current.Members {
		if existing.TenureSeq > maxTenure {
			maxTenure = existing.TenureSeq
		}
	}
	m.State = StateActive
	m.TenureSeq = maxTenure + 1
	t := c.current.Clone()
	t.Members = append(t.Members, m)
	if t.Weights == nil {
		t.Weights = make(map[string]float64, len(t.Members))
	}
	t.Weights[m.ID] = 0
	t.Version++
	return c.ApplyTable(t)
}

// EnsureChief names a chief when the table has none (mother
// perspective only): the deterministic ranking over the live member
// view, issued as a NEW term (T1 for a table that never had a
// term, otherwise the next normal term — a chief change at equal
// term is refused by the term rule, so the term must move),
// version reset to 1 for the new term, via ApplyTable. The first
// chief is selected the same way every successor is — no special
// case, no voting. It returns false when a chief already exists,
// no member is eligible, or the caller is not the mother.
func (c *Coordinator) EnsureChief() bool {
	if !c.isMother || c.current.ChiefID != "" {
		return false
	}
	members := make([]Member, 0, len(c.members))
	for _, st := range c.members {
		members = append(members, st.member)
	}
	chief := RankSuccessor(members, "")
	if chief == "" {
		return false
	}
	t := c.current.Clone()
	t.ChiefID = chief
	if t.Term.IsZero() {
		t.Term = Term{Number: 1}
	} else {
		t.Term = t.Term.NextNormal()
	}
	t.Version = 1
	return c.ApplyTable(t)
}

// PublishMotherTable computes the next mother-issued table:
// membership and live liveness/capacity folded from heartbeats,
// weights recomputed via ComputeWeights, term unchanged, version
// bumped. Only the mother perspective may publish; a node publishes
// through PublishTable (chief-only). The caller delivers the table
// (heartbeat replies carry it to nodes).
func (c *Coordinator) PublishMotherTable() (Table, error) {
	if !c.isMother {
		return Table{}, errors.New("only the mother may publish the membership table")
	}
	t := c.current.Clone()
	for i := range t.Members {
		if st, ok := c.members[t.Members[i].ID]; ok {
			t.Members[i].State = st.member.State
			t.Members[i].CapacityBps = st.member.CapacityBps
			t.Members[i].Loss = st.member.Loss
			t.Members[i].LegRTTMs = st.member.LegRTTMs
			t.Members[i].LegOK = st.member.LegOK
			t.Members[i].TenureSeq = st.member.TenureSeq
		}
	}
	t.Version++
	t.Weights = ComputeWeights(t.Members)
	return t, nil
}

// tableMembers extracts the member list for weight computation.
func tableMembers(t Table) []Member { return t.Members }

// ComputeWeights computes capacity-share weights for members using
// the node-level chooser math (capacity × loss discount × RTT
// discount; zero for excluded/collapsed/unreachable members).
// Members in non-ACTIVE states weigh zero: they take no new
// streams. The result is keyed by member ID.
func ComputeWeights(members []Member) map[string]float64 {
	caps := make([]multisession.NodeCapacity, 0, len(members))
	for _, m := range members {
		caps = append(caps, multisession.NodeCapacity{
			ID:          m.ID,
			CapacityBps: m.CapacityBps,
			Loss:        m.Loss,
			LegRTTMs:    m.LegRTTMs,
			LegOK:       m.LegOK,
			Excluded:    m.State != StateActive,
		})
	}
	ws := multisession.NodeWeights(caps)
	out := make(map[string]float64, len(members))
	for i, m := range members {
		out[m.ID] = ws[i]
	}
	return out
}

// StepDown relinquishes the chief role for this node: it clears the
// local chief claim and reports the event. The mother elects the
// successor on the step-down message (no 60 s wait); this method
// only models the local half. Calling it when not chief is a no-op
// returning false.
func (c *Coordinator) StepDown() bool {
	if !c.IsChief() {
		return false
	}
	c.current.ChiefID = ""
	c.degradedChief = false
	return true
}

// RequestReElection enforces the §6.6 operator rate limit: at most
// one forced re-election per 5 minutes. It returns nil when the
// request is allowed (and records it) or an error naming the wait.
func (c *Coordinator) RequestReElection(now time.Time) error {
	if !c.lastReElection.IsZero() && now.Sub(c.lastReElection) < 5*time.Minute {
		return fmt.Errorf("forced re-election rate-limited: wait %s", 5*time.Minute-now.Sub(c.lastReElection))
	}
	c.lastReElection = now
	return nil
}

// ErrNoSnapshotKey is returned when degraded derivation is attempted
// without a snapshot verification key.
var ErrNoSnapshotKey = errors.New("no snapshot verification key: degraded derivation disabled")

// SnapshotKeyFingerprint returns the first 8 hex chars of the SHA-256
// of the snapshot key, for logs. It never exposes the key.
func (c *Coordinator) SnapshotKeyFingerprint() string {
	if len(c.snapshotKey) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.snapshotKey)
	return hex.EncodeToString(sum[:])[:8]
}
