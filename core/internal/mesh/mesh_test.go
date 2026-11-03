package mesh

import (
	"sort"
	"testing"
	"time"
)

func TestCompareTerms(t *testing.T) {
	cases := []struct {
		a, b Term
		want int
	}{
		{Term{1, false}, Term{1, false}, 0},
		{Term{2, false}, Term{1, false}, 1},
		{Term{1, false}, Term{2, false}, -1},
		// Normal always beats degraded, regardless of number.
		{Term{1, false}, Term{999, true}, 1},
		{Term{999, true}, Term{1, false}, -1},
		{Term{2, true}, Term{1, true}, 1},
		{Term{0, false}, Term{1, true}, -1}, // zero term loses to everything real
		{Term{0, false}, Term{0, false}, 0},
	}
	for _, tc := range cases {
		if got := CompareTerms(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareTerms(%v, %v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	zeroTerm := Term{}
	if !zeroTerm.IsZero() {
		t.Error("zero Term must report IsZero")
	}
	gotDegraded := DegradedFrom(Term{Number: 4})
	wantDegraded := Term{Number: 5, Degraded: true}
	if gotDegraded != wantDegraded {
		t.Errorf("DegradedFrom(T4) = %v, want T5(degraded)", gotDegraded)
	}
}

func TestSnapshotSignVerify(t *testing.T) {
	key := []byte("snapshot-signing-key-for-tests-only")
	table := Table{
		Term:    Term{Number: 3},
		Version: 2,
		ChiefID: "node-a",
		Members: []Member{
			{ID: "node-a", State: StateActive, CapacityBps: 400000, TenureSeq: 1},
			{ID: "node-b", State: StateActive, CapacityBps: 200000, TenureSeq: 2},
		},
		Weights: map[string]float64{"node-a": 0.66, "node-b": 0.34},
	}
	snap, err := SignSnapshot(table, key)
	if err != nil {
		t.Fatalf("SignSnapshot: %v", err)
	}
	if !snap.Verify(key) {
		t.Error("freshly signed snapshot must verify")
	}
	if snap.Verify([]byte("wrong-key")) {
		t.Error("snapshot must not verify under a different key")
	}
	if _, err := SignSnapshot(table, nil); err == nil {
		t.Error("signing with an empty key must be refused")
	}
	if (Snapshot{}).Verify(key) {
		t.Error("empty snapshot must not verify")
	}
	// Tampering with any signed field breaks verification.
	tampered := snap
	tampered.Table.Weights["node-a"] = 0.99
	if tampered.Verify(key) {
		t.Error("tampered weights must break verification")
	}
	tampered = snap
	tampered.Table.Members[1].CapacityBps = 999999
	if tampered.Verify(key) {
		t.Error("tampered capacity must break verification")
	}
	tampered = snap
	tampered.Table.Term.Number = 4
	if tampered.Verify(key) {
		t.Error("tampered term must break verification")
	}
	// Member order must not matter: the canonical encoding sorts.
	reordered := table
	reordered.Members = []Member{table.Members[1], table.Members[0]}
	snap2, err := SignSnapshot(reordered, key)
	if err != nil {
		t.Fatalf("SignSnapshot reordered: %v", err)
	}
	if snap2.Signature != snap.Signature {
		t.Error("signature must be order-independent over members")
	}
}

func TestRankSuccessorDeterminism(t *testing.T) {
	members := []Member{
		{ID: "node-c", State: StateActive, CapacityBps: 300000, TenureSeq: 3},
		{ID: "node-a", State: StateActive, CapacityBps: 100000, TenureSeq: 1}, // lost chief
		{ID: "node-b", State: StateActive, CapacityBps: 500000, TenureSeq: 2},
		{ID: "node-d", State: StateSuspect, CapacityBps: 900000, TenureSeq: 1}, // suspect: ineligible
		{ID: "node-e", State: StateDown, CapacityBps: 900000, TenureSeq: 1},    // down: ineligible
	}
	// Longest tenure among eligible (excluding node-a) is node-b.
	if got := RankSuccessor(members, "node-a"); got != "node-b" {
		t.Errorf("RankSuccessor = %q, want node-b", got)
	}
	// Same set, shuffled order: same successor (no voting, no order dependence).
	shuffled := []Member{members[4], members[2], members[0], members[3], members[1]}
	if got := RankSuccessor(shuffled, "node-a"); got != "node-b" {
		t.Errorf("RankSuccessor shuffled = %q, want node-b", got)
	}
	// Tiebreak: equal tenure → higher capacity wins.
	tied := []Member{
		{ID: "node-x", State: StateActive, CapacityBps: 100, TenureSeq: 5},
		{ID: "node-y", State: StateActive, CapacityBps: 200, TenureSeq: 5},
	}
	if got := RankSuccessor(tied, ""); got != "node-y" {
		t.Errorf("capacity tiebreak: got %q, want node-y", got)
	}
	// Tiebreak: equal tenure and capacity → smallest ID wins.
	tied2 := []Member{
		{ID: "node-y", State: StateActive, CapacityBps: 200, TenureSeq: 5},
		{ID: "node-x", State: StateActive, CapacityBps: 200, TenureSeq: 5},
	}
	if got := RankSuccessor(tied2, ""); got != "node-x" {
		t.Errorf("ID tiebreak: got %q, want node-x", got)
	}
	if got := RankSuccessor(nil, ""); got != "" {
		t.Errorf("empty membership must yield no successor, got %q", got)
	}
	// Excluding node-b leaves node-a (longest tenure) as successor.
	if got := RankSuccessor(members, "node-b"); got != "node-a" {
		t.Errorf("excluding node-b: got %q, want node-a", got)
	}
}

func TestTableAcceptanceRules(t *testing.T) {
	c, err := NewCoordinator("node-b", false, Timeouts{}, nil)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	base := Table{Term: Term{Number: 3}, Version: 1, ChiefID: "node-a",
		Members: []Member{{ID: "node-a", State: StateActive, TenureSeq: 1}}}
	if !c.ApplyTable(base) {
		t.Fatal("first table must be accepted")
	}
	// Stale term rejected.
	if c.ApplyTable(Table{Term: Term{Number: 2}, Version: 9, ChiefID: "node-a"}) {
		t.Error("lower term must be rejected")
	}
	// Equal term, higher version, same chief: routine republication.
	if !c.ApplyTable(Table{Term: Term{Number: 3}, Version: 2, ChiefID: "node-a"}) {
		t.Error("equal term + higher version + same chief must be accepted")
	}
	// Equal term, higher version, DIFFERENT chief: rejected.
	if c.ApplyTable(Table{Term: Term{Number: 3}, Version: 3, ChiefID: "node-b"}) {
		t.Error("equal term + different chief must be rejected")
	}
	// Equal term, lower version: rejected.
	if c.ApplyTable(Table{Term: Term{Number: 3}, Version: 1, ChiefID: "node-a"}) {
		t.Error("equal term + lower version must be rejected")
	}
	// Degraded term with a huge number still loses to the normal term.
	if c.ApplyTable(Table{Term: Term{Number: 99, Degraded: true}, Version: 1, ChiefID: "node-b"}) {
		t.Error("degraded term must lose to a normal term regardless of number")
	}
	// Higher normal term wins and replaces the chief.
	if !c.ApplyTable(Table{Term: Term{Number: 4}, Version: 1, ChiefID: "node-b"}) {
		t.Error("higher normal term must be accepted")
	}
	if got := c.Current().ChiefID; got != "node-b" {
		t.Errorf("chief after term 4 = %q, want node-b", got)
	}
}

func TestCoordinatorLivenessTransitions(t *testing.T) {
	c, err := NewCoordinator("node-b", false, Timeouts{}, nil)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	t0 := time.Now()
	table := Table{Term: Term{Number: 1}, Version: 1, ChiefID: "node-a", Members: []Member{
		{ID: "node-a", State: StateActive, TenureSeq: 1},
		{ID: "node-b", State: StateActive, TenureSeq: 2},
	}}
	if !c.ApplyTable(table) {
		t.Fatal("table must apply")
	}
	// Unknown heartbeat ignored; DOWN heartbeat ignored.
	if c.NoteHeartbeat("node-zzz", 1, 0, 0, true, t0) {
		t.Error("heartbeat from an unknown member must be ignored")
	}
	for _, id := range []string{"node-a", "node-b"} {
		if !c.NoteHeartbeat(id, 1000, 0, 10, true, t0) {
			t.Fatalf("heartbeat for %s must apply", id)
		}
	}
	// 59 s of silence: nothing yet.
	if events := c.Evaluate(t0.Add(59 * time.Second)); len(events) != 0 {
		t.Errorf("no events expected before the suspect threshold, got %v", events)
	}
	// 60 s: both SUSPECT (one event each).
	events := c.Evaluate(t0.Add(60 * time.Second))
	if len(events) != 2 {
		t.Fatalf("expected 2 suspect events, got %v", events)
	}
	// Idempotent: re-evaluating at the same instant emits nothing new.
	if events := c.Evaluate(t0.Add(60 * time.Second)); len(events) != 0 {
		t.Errorf("re-evaluation must not repeat transitions, got %v", events)
	}
	// Heartbeat recovers node-b; node-a stays SUSPECT, then DOWN at 120 s.
	c.NoteHeartbeat("node-b", 1000, 0, 10, true, t0.Add(61*time.Second))
	events = c.Evaluate(t0.Add(120 * time.Second))
	if len(events) != 1 || events[0].Kind != EventNodeDown || events[0].NodeID != "node-a" {
		t.Errorf("expected node-a DOWN, got %v", events)
	}
	// DOWN members ignore heartbeats: no resurrection without a table.
	if c.NoteHeartbeat("node-a", 1000, 0, 10, true, t0.Add(121*time.Second)) {
		t.Error("heartbeat from a DOWN member must be ignored")
	}
}

func TestMotherElectionOnChiefLoss(t *testing.T) {
	c, err := NewCoordinator("", true, Timeouts{}, nil)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	t0 := time.Now()
	table := Table{Term: Term{Number: 2}, Version: 1, ChiefID: "node-a", Members: []Member{
		{ID: "node-a", State: StateActive, CapacityBps: 100, TenureSeq: 1},
		{ID: "node-b", State: StateActive, CapacityBps: 500, TenureSeq: 2},
		{ID: "node-c", State: StateActive, CapacityBps: 300, TenureSeq: 3},
	}}
	c.ApplyTable(table)
	for _, id := range []string{"node-a", "node-b", "node-c"} {
		c.NoteHeartbeat(id, 100, 0, 10, true, t0)
	}
	// Everyone but the chief keeps heartbeating; the chief goes silent.
	later := t0.Add(61 * time.Second)
	c.NoteHeartbeat("node-b", 500, 0, 10, true, later)
	c.NoteHeartbeat("node-c", 300, 0, 10, true, later)
	var found *Event
	for _, e := range c.Evaluate(later) {
		if e.Kind == EventChiefLost {
			ev := e
			found = &ev
		}
	}
	if found == nil {
		t.Fatal("expected a chief-lost election event")
	}
	if found.Successor != "node-b" {
		t.Errorf("successor = %q, want node-b (longest tenure among survivors)", found.Successor)
	}
	if found.Term != (Term{Number: 3}) {
		t.Errorf("election term = %v, want T3", found.Term)
	}
}

func TestMotherAddMemberAndEnsureChief(t *testing.T) {
	c, err := NewCoordinator("", true, Timeouts{}, nil)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	if !c.AddMember(Member{ID: "node-a", CapacityBps: 100}) {
		t.Fatal("AddMember node-a should succeed")
	}
	if !c.AddMember(Member{ID: "node-b", CapacityBps: 500}) {
		t.Fatal("AddMember node-b should succeed")
	}
	if c.AddMember(Member{ID: "node-a"}) {
		t.Error("AddMember must refuse a duplicate")
	}
	cur := c.Current()
	if len(cur.Members) != 2 || cur.Members[0].TenureSeq != 1 || cur.Members[1].TenureSeq != 2 {
		t.Errorf("tenure assignment wrong: %+v", cur.Members)
	}
	if cur.Members[0].State != StateActive || cur.Weights["node-a"] != 0 {
		t.Errorf("new member must start ACTIVE with zero weight: %+v weights=%v", cur.Members[0], cur.Weights)
	}
	if !c.EnsureChief() {
		t.Fatal("EnsureChief should name a chief")
	}
	if c.Current().ChiefID != "node-a" {
		t.Errorf("chief = %q, want node-a (longest tenure)", c.Current().ChiefID)
	}
	if c.EnsureChief() {
		t.Error("EnsureChief must be a no-op once a chief exists")
	}
	// Node perspective refuses both operations.
	node, _ := NewCoordinator("node-a", false, Timeouts{}, nil)
	if node.AddMember(Member{ID: "node-x"}) {
		t.Error("node perspective must not admit members")
	}
	if node.EnsureChief() {
		t.Error("node perspective must not elect a chief")
	}
	if _, err := node.PublishMotherTable(); err == nil {
		t.Error("node perspective must not publish mother tables")
	}
}

func TestMotherPublishFoldsHeartbeats(t *testing.T) {
	c, _ := NewCoordinator("", true, Timeouts{}, nil)
	c.AddMember(Member{ID: "node-a"})
	c.AddMember(Member{ID: "node-b"})
	now := time.Now()
	c.NoteHeartbeat("node-a", 100, 0.1, 20, true, now)
	c.NoteHeartbeat("node-b", 300, 0.0, 10, true, now)
	tbl, err := c.PublishMotherTable()
	if err != nil {
		t.Fatalf("PublishMotherTable: %v", err)
	}
	if tbl.Version != c.Current().Version+1 {
		t.Errorf("published version %d, want current+1", tbl.Version)
	}
	var a, b *Member
	for i := range tbl.Members {
		switch tbl.Members[i].ID {
		case "node-a":
			a = &tbl.Members[i]
		case "node-b":
			b = &tbl.Members[i]
		}
	}
	if a == nil || b == nil {
		t.Fatalf("members missing: %+v", tbl.Members)
	}
	if a.CapacityBps != 100 || b.CapacityBps != 300 {
		t.Errorf("capacities not folded: a=%v b=%v", a.CapacityBps, b.CapacityBps)
	}
	if tbl.Weights["node-a"] >= tbl.Weights["node-b"] {
		t.Errorf("weights must follow capacity: %v", tbl.Weights)
	}
	if tbl.Weights["node-a"]+tbl.Weights["node-b"] < 0.99 {
		t.Errorf("weights must sum to ~1: %v", tbl.Weights)
	}
	// Publishing does not itself change the enforced table (the
	// caller applies it through the normal path).
	if c.Current().Weights["node-b"] != 0 {
		t.Error("PublishMotherTable must not mutate the enforced table")
	}
}

func TestMotherElectionTableAppliesThroughTermRule(t *testing.T) {
	c, _ := NewCoordinator("", true, Timeouts{}, nil)
	c.ApplyTable(Table{Term: Term{Number: 2}, Version: 1, ChiefID: "node-a", Members: []Member{
		{ID: "node-a", State: StateActive, CapacityBps: 100, TenureSeq: 1},
		{ID: "node-b", State: StateActive, CapacityBps: 500, TenureSeq: 2},
	}})
	t0 := time.Now()
	c.NoteHeartbeat("node-a", 100, 0, 10, true, t0)
	c.NoteHeartbeat("node-b", 500, 0, 10, true, t0)
	later := t0.Add(61 * time.Second)
	c.NoteHeartbeat("node-b", 500, 0, 10, true, later)
	var found *Event
	for _, e := range c.Evaluate(later) {
		if e.Kind == EventChiefLost {
			ev := e
			found = &ev
		}
	}
	if found == nil {
		t.Fatal("expected chief-lost event")
	}
	elected := c.Current()
	elected.ChiefID = found.Successor
	elected.Term = found.Term
	elected.Version = 1
	if !c.ApplyTable(elected) {
		t.Fatal("election table (higher term) must apply")
	}
	if c.Current().ChiefID != "node-b" || c.Current().Term != (Term{Number: 3}) {
		t.Errorf("elected table wrong: %+v", c.Current())
	}
}

func TestDegradedDerivationDeterministic(t *testing.T) {
	key := []byte("snapshot-signing-key-for-tests-only")
	snapshotTable := Table{Term: Term{Number: 5}, Version: 4, ChiefID: "node-a", Members: []Member{
		{ID: "node-a", State: StateActive, CapacityBps: 100, TenureSeq: 1},
		{ID: "node-b", State: StateActive, CapacityBps: 500, TenureSeq: 2},
		{ID: "node-c", State: StateActive, CapacityBps: 300, TenureSeq: 3},
	}, Weights: map[string]float64{"node-a": 0.1, "node-b": 0.5, "node-c": 0.4}}
	snap, err := SignSnapshot(snapshotTable, key)
	if err != nil {
		t.Fatalf("SignSnapshot: %v", err)
	}

	newNodeCoordinator := func(ownID string, members []Member) *Coordinator {
		c, err := NewCoordinator(ownID, false, Timeouts{}, key)
		if err != nil {
			t.Fatalf("NewCoordinator: %v", err)
		}
		if !c.NoteSignedSnapshot(snap) {
			t.Fatal("verified snapshot must be accepted")
		}
		// Apply the snapshot table in a shuffled member order.
		shuffled := append([]Member(nil), members...)
		sort.Slice(shuffled, func(i, j int) bool { return shuffled[i].ID > shuffled[j].ID })
		tbl := snapshotTable.Clone()
		tbl.Members = shuffled
		if !c.ApplyTable(tbl) {
			t.Fatal("snapshot table must apply")
		}
		return c
	}

	t0 := time.Now()
	// Coordinator for node-b (the expected successor): takeover installs locally.
	cb := newNodeCoordinator("node-b", snapshotTable.Members)
	cb.NoteMotherAnnouncement(t0)
	cb.NoteChiefContact(t0)
	events := cb.Evaluate(t0.Add(121 * time.Second))
	var takeover *Event
	for i := range events {
		if events[i].Kind == EventDegradedTakeover {
			takeover = &events[i]
		}
	}
	if takeover == nil {
		t.Fatalf("expected degraded takeover, got %v", events)
	}
	if takeover.Successor != "node-b" || takeover.Term != (Term{Number: 6, Degraded: true}) {
		t.Errorf("takeover = successor %q term %v, want node-b T6(degraded)", takeover.Successor, takeover.Term)
	}
	if cur := cb.Current(); cur.ChiefID != "node-b" || cur.Term != takeover.Term || cur.Version != 1 {
		t.Errorf("installed degraded table = chief %q term %v version %d", cur.ChiefID, cur.Term, cur.Version)
	}
	// Weights must not churn on handover: same table, re-termed.
	if got := cb.Current().Weights["node-b"]; got != 0.5 {
		t.Errorf("handover weight node-b = %v, want 0.5 (snapshot weights preserved)", got)
	}

	// Coordinator for node-c: same snapshot, same derivation, but it
	// does NOT install (it is not the successor) — no voting, one answer.
	cc := newNodeCoordinator("node-c", snapshotTable.Members)
	cc.NoteMotherAnnouncement(t0)
	cc.NoteChiefContact(t0)
	events = cc.Evaluate(t0.Add(121 * time.Second))
	takeover = nil
	for i := range events {
		if events[i].Kind == EventDegradedTakeover {
			takeover = &events[i]
		}
	}
	if takeover == nil || takeover.Successor != "node-b" {
		t.Fatalf("node-c must derive the same successor node-b, got %v", events)
	}
	if cc.Current().ChiefID != "node-a" {
		t.Error("non-successor must keep enforcing the last table, not install a degraded one")
	}

	// An unverified snapshot is refused as derivation input.
	cbad, _ := NewCoordinator("node-b", false, Timeouts{}, key)
	if cbad.NoteSignedSnapshot(Snapshot{Table: snapshotTable, Signature: "deadbeef"}) {
		t.Error("forged snapshot must be refused")
	}
	// Without a snapshot key, degraded derivation is disabled.
	cnokey, _ := NewCoordinator("node-b", false, Timeouts{}, nil)
	if cnokey.NoteSignedSnapshot(snap) {
		t.Error("snapshot must not be accepted without a verification key")
	}
}

func TestDegradedLosesToMotherOnResync(t *testing.T) {
	key := []byte("snapshot-signing-key-for-tests-only")
	snapTable := Table{Term: Term{Number: 5}, Version: 1, ChiefID: "node-a", Members: []Member{
		{ID: "node-a", State: StateActive, TenureSeq: 1},
		{ID: "node-b", State: StateActive, TenureSeq: 2},
	}}
	snap, _ := SignSnapshot(snapTable, key)
	c, _ := NewCoordinator("node-b", false, Timeouts{}, key)
	c.NoteSignedSnapshot(snap)
	c.ApplyTable(snapTable)
	t0 := time.Now()
	c.NoteMotherAnnouncement(t0)
	c.NoteChiefContact(t0)
	c.Evaluate(t0.Add(121 * time.Second))
	if !c.Degraded() || !c.IsChief() {
		t.Fatal("node-b must be degraded chief after takeover")
	}
	// Mother returns with a fresh NORMAL term (lower number than the
	// degraded term's number is impossible here — mother terms always
	// advance past degraded ones; use T6 normal vs T6 degraded).
	motherTable := Table{Term: Term{Number: 6}, Version: 1, ChiefID: "node-a", Members: snapTable.Members}
	if !c.ApplyTable(motherTable) {
		t.Fatal("mother table must win over the degraded table")
	}
	if c.Degraded() || c.IsChief() {
		t.Error("degraded chief must step down without argument on mother resync")
	}
	if got := c.Current().ChiefID; got != "node-a" {
		t.Errorf("chief after resync = %q, want node-a", got)
	}
}

func TestStepDownAndReElectionRateLimit(t *testing.T) {
	c, _ := NewCoordinator("node-a", false, Timeouts{}, nil)
	if c.StepDown() {
		t.Error("step-down with no chief role must be a no-op")
	}
	c.ApplyTable(Table{Term: Term{Number: 1}, Version: 1, ChiefID: "node-a",
		Members: []Member{{ID: "node-a", State: StateActive, TenureSeq: 1}}})
	if !c.StepDown() {
		t.Error("chief step-down must succeed")
	}
	if c.IsChief() {
		t.Error("stepped-down node must no longer be chief")
	}
	t0 := time.Now()
	if err := c.RequestReElection(t0); err != nil {
		t.Fatalf("first forced re-election must be allowed: %v", err)
	}
	if err := c.RequestReElection(t0.Add(4 * time.Minute)); err == nil {
		t.Error("second forced re-election within 5 minutes must be rate-limited")
	}
	if err := c.RequestReElection(t0.Add(5*time.Minute + time.Second)); err != nil {
		t.Errorf("forced re-election after 5 minutes must be allowed: %v", err)
	}
}

func TestPublishTableChiefOnly(t *testing.T) {
	c, _ := NewCoordinator("node-b", false, Timeouts{}, nil)
	c.ApplyTable(Table{Term: Term{Number: 1}, Version: 1, ChiefID: "node-a", Members: []Member{
		{ID: "node-a", State: StateActive, CapacityBps: 300000, LegOK: true, TenureSeq: 1},
		{ID: "node-b", State: StateActive, CapacityBps: 100000, LegOK: true, TenureSeq: 2},
	}})
	if _, err := c.PublishTable(); err == nil {
		t.Error("non-chief must not publish tables")
	}
	c.ApplyTable(Table{Term: Term{Number: 2}, Version: 1, ChiefID: "node-b", Members: []Member{
		{ID: "node-a", State: StateActive, CapacityBps: 300000, LegOK: true, TenureSeq: 1},
		{ID: "node-b", State: StateActive, CapacityBps: 100000, LegOK: true, TenureSeq: 2},
	}})
	tbl, err := c.PublishTable()
	if err != nil {
		t.Fatalf("chief publish: %v", err)
	}
	if tbl.Version != 2 || tbl.Term.Number != 2 {
		t.Errorf("publish must bump version only: term %v version %d", tbl.Term, tbl.Version)
	}
	if tbl.Weights["node-a"] <= tbl.Weights["node-b"] {
		t.Errorf("weights must follow capacity: %v", tbl.Weights)
	}
	if tbl.Weights["node-a"]+tbl.Weights["node-b"] == 0 {
		t.Error("weights must be non-zero for healthy members")
	}
}

func TestTimeoutsValidation(t *testing.T) {
	if err := DefaultTimeouts().Validate(); err != nil {
		t.Errorf("defaults must validate: %v", err)
	}
	bad := DefaultTimeouts()
	bad.DownAfter = bad.SuspectAfter
	if err := bad.Validate(); err == nil {
		t.Error("down <= suspect must be rejected")
	}
	if _, err := NewCoordinator("x", false, Timeouts{HeartbeatInterval: -1}, nil); err == nil {
		t.Error("negative timeout must be rejected")
	}
}
