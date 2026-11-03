// ==============================================================================
// Nexounel — derived from the CottenDNS core (MIT; see NOTICE).
// ==============================================================================
// ARQ repair-experiment tests (docs/ARQ-PROTOTYPE.md). The experiment is
// one master flag: off means every experiment knob is inert, on means the
// per-tick retransmit budget applies. NACK emission itself is covered by
// the existing gap tests in arq_test.go; these tests pin the budget only.
// ==============================================================================

package arq

import (
	"testing"
	"time"
)

func TestResolveRetransmitBudget(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want int
	}{
		{"off ignores explicit budget", Config{RetransmitBudget: 2}, 0},
		{"on defaults to 64", Config{ExperimentEnabled: true}, 64},
		{"on honors explicit budget", Config{ExperimentEnabled: true, RetransmitBudget: 32}, 32},
		{"on treats non-positive budget as default", Config{ExperimentEnabled: true, RetransmitBudget: -5}, 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveRetransmitBudget(tc.cfg); got != tc.want {
				t.Fatalf("resolveRetransmitBudget = %d, want %d", got, tc.want)
			}
		})
	}
}

// seedOverdueItems fills sndBuf with dispatched, long-overdue items. The
// ARQ is never Start()ed, so checkRetransmits runs synchronously in the
// test goroutine and no background loop interferes.
func seedOverdueItems(t *testing.T, a *ARQ, sns []uint16) {
	t.Helper()
	now := time.Now()
	for _, sn := range sns {
		a.sndBuf[sn] = &arqDataItem{
			Data:            []byte("payload"),
			CreatedAt:       now.Add(-time.Second),
			LastSentAt:      now.Add(-time.Second),
			Dispatched:      true,
			Retries:         0,
			CurrentRTO:      100 * time.Millisecond,
			SampleEligible:  true,
			CompressionType: 0,
		}
	}
}

func drainEnqueued(t *testing.T, enq *MockPacketEnqueuer) []uint16 {
	t.Helper()
	var sns []uint16
	for {
		select {
		case pkt := <-enq.Packets:
			sns = append(sns, pkt.sequenceNum)
		default:
			return sns
		}
	}
}

func TestRetransmitBudgetCapsPerTickOldestFirst(t *testing.T) {
	enq := NewMockPacketEnqueuer()
	a := NewARQ(1, 1, enq, nil, 1200, nil, Config{
		WindowSize:        5000,
		RTO:               0.1,
		MaxRTO:            0.5,
		ExperimentEnabled: true,
		RetransmitBudget:  2,
	})
	// sndNxt sits just past a wraparound: distances from sndNxt are
	// 65534->5, 65535->4, 0->3, 1->2, 2->1. Oldest-first must emit
	// 65534 and 65535, not the numerically smallest SNs.
	a.sndNxt = 3
	seedOverdueItems(t, a, []uint16{65534, 65535, 0, 1, 2})

	a.checkRetransmits()

	got := drainEnqueued(t, enq)
	if len(got) != 2 {
		t.Fatalf("enqueued %d packets, want 2 (budget): %v", len(got), got)
	}
	want := map[uint16]bool{65534: true, 65535: true}
	for _, sn := range got {
		if !want[sn] {
			t.Fatalf("enqueued SN %d, want only the two oldest {65534, 65535}: %v", sn, got)
		}
	}
}

func TestRetransmitBudgetOffEnqueuesEverything(t *testing.T) {
	enq := NewMockPacketEnqueuer()
	a := NewARQ(1, 1, enq, nil, 1200, nil, Config{
		WindowSize:       5000,
		RTO:              0.1,
		MaxRTO:           0.5,
		RetransmitBudget: 2, // inert: the experiment flag is off.
	})
	a.sndNxt = 10
	seedOverdueItems(t, a, []uint16{5, 6, 7, 8, 9})

	a.checkRetransmits()

	got := drainEnqueued(t, enq)
	if len(got) != 5 {
		t.Fatalf("enqueued %d packets, want all 5 (experiment off): %v", len(got), got)
	}
}

func TestRetransmitBudgetDefaultsTo64UnderExperiment(t *testing.T) {
	enq := NewMockPacketEnqueuer()
	a := NewARQ(1, 1, enq, nil, 1200, nil, Config{
		WindowSize:        5000,
		RTO:               0.1,
		MaxRTO:            0.5,
		ExperimentEnabled: true,
		// No explicit budget: the default of 64 applies.
	})
	sns := make([]uint16, 70)
	for i := range sns {
		sns[i] = uint16(i)
	}
	a.sndNxt = 100
	seedOverdueItems(t, a, sns)

	a.checkRetransmits()

	got := drainEnqueued(t, enq)
	if len(got) != 64 {
		t.Fatalf("enqueued %d packets, want the default budget of 64: got %d", len(got), len(got))
	}
	// The 64 survivors must be the oldest: SNs 0..63, not 6..69.
	for _, sn := range got {
		if sn >= 64 {
			t.Fatalf("enqueued SN %d, want only the oldest 64 (0..63)", sn)
		}
	}
}

func TestRetransmitBudgetDeferredItemsRetryNextTick(t *testing.T) {
	enq := NewMockPacketEnqueuer()
	a := NewARQ(1, 1, enq, nil, 1200, nil, Config{
		WindowSize:        5000,
		RTO:               0.1,
		MaxRTO:            0.5,
		ExperimentEnabled: true,
		RetransmitBudget:  1,
	})
	a.sndNxt = 10
	seedOverdueItems(t, a, []uint16{8, 9})

	a.checkRetransmits()
	if got := drainEnqueued(t, enq); len(got) != 1 || got[0] != 8 {
		t.Fatalf("first tick: got %v, want [8] (oldest only)", got)
	}
	// The deferred item is still overdue and still tracked; backdate
	// its RTO again (the first tick advanced it) and clear the hint
	// the same way the existing timer tests do.
	a.mu.Lock()
	a.sndBuf[9].LastSentAt = time.Now().Add(-time.Second)
	a.minRetransmitAt = time.Time{}
	a.mu.Unlock()

	a.checkRetransmits()
	if got := drainEnqueued(t, enq); len(got) != 1 || got[0] != 9 {
		t.Fatalf("second tick: got %v, want [9] (deferred item, no starvation)", got)
	}
}
