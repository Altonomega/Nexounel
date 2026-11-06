// ==============================================================================
// Nexounel — derived from the CottenDNS core (MIT; see NOTICE).
// ==============================================================================
// Offered-rate governor config tests (GLOBAL_OFFERED_QPS_MAX). The governor
// caps total offered DNS queries per second below the fleet's rate-limit
// knee (spike observed at ~3,000 q/s offered, below the ~5,100 q/s knee
// estimate). These tests pin the default and the clamps.
package config

import (
	"testing"
)

// The governor defaults on at 2000 q/s when unset, and an explicit value
// wins. 2000 sits a third below the ~3,000 q/s spike onset while leaving
// ample headroom over clean-operation rates.
func TestGlobalOfferedQPSMaxDefault(t *testing.T) {
	unset := defaultClientConfig()
	unset.GlobalOfferedQPSMax = 0
	got := finalizeTestClientConfig(t, unset)
	if got.GlobalOfferedQPSMax != 2000 {
		t.Fatalf("governor default: got=%v want=2000 q/s", got.GlobalOfferedQPSMax)
	}

	explicit := defaultClientConfig()
	explicit.GlobalOfferedQPSMax = 1200
	if got := finalizeTestClientConfig(t, explicit); got.GlobalOfferedQPSMax != 1200 {
		t.Fatalf("explicit governor cap: got=%v want=1200 q/s", got.GlobalOfferedQPSMax)
	}
}

// The governor is clamped to a sane range: a negative value becomes the
// default, and an absurd value is capped (a very large value is the
// documented way to effectively disable it).
func TestGlobalOfferedQPSMaxClamp(t *testing.T) {
	negative := defaultClientConfig()
	negative.GlobalOfferedQPSMax = -5
	if got := finalizeTestClientConfig(t, negative); got.GlobalOfferedQPSMax != 2000 {
		t.Fatalf("negative governor cap: got=%v want=2000 (default)", got.GlobalOfferedQPSMax)
	}

	huge := defaultClientConfig()
	huge.GlobalOfferedQPSMax = 1000000
	if got := finalizeTestClientConfig(t, huge); got.GlobalOfferedQPSMax != 100000 {
		t.Fatalf("huge governor cap: got=%v want=100000 (clamped)", got.GlobalOfferedQPSMax)
	}
}

// The governor must NOT fold into QueryRateLimited(): it paces the offered
// rate only and must not force duplication to 1 or disable session-init
// racing (those are the legacy per-network caps' side effects).
func TestGovernorDoesNotForceDuplicationToOne(t *testing.T) {
	got := finalizeTestClientConfig(t, defaultClientConfig())
	if got.QueryRateLimited() {
		t.Fatal("governor alone must not count as rate-limited (it must not force dup=1)")
	}
	if got.UploadPacketDuplicationCount != 3 {
		t.Fatalf("upload duplication with governor only: got=%d want=3 (unchanged)", got.UploadPacketDuplicationCount)
	}
	if got.DownloadPacketDuplicationCount != 7 {
		t.Fatalf("download duplication with governor only: got=%d want=7 (unchanged)", got.DownloadPacketDuplicationCount)
	}
}
