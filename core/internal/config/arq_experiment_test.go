// ==============================================================================
// Nexounel — derived from the CottenDNS core (MIT; see NOTICE).
// ==============================================================================
// ARQ repair-experiment config tests (docs/ARQ-PROTOTYPE.md). The
// experiment is one master flag; these tests pin what finalize does
// with it: the server NACK gap default, the inertness of the keys
// when the flag is off, and the clamps.
// ==============================================================================

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// finalizeTestClientConfig runs finalizeClientConfig with the
// loader-required scaffolding (encryption key, domain, resolvers
// file) so the tests pin only the experiment behavior.
func finalizeTestClientConfig(t *testing.T, cfg ClientConfig) ClientConfig {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.EncryptionKey = "secret"
	cfg.Domains = []string{"v.example.com"}
	cfg.ConfigDir = dir
	got, err := finalizeClientConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestFinalizeServerConfigExperimentNackGap(t *testing.T) {
	// Flag off (explicit): the historical default (server NACKs disabled).
	offCfg := defaultServerConfig()
	offCfg.ARQExperimentEnabled = false
	off, err := finalizeServerConfig(offCfg)
	if err != nil {
		t.Fatal(err)
	}
	if off.ARQDataNackMaxGap != 0 {
		t.Fatalf("experiment off: gap=%d want=0", off.ARQDataNackMaxGap)
	}

	// Flag on (the default), gap unset: the experiment default of 64.
	on := defaultServerConfig()
	if !on.ARQExperimentEnabled {
		t.Fatal("experiment flag must default on")
	}
	got, err := finalizeServerConfig(on)
	if err != nil {
		t.Fatal(err)
	}
	if got.ARQDataNackMaxGap != 64 {
		t.Fatalf("experiment on, gap unset: gap=%d want=64", got.ARQDataNackMaxGap)
	}

	// Flag on, gap explicit: the explicit value wins (subject to the
	// window/4 ceiling, which the default window of 2000 allows).
	explicit := defaultServerConfig()
	explicit.ARQExperimentEnabled = true
	explicit.ARQDataNackMaxGap = 32
	got, err = finalizeServerConfig(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if got.ARQDataNackMaxGap != 32 {
		t.Fatalf("experiment on, gap=32: gap=%d want=32", got.ARQDataNackMaxGap)
	}

	// Flag on, gap explicitly 0: indistinguishable from unset after
	// the defaults merge, so it means 64. This is the documented
	// sacrifice: turn the experiment off to force NACKs off.
	zero := defaultServerConfig()
	zero.ARQExperimentEnabled = true
	zero.ARQDataNackMaxGap = 0
	got, err = finalizeServerConfig(zero)
	if err != nil {
		t.Fatal(err)
	}
	if got.ARQDataNackMaxGap != 64 {
		t.Fatalf("experiment on, gap=0: gap=%d want=64 (documented)", got.ARQDataNackMaxGap)
	}
}

func TestFinalizeConfigExperimentBudgetClamps(t *testing.T) {
	server := defaultServerConfig()
	server.ARQExperimentEnabled = true
	server.ARQRetransmitBudget = 2000
	got, err := finalizeServerConfig(server)
	if err != nil {
		t.Fatal(err)
	}
	if got.ARQRetransmitBudget != 1024 {
		t.Fatalf("server budget clamp: got=%d want=1024", got.ARQRetransmitBudget)
	}

	server.ARQRetransmitBudget = -5
	got, err = finalizeServerConfig(server)
	if err != nil {
		t.Fatal(err)
	}
	if got.ARQRetransmitBudget != 0 {
		t.Fatalf("server negative budget: got=%d want=0", got.ARQRetransmitBudget)
	}

	client := defaultClientConfig()
	client.ARQExperimentEnabled = true
	client.ARQResendDuplicationCount = 99
	client.ARQAckNackDuplicationCount = -3
	client.ARQRetransmitBudget = 2000
	gotClient := finalizeTestClientConfig(t, client)
	if gotClient.ARQResendDuplicationCount != 8 {
		t.Fatalf("client resend dup clamp: got=%d want=8", gotClient.ARQResendDuplicationCount)
	}
	if gotClient.ARQAckNackDuplicationCount != 0 {
		t.Fatalf("client ack/nack dup clamp: got=%d want=0", gotClient.ARQAckNackDuplicationCount)
	}
	if gotClient.ARQRetransmitBudget != 1024 {
		t.Fatalf("client budget clamp: got=%d want=1024", gotClient.ARQRetransmitBudget)
	}
}

func TestFinalizeClientConfigExperimentDefaultsInert(t *testing.T) {
	// Default: the experiment is ON. The experiment keys keep their zero
	// (inherit/unlimited) meaning in the config through finalize; the
	// on-values (RESEND/ACK-NACK duplication 1, retransmit budget 64) are
	// resolved at use time, not by rewriting the keys.
	cfg := finalizeTestClientConfig(t, defaultClientConfig())
	if !cfg.ARQExperimentEnabled {
		t.Fatal("experiment flag must default on")
	}
	if cfg.ARQResendDuplicationCount != 0 || cfg.ARQAckNackDuplicationCount != 0 || cfg.ARQRetransmitBudget != 0 {
		t.Fatalf("experiment keys must default to 0: resend=%d acknack=%d budget=%d",
			cfg.ARQResendDuplicationCount, cfg.ARQAckNackDuplicationCount, cfg.ARQRetransmitBudget)
	}
	// The client NACK gap default is untouched by the experiment.
	if cfg.ARQDataNackMaxGap != 64 {
		t.Fatalf("client NACK gap default: got=%d want=64", cfg.ARQDataNackMaxGap)
	}

	// Explicitly off: the flag stays off and the keys stay inert (the
	// historical behaviour is preserved when the flag is off).
	offCfg := defaultClientConfig()
	offCfg.ARQExperimentEnabled = false
	off := finalizeTestClientConfig(t, offCfg)
	if off.ARQExperimentEnabled {
		t.Fatal("explicitly-off experiment flag must stay off")
	}
	if off.ARQResendDuplicationCount != 0 || off.ARQAckNackDuplicationCount != 0 || off.ARQRetransmitBudget != 0 {
		t.Fatalf("experiment off: keys must stay 0: resend=%d acknack=%d budget=%d",
			off.ARQResendDuplicationCount, off.ARQAckNackDuplicationCount, off.ARQRetransmitBudget)
	}
}
