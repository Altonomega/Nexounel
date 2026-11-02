// ==============================================================================
// Nexounel — derived from the CottenDNS core (MIT; see NOTICE).
// ==============================================================================
// shipped_templates_test.go — guards the sample configs shipped in
// configs/ (nexounel-server.toml / nexounel-node.toml). They must parse
// cleanly through the real loaders and expose the Phase 1 knobs, so a
// fresh install always carries them.
// ==============================================================================

package config

import (
	"path/filepath"
	"testing"
)

func shippedConfig(name string) string {
	// This test file lives in internal/config; the samples are two levels
	// up, under configs/.
	return filepath.Join("..", "..", "configs", name)
}

func TestShippedServerTemplateParsesWithFeatureKnobs(t *testing.T) {
	cfg, err := LoadServerConfig(shippedConfig("nexounel-server.toml"))
	if err != nil {
		t.Fatalf("nexounel-server.toml failed to load: %v", err)
	}
	// AES-GCM-only: the shipped server must use the strongest method.
	if cfg.DataEncryptionMethod != 5 {
		t.Errorf("server DATA_ENCRYPTION_METHOD = %d, want AES-256-GCM method 5", cfg.DataEncryptionMethod)
	}
	if cfg.FECBlockSize <= 0 || cfg.FECParity <= 0 {
		t.Errorf("FEC defaults not finalized: block=%d parity=%d", cfg.FECBlockSize, cfg.FECParity)
	}
	if cfg.FECBlockSize+cfg.FECParity > 256 {
		t.Errorf("FEC shard total exceeds 256: block=%d parity=%d", cfg.FECBlockSize, cfg.FECParity)
	}
	if cfg.MaxPacketSize != 4096 {
		t.Errorf("MAX_PACKET_SIZE = %d, want DNS-sized 4096-byte ingress buffers", cfg.MaxPacketSize)
	}
	if cfg.MaxIngressQueueBytes != 64*1024*1024 {
		t.Errorf("MAX_INGRESS_QUEUE_BYTES = %d, want 64 MiB", cfg.MaxIngressQueueBytes)
	}
	// Phase 1 keys: node registry + forward-port allowlist.
	if cfg.NodeRegistryFile == "" {
		t.Error("NODE_REGISTRY_FILE is empty in the shipped server template")
	}
	lo, hi, ok, err := cfg.ForwardPortRangeBounds()
	if err != nil || !ok || lo != 10101 || hi != 10110 {
		t.Errorf("FORWARD_PORT_RANGE bounds = (%d, %d, %v, %v), want (10101, 10110, true, nil)", lo, hi, ok, err)
	}
	if len(cfg.Domain) == 0 {
		t.Error("DOMAIN is empty in the shipped server template")
	}
}

func TestLegacyServerPacketBufferIsClampedOnUpgrade(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.MaxPacketSize = 65535
	finalized, err := finalizeServerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if finalized.MaxPacketSize != 4096 {
		t.Fatalf("legacy MAX_PACKET_SIZE was not clamped: got %d want 4096", finalized.MaxPacketSize)
	}
}

func TestShippedNodeTemplateParses(t *testing.T) {
	cfg, err := LoadClientConfig(shippedConfig("nexounel-node.toml"))
	if err != nil {
		t.Fatalf("nexounel-node.toml failed to load: %v", err)
	}
	if cfg.DataEncryptionMethod != 5 {
		t.Errorf("node DATA_ENCRYPTION_METHOD = %d, want AES-256-GCM method 5", cfg.DataEncryptionMethod)
	}
	if cfg.NodeID == "" {
		t.Error("NODE_ID is empty in the shipped node template")
	}
	if cfg.NodeKeyFile == "" {
		t.Error("NODE_KEY_FILE is empty in the shipped node template")
	}
	if !cfg.MultiSessionEnabled {
		t.Error("MULTISESSION_ENABLED should default true in the shipped node template")
	}
	if cfg.CapacityMargin != 0.95 {
		t.Errorf("CAPACITY_MARGIN = %v, want 0.95", cfg.CapacityMargin)
	}
	lo, hi, ok, err := cfg.ForwardRangeBounds()
	if err != nil || !ok || lo != 10101 || hi != 10110 {
		t.Errorf("FORWARD_RANGE bounds = (%d, %d, %v, %v), want (10101, 10110, true, nil)", lo, hi, ok, err)
	}
	if cfg.ProtocolType != "TCP" {
		t.Errorf("PROTOCOL_TYPE = %q, want TCP (multi-session forward mode)", cfg.ProtocolType)
	}
}

func TestClientConfigNodeKeyFileReplacesInlineKey(t *testing.T) {
	resolvers, err := filepath.Abs(shippedConfig("client_resolvers.txt"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := defaultClientConfig()
	cfg.ResolversFilePath = resolvers
	cfg.EncryptionKey = ""
	cfg.NodeKeyFile = "node.key"
	cfg.Domains = []string{"tunnel.example.com"}
	if _, err := finalizeClientConfig(cfg); err != nil {
		t.Fatalf("node-key config without ENCRYPTION_KEY should finalize: %v", err)
	}

	cfg.NodeKeyFile = ""
	if _, err := finalizeClientConfig(cfg); err == nil {
		t.Fatal("config with neither ENCRYPTION_KEY nor NODE_KEY_FILE should fail")
	}
}

func TestClientConfigRejectsBadForwardRange(t *testing.T) {
	resolvers, err := filepath.Abs(shippedConfig("client_resolvers.txt"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := defaultClientConfig()
	cfg.ResolversFilePath = resolvers
	cfg.EncryptionKey = "test-key"
	cfg.Domains = []string{"tunnel.example.com"}
	cfg.ForwardRange = "10010-10001"
	if _, err := finalizeClientConfig(cfg); err == nil {
		t.Fatal("reversed FORWARD_RANGE should fail validation")
	}
	cfg.ForwardRange = "1-70000"
	if _, err := finalizeClientConfig(cfg); err == nil {
		t.Fatal("out-of-range FORWARD_RANGE should fail validation")
	}
}
