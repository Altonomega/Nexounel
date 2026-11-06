// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Tests for the scale-audit cache fast start (F1a) and the measured-MTU
// pass-through (F1c). These tests pin the wiring only: resolver-list
// union, pre-fill values, and flags. Live probing (verification against a
// real resolver, full scans) is deliberately not exercised here — the
// sandbox blocks UDP loopback — and reuses the existing probe machinery
// verbatim.
// ==============================================================================

package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/config"
	"github.com/Altonomega/Nexounel/core/internal/multisession"
	"github.com/Altonomega/Nexounel/core/internal/security"
)

const scaleAuditTestKey = "0123456789abcdef0123456789abcdef"

func writeScaleAuditTestConfig(t *testing.T, dir string) (configPath, resolversPath string) {
	t.Helper()
	logDir := filepath.Join(dir, "logs")
	configPath = filepath.Join(dir, "node.toml")
	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "TCP"
DOMAINS = ["a.example.com"]
DATA_ENCRYPTION_METHOD = 5
ENCRYPTION_KEY = "`+scaleAuditTestKey+`"
LOG_DIR = "`+logDir+`"
MIN_UPLOAD_MTU = 40
MAX_UPLOAD_MTU = 200
MIN_DOWNLOAD_MTU = 100
MAX_DOWNLOAD_MTU = 4000
`), 0o644); err != nil {
		t.Fatal(err)
	}
	resolversPath = filepath.Join(dir, "resolvers.txt")
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return configPath, resolversPath
}

func findScaleAuditConnection(t *testing.T, c *Client, resolver, domain string) *Connection {
	t.Helper()
	for i := range c.connections {
		if c.connections[i].Resolver == resolver && c.connections[i].Domain == domain {
			return &c.connections[i]
		}
	}
	t.Fatalf("no connection for %s/%s (have %d connections)", resolver, domain, len(c.connections))
	return nil
}

func TestBootstrapFromLogsScopesCacheToConfiguredList(t *testing.T) {
	dir := t.TempDir()
	configPath, resolversPath := writeScaleAuditTestConfig(t, dir)
	now := time.Now().UTC()
	entries := []ResolverCacheEntry{
		{IP: "8.8.8.8", Port: 53, Domain: "a.example.com", UploadMTU: 110, DownloadMTU: 2000, LastSeen: now},
		{IP: "9.9.9.9", Port: 53, Domain: "a.example.com", UploadMTU: 90, DownloadMTU: 1015, LastSeen: now},
		// Duplicate of the first entry: dedup must keep one row.
		{IP: "8.8.8.8", Port: 53, Domain: "a.example.com", UploadMTU: 110, DownloadMTU: 2000, LastSeen: now},
	}
	c, err := BootstrapFromLogs(configPath, entries, config.ClientConfigOverrides{ResolversFilePath: &resolversPath})
	if err != nil {
		t.Fatal(err)
	}
	defer c.closeResolverCacheLog()

	// Scoped to the configured list (8.8.8.8, 1.1.1.1): the cache-only
	// resolver 9.9.9.9 must NOT expand the fleet, or a deliberate prune
	// (e.g. to a capacity-chosen subset) is silently undone by stale
	// cache entries. Nothing configured is dropped.
	if len(c.cfg.Resolvers) != 2 {
		t.Fatalf("scoped resolver list = %+v, want 2 entries", c.cfg.Resolvers)
	}
	if c.cfg.Resolvers[0].IP != "8.8.8.8" || c.cfg.Resolvers[1].IP != "1.1.1.1" {
		t.Fatalf("unexpected scoped order: %+v", c.cfg.Resolvers)
	}
	if !c.connectionsHavePreknownMTU {
		t.Fatal("BootstrapFromLogs must set connectionsHavePreknownMTU")
	}
	if !c.logBasedMTUVerify {
		t.Fatal("LOG_BASED_MTU_VERIFY defaults to true and must be honored")
	}

	cached := findScaleAuditConnection(t, c, "8.8.8.8", "a.example.com")
	if !cached.IsValid || cached.UploadMTUBytes != 110 || cached.DownloadMTUBytes != 2000 {
		t.Fatalf("cached connection not pre-filled: %+v", *cached)
	}
	uncached := findScaleAuditConnection(t, c, "1.1.1.1", "a.example.com")
	// Fresh connections default to IsValid=true with zero MTUs (the scan
	// resets them); "unscanned" is defined by the zero MTUs, matching the
	// connectionsWithoutPreknownMTU predicate.
	if uncached.UploadMTUBytes != 0 || uncached.DownloadMTUBytes != 0 {
		t.Fatalf("uncached connection must stay unscanned: %+v", *uncached)
	}
	// The cache-only resolver must not be in the connection map at all.
	for i := range c.connections {
		if c.connections[i].Resolver == "9.9.9.9" {
			t.Fatal("cache-only resolver 9.9.9.9 must not be in the fleet")
		}
	}
}

// Unit test for the scoping helper: with a configured fleet, only entries
// for configured resolvers are kept; with no configured fleet, all entries
// are kept (the cache is the only fleet source).
func TestScopeCacheEntriesToConfigured(t *testing.T) {
	now := time.Now().UTC()
	entries := []ResolverCacheEntry{
		{IP: "8.8.8.8", Port: 53, Domain: "a.example.com", UploadMTU: 110, DownloadMTU: 2000, LastSeen: now},
		{IP: "9.9.9.9", Port: 53, Domain: "a.example.com", UploadMTU: 90, DownloadMTU: 1015, LastSeen: now},
		{IP: "1.1.1.1", Port: 53, Domain: "a.example.com", UploadMTU: 110, DownloadMTU: 2000, LastSeen: now},
	}
	configured := []config.ResolverAddress{{IP: "8.8.8.8", Port: 53}, {IP: "1.1.1.1", Port: 53}}
	scoped := scopeCacheEntriesToConfigured(entries, configured)
	if len(scoped) != 2 {
		t.Fatalf("scoped entries = %d, want 2 (8.8.8.8 and 1.1.1.1)", len(scoped))
	}
	for _, e := range scoped {
		if e.IP == "9.9.9.9" {
			t.Fatal("cache-only resolver 9.9.9.9 must be scoped out")
		}
	}
	// Empty configured list: the cache is the fleet, keep everything.
	unscoped := scopeCacheEntriesToConfigured(entries, nil)
	if len(unscoped) != 3 {
		t.Fatalf("empty configured list: entries = %d, want 3", len(unscoped))
	}
	// A port mismatch is a different resolver and must be scoped out.
	otherPort := []config.ResolverAddress{{IP: "8.8.8.8", Port: 5353}}
	if got := scopeCacheEntriesToConfigured(entries, otherPort); len(got) != 0 {
		t.Fatalf("port-mismatched entry must be scoped out, got %d", len(got))
	}
}

// When no cache entry matches the configured fleet, there is nothing to
// fast-start from, so the plain Bootstrap (full probe) runs instead.
func TestBootstrapFromLogsNoCacheMatchFallsBack(t *testing.T) {
	dir := t.TempDir()
	configPath, resolversPath := writeScaleAuditTestConfig(t, dir)
	now := time.Now().UTC()
	entries := []ResolverCacheEntry{
		{IP: "9.9.9.9", Port: 53, Domain: "a.example.com", UploadMTU: 90, DownloadMTU: 1015, LastSeen: now},
		{IP: "4.4.4.4", Port: 53, Domain: "a.example.com", UploadMTU: 90, DownloadMTU: 1015, LastSeen: now},
	}
	c, err := BootstrapFromLogs(configPath, entries, config.ClientConfigOverrides{ResolversFilePath: &resolversPath})
	if err != nil {
		t.Fatal(err)
	}
	defer c.closeResolverCacheLog()
	if c.connectionsHavePreknownMTU {
		t.Fatal("no cache match must fall back to the plain Bootstrap path")
	}
	if len(c.cfg.Resolvers) != 2 {
		t.Fatalf("fallback resolver list = %+v, want the 2 file resolvers", c.cfg.Resolvers)
	}
}

func TestBootstrapFromLogsEmptyEntriesFallsBack(t *testing.T) {
	dir := t.TempDir()
	configPath, resolversPath := writeScaleAuditTestConfig(t, dir)
	c, err := BootstrapFromLogs(configPath, nil, config.ClientConfigOverrides{ResolversFilePath: &resolversPath})
	if err != nil {
		t.Fatal(err)
	}
	defer c.closeResolverCacheLog()
	if c.connectionsHavePreknownMTU {
		t.Fatal("empty cache must fall back to the plain Bootstrap path")
	}
	if len(c.cfg.Resolvers) != 2 {
		t.Fatalf("fallback resolver list = %+v, want the 2 file resolvers", c.cfg.Resolvers)
	}
}

func TestBootstrapWithMeasuredMTUsPrefills(t *testing.T) {
	dir := t.TempDir()
	configPath, resolversPath := writeScaleAuditTestConfig(t, dir)
	measured := []multisession.ProbeResult{
		{Resolver: "8.8.8.8", Port: 53, UploadMTU: 110, DownloadMTU: 2000, Loss: 0.05, Valid: true},
		// Invalid / zero-capacity entries must never pre-fill.
		{Resolver: "1.1.1.1", Port: 53, UploadMTU: 0, DownloadMTU: 0, Valid: false},
	}
	c, err := BootstrapWithMeasuredMTUs(configPath, config.ClientConfigOverrides{ResolversFilePath: &resolversPath}, measured)
	if err != nil {
		t.Fatal(err)
	}
	defer c.closeResolverCacheLog()

	if !c.connectionsHavePreknownMTU {
		t.Fatal("measured bootstrap must set connectionsHavePreknownMTU")
	}
	if c.logBasedMTUVerify {
		t.Fatal("measured bootstrap must trust seconds-old measurements (no verify re-probe)")
	}
	pre := findScaleAuditConnection(t, c, "8.8.8.8", "a.example.com")
	if !pre.IsValid || pre.UploadMTUBytes != 110 || pre.DownloadMTUBytes != 2000 {
		t.Fatalf("measured connection not pre-filled: %+v", *pre)
	}
	if pre.UploadMTULoss != 0.05 || pre.DownloadMTULoss != 0.05 {
		t.Fatalf("measured loss not carried through: up=%v down=%v", pre.UploadMTULoss, pre.DownloadMTULoss)
	}
	unmeasured := findScaleAuditConnection(t, c, "1.1.1.1", "a.example.com")
	if unmeasured.UploadMTUBytes != 0 || unmeasured.DownloadMTUBytes != 0 {
		t.Fatalf("invalid measurement must stay unscanned: %+v", *unmeasured)
	}
}

func TestPreknownMTUIndicesComplement(t *testing.T) {
	conns := []Connection{
		{IsValid: true, DownloadMTUBytes: 1000},
		{IsValid: false, DownloadMTUBytes: 1000},
		{IsValid: true, DownloadMTUBytes: 0},
		{IsValid: true, DownloadMTUBytes: 2000},
	}
	preknown := preknownMTUIndices(conns)
	without := connectionsWithoutPreknownMTU(conns)
	if len(preknown) != 2 || preknown[0] != 0 || preknown[1] != 3 {
		t.Fatalf("preknown indices = %v, want [0 3]", preknown)
	}
	if len(without) != 2 || without[0] != 1 || without[1] != 2 {
		t.Fatalf("without-preknown indices = %v, want [1 2]", without)
	}
	// Together they must partition the fleet exactly.
	seen := map[int]bool{}
	for _, i := range append(preknown, without...) {
		if seen[i] {
			t.Fatalf("index %d in both partitions", i)
		}
		seen[i] = true
	}
	if len(seen) != len(conns) {
		t.Fatalf("partitions cover %d of %d connections", len(seen), len(conns))
	}
}

func TestVerifyPreknownMTUsDeadResolver(t *testing.T) {
	codec, err := security.NewCodec(5, "verify-test-key")
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{
		cfg: config.ClientConfig{
			Domains:        []string{"tunnel.example.com"},
			MinUploadMTU:   100,
			MaxUploadMTU:   200,
			MinDownloadMTU: 1000,
			MaxDownloadMTU: 4000,
		},
		codec:          codec,
		mtuTestTimeout: 100 * time.Millisecond,
		connections: []Connection{{
			Domain:           "tunnel.example.com",
			Resolver:         "127.0.0.1",
			ResolverPort:     53,
			ResolverLabel:    "127.0.0.1:53",
			IsValid:          true,
			UploadMTUBytes:   110,
			DownloadMTUBytes: 2000,
		}},
	}
	// 127.0.0.1:53 has no listener in the sandbox: verification fails and
	// the connection is reset for a full re-probe.
	failed := c.verifyPreknownMTUs(context.Background(), []int{0})
	if len(failed) != 1 || failed[0] != 0 {
		t.Fatalf("dead resolver must fail verification: failed=%v", failed)
	}
	conn := c.connections[0]
	if conn.IsValid || conn.UploadMTUBytes != 0 || conn.DownloadMTUBytes != 0 {
		t.Fatalf("failed connection must be reset for a full probe: %+v", conn)
	}
}
