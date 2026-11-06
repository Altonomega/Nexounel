// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Tests for the probe-pass cache fast start (mesh milestone 2, step 1).
//
// Root cause pinned here: the multi-session probe pass
// (runMultiSession -> probeClient.RunInitialMTUTests) re-ran the full
// binary search over the whole fleet on every restart even when the
// client was built from a fresh resolver cache log (BootstrapFromLogs).
// The F1a fast start (verify cached capacities, re-probe only failures)
// lived in applyPreknownMTUsFromLog, which only the single-session Run
// loop called; the probe pass discarded the pre-filled MTUs in
// runFullMTUTests and paid the full scan at logs-mode parallelism (32)
// and retries (5): up to ~120s per degraded resolver
// (5 attempts x 2s timeout x 2 boundary checks x 6 query types), so a
// large, partly-stale fleet stalls startup for tens of minutes while the
// process looks idle (all exchanges deadline-bound, no deadlock).
//
// The harness is a fake resolver behind the queryTransportFactory seam:
// it answers MTU probes up to a per-test ceiling and drops anything
// larger, reproducing a capacity-limited resolver without a network
// (the sandbox blocks UDP loopback). Exchange counts discriminate the
// two paths exactly: verify costs 2 exchanges per resolver, the full
// binary search costs an order of magnitude more.
// ==============================================================================

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/config"
	DnsParser "github.com/Altonomega/Nexounel/core/internal/dnsparser"
	Enums "github.com/Altonomega/Nexounel/core/internal/enums"
	VpnProto "github.com/Altonomega/Nexounel/core/internal/vpnproto"
)

// probePassCeiling is the fake resolver's capacity: probes at or below
// the ceiling are answered, larger probes are dropped.
type probePassCeiling struct {
	upload   int
	download int
}

// probePassCountingTransport is a queryExchanger that counts exchanges
// per factory label and answers MTU probes up to the ceiling.
type probePassCountingTransport struct {
	fake  *probePassHarness
	label string
}

func (t probePassCountingTransport) exchange(query []byte, _ time.Duration) ([]byte, error) {
	return t.fake.answer(t.label, query)
}

func (probePassCountingTransport) Close() error { return nil }

// probePassHarness is the fake fleet: one ceiling for all resolvers,
// exchange counts per resolver label.
type probePassHarness struct {
	client  *Client
	ceiling probePassCeiling
	mu      sync.Mutex
	counts  map[string]int
}

func (h *probePassHarness) factory(label string) (queryExchanger, error) {
	return probePassCountingTransport{fake: h, label: label}, nil
}

func (h *probePassHarness) answer(label string, query []byte) ([]byte, error) {
	h.mu.Lock()
	if h.counts == nil {
		h.counts = make(map[string]int)
	}
	h.counts[label]++
	h.mu.Unlock()

	dns, err := DnsParser.ParsePacket(query)
	if err != nil {
		return nil, err
	}
	question := dns.Questions[0]
	var request VpnProto.Packet
	parsed := false
	for _, domain := range h.client.cfg.Domains {
		labels := strings.TrimSuffix(strings.TrimSuffix(question.Name, "."), "."+domain)
		request, err = VpnProto.ParseFromLabels(strings.ReplaceAll(labels, ".", ""), h.client.codec)
		if err == nil {
			parsed = true
			break
		}
	}
	if !parsed {
		return nil, errors.New("probePassHarness: cannot parse probe query")
	}
	size := len(request.Payload)
	responseType := uint8(Enums.PACKET_MTU_UP_RES)
	responseSize := 6
	if request.PacketType == Enums.PACKET_MTU_DOWN_REQ {
		size = int(binary.BigEndian.Uint16(request.Payload[1+mtuProbeCodeLength:]))
		responseType = Enums.PACKET_MTU_DOWN_RES
		responseSize = size
	}
	ceiling := h.ceiling.upload
	if request.PacketType == Enums.PACKET_MTU_DOWN_REQ {
		ceiling = h.ceiling.download
	}
	if size > ceiling {
		// Capacity ceiling: the probe is dropped, exactly like a
		// resolver that cannot carry this size.
		return nil, errors.New("probePassHarness: size exceeds ceiling")
	}
	payload := make([]byte, responseSize)
	copy(payload, request.Payload[1:1+mtuProbeCodeLength])
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(size))
	domain := h.client.cfg.Domains[0]
	return DnsParser.BuildEncryptedVPNResponsePacketMatchingQuery(query, question.Name, domain, VpnProto.Packet{
		SessionID: 255, PacketType: responseType, Payload: payload,
	}, false, true, true, h.client.codec)
}

func (h *probePassHarness) total() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	total := 0
	for _, n := range h.counts {
		total += n
	}
	return total
}

func (h *probePassHarness) maxPerLabel() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	max := 0
	for _, n := range h.counts {
		if n > max {
			max = n
		}
	}
	return max
}

func writeProbePassTestConfig(t *testing.T, dir string, resolvers []string) (configPath, resolversPath string) {
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
	if err := os.WriteFile(resolversPath, []byte(strings.Join(resolvers, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return configPath, resolversPath
}

func probePassTestEntries(now time.Time, upload, download int) []ResolverCacheEntry {
	entries := make([]ResolverCacheEntry, 0, 3)
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"} {
		entries = append(entries, ResolverCacheEntry{
			IP: ip, Port: 53, Domain: "a.example.com",
			UploadMTU: upload, DownloadMTU: download, LastSeen: now,
		})
	}
	return entries
}

func assertProbePassMTUs(t *testing.T, c *Client, upload, download int) {
	t.Helper()
	if len(c.connections) != 3 {
		t.Fatalf("want 3 connections, have %d", len(c.connections))
	}
	for i := range c.connections {
		conn := &c.connections[i]
		if !conn.IsValid {
			t.Fatalf("connection %d (%s): not valid after probe pass", i, conn.Resolver)
		}
		if conn.UploadMTUBytes != upload || conn.DownloadMTUBytes != download {
			t.Fatalf("connection %d (%s): MTUs up=%d down=%d, want up=%d down=%d",
				i, conn.Resolver, conn.UploadMTUBytes, conn.DownloadMTUBytes, upload, download)
		}
	}
}

// TestProbePassVerifiesCachedMTUsWithoutFullScan is the step-1
// regression test: with a fresh cache whose capacities the fleet still
// sustains, the probe pass must verify (2 exchanges per resolver) and
// must NOT run the full binary search. It FAILS before the fix (full
// scan: dozens of exchanges per resolver) and PASSES after.
func TestProbePassVerifiesCachedMTUsWithoutFullScan(t *testing.T) {
	dir := t.TempDir()
	configPath, resolversPath := writeProbePassTestConfig(t, dir, []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"})
	now := time.Now().UTC()
	c, err := BootstrapFromLogs(configPath, probePassTestEntries(now, 110, 2000),
		config.ClientConfigOverrides{ResolversFilePath: &resolversPath})
	if err != nil {
		t.Fatal(err)
	}
	defer c.closeResolverCacheLog()
	if !c.connectionsHavePreknownMTU {
		t.Fatal("BootstrapFromLogs must set connectionsHavePreknownMTU")
	}
	harness := &probePassHarness{client: c, ceiling: probePassCeiling{upload: 110, download: 2000}}
	c.queryTransportFactory = harness.factory

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.RunInitialMTUTests(ctx); err != nil {
		t.Fatalf("probe pass: %v", err)
	}
	assertProbePassMTUs(t, c, 110, 2000)
	// Verify costs exactly one probe per direction per resolver; the
	// full binary search costs an order of magnitude more. The bound of
	// 3 per label leaves slack for one extra probe; anything near the
	// binary-search cost fails.
	if got := harness.maxPerLabel(); got > 3 {
		t.Fatalf("probe pass used %d exchanges for one resolver (total %d): want verify-scale (<=3), got full-scan scale",
			got, harness.total())
	}
	if total := harness.total(); total == 0 {
		t.Fatal("probe pass exchanged nothing: verification was skipped, not run")
	}
}

// TestProbePassReprobesStaleCachedMTUs guards the other side of the
// fix: a cache entry the fleet no longer sustains must be re-measured,
// never trusted blindly.
func TestProbePassReprobesStaleCachedMTUs(t *testing.T) {
	dir := t.TempDir()
	configPath, resolversPath := writeProbePassTestConfig(t, dir, []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"})
	now := time.Now().UTC()
	c, err := BootstrapFromLogs(configPath, probePassTestEntries(now, 110, 2000),
		config.ClientConfigOverrides{ResolversFilePath: &resolversPath})
	if err != nil {
		t.Fatal(err)
	}
	defer c.closeResolverCacheLog()
	// The fleet shrank below the cached capacities: verification must
	// fail and the full search must re-measure the true ceiling.
	harness := &probePassHarness{client: c, ceiling: probePassCeiling{upload: 80, download: 1500}}
	c.queryTransportFactory = harness.factory

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.RunInitialMTUTests(ctx); err != nil {
		t.Fatalf("probe pass: %v", err)
	}
	assertProbePassMTUs(t, c, 80, 1500)
	if total := harness.total(); total <= 2*len(c.connections) {
		t.Fatalf("probe pass used only %d exchanges: stale entries were trusted without re-probing", total)
	}
}

// TestProbePassColdFleetRunsFullScan guards the no-cache path: without
// cached MTUs the probe pass must still measure the fleet from scratch.
func TestProbePassColdFleetRunsFullScan(t *testing.T) {
	dir := t.TempDir()
	configPath, resolversPath := writeProbePassTestConfig(t, dir, []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"})
	c, err := Bootstrap(configPath, config.ClientConfigOverrides{ResolversFilePath: &resolversPath})
	if err != nil {
		t.Fatal(err)
	}
	defer c.closeResolverCacheLog()
	if c.connectionsHavePreknownMTU {
		t.Fatal("plain Bootstrap must not set connectionsHavePreknownMTU")
	}
	harness := &probePassHarness{client: c, ceiling: probePassCeiling{upload: 110, download: 2000}}
	c.queryTransportFactory = harness.factory

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.RunInitialMTUTests(ctx); err != nil {
		t.Fatalf("probe pass: %v", err)
	}
	assertProbePassMTUs(t, c, 110, 2000)
}
