package panel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFetchServerHealth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "application/json") || r.URL.Path == "/healthz/details" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"status":"ok","version":"test","uptime_seconds":42,"warnings":["queue warning"],"monitoring":[{"name":"active_sessions","value":3,"type":"gauge","unit":"sessions"}],"transports":{"udp_up":true}}`)
			return
		}
		_, _ = fmt.Fprint(w, "ok\n")
	})
	mux.HandleFunc("/healthz/details", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"status":"ok","uptime_seconds":42,"warnings":["queue warning"],"monitoring":[{"name":"active_sessions","value":3,"type":"gauge","unit":"sessions"}],"transports":{"udp_up":true}}`)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "# TYPE x gauge\ncottendns_active_sessions 3\ncottendns_uptime_seconds 42\n")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	health := FetchServerHealth(context.Background(), addr, srv.Client())
	if !health.Up {
		t.Fatalf("server not up: %+v", health)
	}
	if health.Details == nil || health.Details.UptimeSeconds != 42 || len(health.Details.Monitoring) != 1 || health.Details.Monitoring[0].Value != 3 {
		t.Fatalf("details not parsed: %+v", health.Details)
	}
	if !health.Details.Transports.UDPUp || len(health.Details.Warnings) != 1 {
		t.Fatalf("transports/warnings not parsed: %+v", health.Details)
	}
	if !health.MetricsAvailable || health.MetricsValueCount != 2 {
		t.Fatalf("metrics not counted: %+v", health)
	}

	// Down server: closed listener.
	down := FetchServerHealth(context.Background(), "127.0.0.1:1", nil)
	if down.Up || down.Error == "" {
		t.Fatalf("down server reported up: %+v", down)
	}
	// Metrics endpoint absent: details still parsed, metrics unavailable.
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, "ok\n") })
	mux2.HandleFunc("/healthz/details", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","uptime_seconds":7}`)
	})
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	health2 := FetchServerHealth(context.Background(), strings.TrimPrefix(srv2.URL, "http://"), srv2.Client())
	if !health2.Up || health2.MetricsAvailable || health2.Details == nil {
		t.Fatalf("absent metrics mishandled: %+v", health2)
	}
}

func TestListRegistryNodesFingerprintOnly(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	key := "test-key-0123456789abcdef0123456789ab"
	content := "[[nodes]]\nid = \"node-1\"\nkey = \"" + key + "\"\n"
	if err := os.WriteFile(regPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes, err := ListRegistryNodes(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].ID != "node-1" || nodes[0].Fingerprint == "" || nodes[0].Fingerprint == key {
		t.Fatalf("unexpected node view: %+v", nodes)
	}
	if _, err := ListRegistryNodes(filepath.Join(dir, "missing.toml")); err == nil {
		t.Fatal("missing registry accepted")
	}
}

func TestParseResolverCacheLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "resolver_cache_20260101.log")
	content := "2026-01-01T00:00:00Z 8.8.8.8:53 tunnel.example.invalid UP=110 DOWN=1015\n" +
		"garbage line\n" +
		"2026-01-01T00:01:00Z 1.1.1.1:53 tunnel.example.invalid UP=110 DOWN=2130\n" +
		"2026-01-01T00:02:00Z 9.9.9.9:53 tunnel.example.invalid UP=90 DOWN=1015\n"
	if err := os.WriteFile(logPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	entries := ParseResolverCacheLog(logPath)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].IP != "1.1.1.1" || entries[0].DownloadMTU != 2130 {
		t.Fatalf("entries not sorted by download MTU: %+v", entries[0])
	}
	classes := groupResolverClasses(entries)
	if len(classes) != 2 || classes[0].Count != 1 || classes[1].Count != 2 || classes[1].UploadMTU != 90 {
		t.Fatalf("unexpected classes: %+v", classes)
	}
}

func TestTailServiceLogsRedactsAndHandlesMissing(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		if name != "journalctl" {
			t.Fatalf("unexpected command %q", name)
		}
		unit := args[1]
		if unit == "nexounel" {
			return "server started\npassword = test-key-secret\nplain line\n", nil
		}
		return "", fmt.Errorf("unit not found")
	}
	tails := TailServiceLogs(context.Background(), 10, runner)
	if !tails.ServerOK || tails.NodeOK {
		t.Fatalf("unexpected availability: %+v", tails)
	}
	for _, line := range tails.ServerLines {
		if strings.Contains(line, "test-key-secret") {
			t.Fatalf("secret line rendered: %q", line)
		}
	}
	if len(tails.ServerLines) != 2 {
		t.Fatalf("expected 2 server lines, got %v", tails.ServerLines)
	}
	// Missing journalctl binary: both unavailable.
	missing := func(ctx context.Context, name string, args ...string) (string, error) {
		return "", fmt.Errorf("executable file not found")
	}
	tails = TailServiceLogs(context.Background(), 10, missing)
	if tails.ServerOK || tails.NodeOK {
		t.Fatalf("missing journalctl reported available: %+v", tails)
	}
	_ = time.Now
}

// Scale-audit fix F2: resolver-fleet cap, totals, and file-identity cache.

func writePanelNodeConfig(t *testing.T, dir, logDir string) string {
	t.Helper()
	configPath := filepath.Join(dir, "node.toml")
	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "TCP"
DOMAINS = ["a.example.com"]
DATA_ENCRYPTION_METHOD = 5
ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"
LOG_DIR = "`+logDir+`"
MIN_UPLOAD_MTU = 40
MAX_UPLOAD_MTU = 200
MIN_DOWNLOAD_MTU = 100
MAX_DOWNLOAD_MTU = 4000
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func TestLoadNodeResolverHealthCapsEntriesKeepsTotals(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := writePanelNodeConfig(t, dir, logDir)

	// 250 entries across two download-MTU tiers; the top tier must win
	// the capped row list while the class totals cover all 250.
	var sb strings.Builder
	for i := 0; i < 250; i++ {
		down := 1015
		if i%2 == 0 {
			down = 3475
		}
		fmt.Fprintf(&sb, "2026-01-01T00:%02d:00Z 192.0.2.%d:53 tunnel.example.com UP=110 DOWN=%d\n", i%60, (i%250)+1, down)
	}
	logPath := filepath.Join(logDir, "resolver_cache_20260101_000000.log")
	if err := os.WriteFile(logPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	health := LoadNodeResolverHealth(configPath)
	if !health.Available {
		t.Fatalf("health unavailable: %q", health.Note)
	}
	if health.TotalEntries != 250 {
		t.Fatalf("TotalEntries = %d, want 250", health.TotalEntries)
	}
	if health.EntryTotal() != 250 {
		t.Fatalf("EntryTotal() = %d, want 250", health.EntryTotal())
	}
	if len(health.Entries) != MaxResolverHealthEntries {
		t.Fatalf("len(Entries) = %d, want cap %d", len(health.Entries), MaxResolverHealthEntries)
	}
	for _, e := range health.Entries {
		if e.DownloadMTU != 3475 {
			t.Fatalf("capped rows must be the top tier by download MTU, got DOWN=%d", e.DownloadMTU)
		}
	}
	classTotal := 0
	for _, c := range health.Classes {
		classTotal += c.Count
	}
	if classTotal != 250 {
		t.Fatalf("class totals cover %d resolvers, want 250", classTotal)
	}
	if len(health.Classes) != 2 {
		t.Fatalf("expected 2 MTU classes, got %d", len(health.Classes))
	}
}

func TestLoadNodeResolverHealthCachesByFileIdentity(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := writePanelNodeConfig(t, dir, logDir)
	logPath := filepath.Join(logDir, "resolver_cache_20260101_000000.log")

	// Two contents of identical byte length: only the file identity
	// (mtime/size) may distinguish them to the cache.
	first := "2026-01-01T00:00:00Z 192.0.2.1:53 tunnel.example.com UP=110 DOWN=1015\n"
	second := "2026-01-01T00:00:00Z 192.0.2.2:53 tunnel.example.com UP=110 DOWN=2015\n"
	if len(first) != len(second) {
		t.Fatalf("fixture lengths differ: %d vs %d", len(first), len(second))
	}
	if err := os.WriteFile(logPath, []byte(first), 0o644); err != nil {
		t.Fatal(err)
	}
	origInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	origMod := origInfo.ModTime()

	health := LoadNodeResolverHealth(configPath)
	if len(health.Entries) != 1 || health.Entries[0].IP != "192.0.2.1" {
		t.Fatalf("first load unexpected: %+v", health.Entries)
	}

	// Rewrite with different content but restore the original mtime and
	// keep the size: the cache must return the first content.
	if err := os.WriteFile(logPath, []byte(second), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(logPath, origMod, origMod); err != nil {
		t.Fatal(err)
	}
	health = LoadNodeResolverHealth(configPath)
	if len(health.Entries) != 1 || health.Entries[0].IP != "192.0.2.1" {
		t.Fatalf("same-identity rewrite must hit the cache: %+v", health.Entries)
	}

	// Bump the mtime: the cache must re-parse and see the new content.
	if err := os.Chtimes(logPath, origMod.Add(time.Hour), origMod.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	health = LoadNodeResolverHealth(configPath)
	if len(health.Entries) != 1 || health.Entries[0].IP != "192.0.2.2" || health.Entries[0].DownloadMTU != 2015 {
		t.Fatalf("mtime bump must invalidate the cache: %+v", health.Entries)
	}
}

func TestResolverHealthEntryTotalFallback(t *testing.T) {
	// Values built without TotalEntries (older callers, tests) keep
	// reporting the row count.
	h := ResolverHealth{Entries: []ResolverEntry{{}, {}}}
	if h.EntryTotal() != 2 {
		t.Fatalf("EntryTotal() = %d, want 2", h.EntryTotal())
	}
	h.TotalEntries = 250
	if h.EntryTotal() != 250 {
		t.Fatalf("EntryTotal() = %d, want 250", h.EntryTotal())
	}
}
