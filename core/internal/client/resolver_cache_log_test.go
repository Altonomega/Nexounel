// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Tests for resolver cache log rotation (scale-audit fix F2).
// ==============================================================================

package client

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCacheLogFixture(t *testing.T, dir, name string, modTime time.Time) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("2026-01-01T00:00:00Z 8.8.8.8:53 tunnel.example.com UP=110 DOWN=1015\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatal(err)
	}
	return path
}

func countCacheLogs(t *testing.T, dir string) int {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "resolver_cache_*.log"))
	if err != nil {
		t.Fatal(err)
	}
	return len(files)
}

func TestPruneResolverCacheLogsKeepsNewestSeven(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	// Ages 0..9 days: the newest 7 (ages 0-6) survive; ages 7-9 are
	// beyond the retain count AND older than the grace period.
	for i := 0; i < 10; i++ {
		name := "resolver_cache_2026010" + string(rune('1'+i)) + "_000000.log"
		writeCacheLogFixture(t, dir, name, now.Add(-time.Duration(i)*24*time.Hour))
	}
	pruneResolverCacheLogs(dir, "")
	if got := countCacheLogs(t, dir); got != 7 {
		t.Fatalf("expected 7 retained logs, got %d", got)
	}
}

func TestPruneResolverCacheLogsNeverDeletesRecentBurst(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for i := 0; i < 10; i++ {
		name := "resolver_cache_2026010" + string(rune('1'+i)) + "_000000.log"
		writeCacheLogFixture(t, dir, name, now.Add(-time.Duration(i)*time.Minute))
	}
	pruneResolverCacheLogs(dir, "")
	if got := countCacheLogs(t, dir); got != 10 {
		t.Fatalf("recent burst must survive pruning entirely, got %d files", got)
	}
}

func TestPruneResolverCacheLogsKeepsJustOpened(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	var keepPath string
	for i := 0; i < 10; i++ {
		name := "resolver_cache_2026010" + string(rune('1'+i)) + "_000000.log"
		p := writeCacheLogFixture(t, dir, name, now.Add(-time.Duration(i+1)*24*time.Hour))
		if i == 9 {
			keepPath = p
		}
	}
	pruneResolverCacheLogs(dir, keepPath)
	if _, err := os.Stat(keepPath); err != nil {
		t.Fatalf("just-opened file must survive pruning: %v", err)
	}
	if got := countCacheLogs(t, dir); got != 8 {
		t.Fatalf("expected 7 newest + just-opened = 8 files, got %d", got)
	}
}

func TestPruneResolverCacheLogsMissingDirIsSilent(t *testing.T) {
	pruneResolverCacheLogs(filepath.Join(t.TempDir(), "no-such-dir"), "")
}
