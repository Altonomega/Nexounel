package main

import (
	"testing"

	"github.com/Altonomega/Nexounel/core/internal/multisession"
)

func TestMergeProbeResults(t *testing.T) {
	original := []multisession.ProbeResult{
		{Resolver: "1.1.1.1", Port: 53, UploadMTU: 103, DownloadMTU: 3439, Valid: true},
		{Resolver: "8.8.8.8", Port: 53, Valid: false},
		{Resolver: "9.9.9.9", Port: 53, Valid: false},
		{Resolver: "1.0.0.1", Port: 53, UploadMTU: 100, DownloadMTU: 3000, Valid: true},
	}

	// Empty retry returns the original unchanged.
	if got := mergeProbeResults(original, nil); len(got) != len(original) {
		t.Fatalf("empty retry: got %d results, want %d", len(got), len(original))
	}

	// Retry recovers one failed resolver; the other stays failed; the
	// valid ones are untouched.
	retry := []multisession.ProbeResult{
		{Resolver: "8.8.8.8", Port: 53, UploadMTU: 104, DownloadMTU: 3400, Valid: true},
		{Resolver: "9.9.9.9", Port: 53, Valid: false},
	}
	merged := mergeProbeResults(original, retry)
	if len(merged) != len(original) {
		t.Fatalf("merged length: got %d, want %d", len(merged), len(original))
	}
	byIP := make(map[string]multisession.ProbeResult, len(merged))
	for _, r := range merged {
		byIP[r.Resolver] = r
	}
	if !byIP["8.8.8.8"].Valid || byIP["8.8.8.8"].DownloadMTU != 3400 {
		t.Fatalf("8.8.8.8 should be recovered with download 3400, got %+v", byIP["8.8.8.8"])
	}
	if byIP["9.9.9.9"].Valid {
		t.Fatalf("9.9.9.9 should stay failed, got %+v", byIP["9.9.9.9"])
	}
	if !byIP["1.1.1.1"].Valid || byIP["1.1.1.1"].DownloadMTU != 3439 {
		t.Fatalf("1.1.1.1 should be untouched, got %+v", byIP["1.1.1.1"])
	}
	if !byIP["1.0.0.1"].Valid {
		t.Fatalf("1.0.0.1 should be untouched, got %+v", byIP["1.0.0.1"])
	}
	// The original slice must not be mutated.
	if original[1].Valid {
		t.Fatal("mergeProbeResults mutated the original slice")
	}

	// A retry result for an unknown resolver is ignored.
	merged = mergeProbeResults(original, []multisession.ProbeResult{
		{Resolver: "203.0.113.1", Port: 53, UploadMTU: 100, DownloadMTU: 3000, Valid: true},
	})
	if len(merged) != len(original) {
		t.Fatalf("unknown resolver: merged length %d, want %d", len(merged), len(original))
	}
	if countValidProbeResults(merged) != 2 {
		t.Fatalf("unknown resolver: valid count %d, want 2", countValidProbeResults(merged))
	}
}

func TestCountValidProbeResults(t *testing.T) {
	results := []multisession.ProbeResult{
		{Resolver: "1.1.1.1", Valid: true},
		{Resolver: "8.8.8.8", Valid: false},
		{Resolver: "9.9.9.9", Valid: true},
	}
	if got := countValidProbeResults(results); got != 2 {
		t.Fatalf("countValidProbeResults: got %d, want 2", got)
	}
	if got := countValidProbeResults(nil); got != 0 {
		t.Fatalf("countValidProbeResults(nil): got %d, want 0", got)
	}
}
