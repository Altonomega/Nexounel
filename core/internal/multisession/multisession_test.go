package multisession

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func probe(resolver string, up, down int) ProbeResult {
	return ProbeResult{Resolver: resolver, UploadMTU: up, DownloadMTU: down, Valid: true}
}

func TestOperatingSizeAppliesMargin(t *testing.T) {
	if got := OperatingSize(1000, 0.95); got != 950 {
		t.Fatalf("OperatingSize(1000, 0.95) = %d, want 950", got)
	}
	if got := OperatingSize(101, 0.95); got != 95 {
		t.Fatalf("OperatingSize(101, 0.95) = %d, want floor(95.95)=95", got)
	}
	if got := OperatingSize(0, 0.95); got != 0 {
		t.Fatalf("OperatingSize(0) = %d, want 0", got)
	}
	if got := OperatingSize(-5, 0.95); got != 0 {
		t.Fatalf("OperatingSize(-5) = %d, want 0", got)
	}
	if err := ValidateMargin(0.95); err != nil {
		t.Fatalf("0.95 must be valid: %v", err)
	}
	for _, bad := range []float64{0, -0.5, 1.01, 2} {
		if err := ValidateMargin(bad); err == nil {
			t.Fatalf("margin %v must be rejected", bad)
		}
	}
}

func TestClusterSingleResolver(t *testing.T) {
	cl := Cluster([]ProbeResult{probe("8.8.8.8", 140, 1200)}, 0.25, 0.95)
	if len(cl.Classes) != 1 {
		t.Fatalf("classes = %d, want 1", len(cl.Classes))
	}
	c := cl.Classes[0]
	if c.OperatingUpload != 133 || c.OperatingDownload != 1140 {
		t.Fatalf("operating = %d/%d, want 133/1140", c.OperatingUpload, c.OperatingDownload)
	}
	if c.Score != (133+1140)*1 {
		t.Fatalf("score = %d, want %d", c.Score, (133+1140)*1)
	}
	if len(cl.Reserves) != 0 {
		t.Fatalf("reserves = %d, want 0", len(cl.Reserves))
	}
}

func TestClusterExactCapacityBoundary(t *testing.T) {
	// Identical capacities must land in ONE class: no gap, no split.
	results := []ProbeResult{
		probe("a", 100, 1000),
		probe("b", 100, 1000),
		probe("c", 100, 1000),
	}
	cl := Cluster(results, 0.25, 0.95)
	if len(cl.Classes) != 1 || len(cl.Classes[0].Members) != 3 {
		t.Fatalf("identical capacities must form one class of 3, got %+v", cl.Classes)
	}
}

func TestClusterSplitsOnDownloadGap(t *testing.T) {
	results := []ProbeResult{
		probe("slow-1", 140, 200),
		probe("slow-2", 140, 210),
		probe("fast-1", 140, 1400),
		probe("fast-2", 140, 1450),
	}
	cl := Cluster(results, 0.25, 0.95)
	if len(cl.Classes) != 2 {
		t.Fatalf("classes = %d, want 2", len(cl.Classes))
	}
	// Best (fast) class first, by score.
	if cl.Classes[0].RawDownload != 1400 || len(cl.Classes[0].Members) != 2 {
		t.Fatalf("first class = %+v, want fast class of 2", cl.Classes[0])
	}
	if cl.Classes[1].RawDownload != 200 || len(cl.Classes[1].Members) != 2 {
		t.Fatalf("second class = %+v, want slow class of 2", cl.Classes[1])
	}
}

func TestClusterSplitsOnUploadGap(t *testing.T) {
	// Same download, very different upload: upload gap alone must split.
	results := []ProbeResult{
		probe("up-small-1", 40, 1000),
		probe("up-small-2", 45, 1000),
		probe("up-big-1", 140, 1000),
		probe("up-big-2", 140, 1010),
	}
	cl := Cluster(results, 0.25, 0.95)
	if len(cl.Classes) != 2 {
		t.Fatalf("classes = %d, want 2 (upload gap must split)", len(cl.Classes))
	}
}

func TestClusterZeroCapacityBecomesReserve(t *testing.T) {
	results := []ProbeResult{
		probe("good", 140, 1200),
		{Resolver: "dead", UploadMTU: 0, DownloadMTU: 0, Valid: false},
		{Resolver: "half", UploadMTU: 140, DownloadMTU: 0, Valid: true},
	}
	cl := Cluster(results, 0.25, 0.95)
	if len(cl.Classes) != 1 {
		t.Fatalf("classes = %d, want 1", len(cl.Classes))
	}
	if len(cl.Reserves) != 2 {
		t.Fatalf("reserves = %d, want 2 (never discarded)", len(cl.Reserves))
	}
}

func TestClusterEmptyInput(t *testing.T) {
	cl := Cluster(nil, 0.25, 0.95)
	if len(cl.Classes) != 0 || len(cl.Reserves) != 0 {
		t.Fatalf("empty input must yield no classes/reserves, got %+v", cl)
	}
}

func TestHysteresisRule(t *testing.T) {
	if !ShouldAdoptOperatingPoint(0, 100, 0) {
		t.Fatal("no current point must adopt")
	}
	if !ShouldAdoptOperatingPoint(1000, 900, 0) {
		t.Fatal("stranded current point (pool 0) must adopt even a smaller point")
	}
	if ShouldAdoptOperatingPoint(1000, 1100, 3) {
		t.Fatal("10% improvement must NOT adopt (needs >12.5%)")
	}
	if !ShouldAdoptOperatingPoint(1000, 1126, 3) {
		t.Fatal("12.6% improvement must adopt")
	}
	if ShouldAdoptOperatingPoint(1000, 1000, 3) {
		t.Fatal("equal point must NOT adopt")
	}
}

func TestWeightOrdering(t *testing.T) {
	big := Class{Members: []ProbeResult{probe("a", 140, 1200), probe("b", 140, 1200)}, RawUpload: 140, RawDownload: 1200, OperatingUpload: 133, OperatingDownload: 1140, Score: (133 + 1140) * 2}
	small := Class{Members: []ProbeResult{probe("c", 60, 300)}, RawUpload: 60, RawDownload: 300, OperatingUpload: 57, OperatingDownload: 285, Score: (57 + 285) * 1}
	if Weight(big) <= Weight(small) {
		t.Fatalf("capacity must dominate: big=%v small=%v", Weight(big), Weight(small))
	}
	// Equal capacity: lower loss wins.
	lossy := big
	lossy.AvgLoss = 0.5
	clean := big
	clean.AvgLoss = 0
	if Weight(lossy) >= Weight(clean) {
		t.Fatalf("lower loss must weigh more: lossy=%v clean=%v", Weight(lossy), Weight(clean))
	}
	// Equal capacity and loss: lower RTT wins.
	slow := big
	slow.AvgRTTMs = 200
	fast := big
	fast.AvgRTTMs = 20
	if Weight(slow) >= Weight(fast) {
		t.Fatalf("lower RTT must weigh more: slow=%v fast=%v", Weight(slow), Weight(fast))
	}
	// Zero capacity weighs zero.
	empty := Class{}
	if Weight(empty) != 0 {
		t.Fatalf("zero-capacity weight = %v, want 0", Weight(empty))
	}
}

func TestChooseWeighted(t *testing.T) {
	weights := []float64{3, 1}
	if got := Choose(weights, 0); got != 0 {
		t.Fatalf("Choose(0) = %d, want 0", got)
	}
	if got := Choose(weights, 2.99); got != 0 {
		t.Fatalf("Choose(2.99) = %d, want 0", got)
	}
	if got := Choose(weights, 3); got != 1 {
		t.Fatalf("Choose(3) = %d, want 1", got)
	}
	if got := Choose(weights, 3.99); got != 1 {
		t.Fatalf("Choose(3.99) = %d, want 1", got)
	}
	if got := Choose([]float64{0, 0}, 0); got != -1 {
		t.Fatalf("all-zero weights must return -1, got %d", got)
	}
	if got := Choose([]float64{1, 1}, 2); got != -1 {
		t.Fatalf("out-of-range r must return -1, got %d", got)
	}
	// Zero-weight classes are skipped, never picked.
	if got := Choose([]float64{0, 2, 0}, 1); got != 1 {
		t.Fatalf("Choose must skip zero weights, got %d", got)
	}
}

func TestRegistryLoadAndLookup(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node2.key")
	if err := os.WriteFile(keyPath, []byte("  second-node-key-0123456789abcdef  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	regPath := filepath.Join(dir, "nodes.toml")
	content := "[[nodes]]\nid = \"iran-1\"\nkey = \"first-node-key-0123456789abcdef\"\n\n[[nodes]]\nid = \"iran-2\"\nkey_file = " + "\"" + keyPath + "\"\n"
	if err := os.WriteFile(regPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := LoadRegistry(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(reg.Nodes))
	}
	n, ok := reg.Lookup("iran-2")
	if !ok || n.Key != "second-node-key-0123456789abcdef" {
		t.Fatalf("key_file node lookup = %+v ok=%v", n, ok)
	}
	if _, ok := reg.Lookup("ghost"); ok {
		t.Fatal("unknown node must not be found")
	}
	codecs, err := reg.Codecs(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(codecs) != 2 {
		t.Fatalf("codecs = %d, want 2", len(codecs))
	}
}

func TestRegistryRejectsBadEntries(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"no-nodes", "other = 1\n"},
		{"bad-id", "[[nodes]]\nid = \"bad id!\"\nkey = \"k\"\n"},
		{"no-key", "[[nodes]]\nid = \"n1\"\n"},
		{"dup-id", "[[nodes]]\nid = \"n1\"\nkey = \"k1\"\n[[nodes]]\nid = \"n1\"\nkey = \"k2\"\n"},
		{"missing-key-file", "[[nodes]]\nid = \"n1\"\nkey_file = \"/nonexistent/key\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, "reg.toml")
			if err := os.WriteFile(p, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadRegistry(p); err == nil {
				t.Fatalf("registry %q must be rejected", tc.name)
			}
		})
	}
	if _, err := LoadRegistry(""); err == nil {
		t.Fatal("empty registry path must be rejected")
	}
	if err := ValidateNodeID("iran-1"); err != nil {
		t.Fatalf("valid node id rejected: %v", err)
	}
	if err := ValidateNodeID("bad id"); err == nil {
		t.Fatal("invalid node id must be rejected")
	}
}

func TestClusterUsesRTTAndLossInWeight(t *testing.T) {
	// End-to-end through Cluster: identical capacities, different
	// loss/RTT must produce different weights in the expected order.
	slow := probe("slow", 140, 1200)
	slow.Loss = 0.4
	slow.RTT = 300 * time.Millisecond
	fast := probe("fast", 140, 1200)
	fast.RTT = 20 * time.Millisecond
	cl := Cluster([]ProbeResult{slow, fast}, 0.25, 0.95)
	if len(cl.Classes) != 1 {
		t.Fatalf("identical capacities must cluster together, got %d classes", len(cl.Classes))
	}
	// Single class: weight is a single number; verify it reflects the
	// member means (loss 0.2, RTT 160ms) rather than ignoring them.
	w := Weight(cl.Classes[0])
	base := float64(cl.Classes[0].Score)
	if w >= base {
		t.Fatalf("weight %v must be discounted below raw score %v by loss/latency", w, base)
	}
	if w <= 0 {
		t.Fatal("weight must stay positive")
	}
}
