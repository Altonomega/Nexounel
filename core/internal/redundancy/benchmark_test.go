package redundancy

// Measurement-only file: it imports the sibling compression package
// solely to compare RE wire bytes against zstd-only on identical
// corpora. Production code in this package is stdlib-only; no new
// dependency is introduced (compression is already vendored).

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/MNSH-Nexo/Nexounel/core/internal/compression"
)

const (
	benchSegments = 64
	benchSegSize  = 2048
)

// buildCorpus returns deterministic corpora (seed 1 throughout; the
// seedBase keeps warmup and measurement sets disjoint). repetitive:
// template responses with small mutations, heavy cross-segment
// repetition (same template family across sets, different mutation
// seeds). mixed: alternating repetitive and PRNG random segments.
// unique: pure PRNG random bytes, disjoint across sets. partial:
// half warmup-shared template, half NEW compressible text never seen
// in warmup: the §7 case where an RE frame carries both references
// and a substantial compressible literal remainder.
func buildCorpus(kind string, seedBase int) [][]byte {
	segs := make([][]byte, benchSegments)
	switch kind {
	case "repetitive":
		for i := range segs {
			segs[i] = repetitiveSegmentForBench(seedBase + i)
		}
	case "mixed":
		for i := range segs {
			if i%2 == 0 {
				segs[i] = repetitiveSegmentForBench(seedBase + i)
			} else {
				segs[i] = randomSegment(seedBase + i)
			}
		}
	case "unique":
		for i := range segs {
			segs[i] = randomSegment(seedBase + i)
		}
	case "partial":
		for i := range segs {
			half := repetitiveSegmentForBench(seedBase + i)[:benchSegSize/2]
			fresh := freshTextBytes(seedBase+i, benchSegSize/2)
			seg := make([]byte, 0, benchSegSize)
			seg = append(seg, half...)
			seg = append(seg, fresh...)
			segs[i] = seg
		}
	}
	return segs
}

func repetitiveSegmentForBench(seed int) []byte {
	// Same template family for every seed (mod 5), so different sets
	// share most chunks while differing in page numbers/mutations.
	return repetitiveBytes(int64(1000+seed%5), benchSegSize)
}

// freshTextBytes builds compressible text from a template family that
// never appears in the warmup set.
func freshTextBytes(seed, size int) []byte {
	tmpl := `{"event":"page_view","session":"sess-%d","payload":{"title":"Fresh Article","body":"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore."}}`
	var out []byte
	for len(out) < size {
		out = append(out, []byte(sprintfTemplate(tmpl, seed))...)
		seed++
	}
	return out[:size]
}

func randomSegment(seed int) []byte {
	rng := rand.New(rand.NewSource(int64(1 + seed)))
	buf := make([]byte, benchSegSize)
	if _, err := rng.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// steadyPair warms an encoder/decoder pair with one full pass over
// warmup (ACKs delivered), then measures the wire total of encoding
// the DISJOINT measure set. Disjointness is what makes the unique
// corpus honest: re-encoding identical random segments would fake
// repetition that does not exist. Repetitive/mixed measure sets share
// the warmup template family, which is exactly the cross-time
// repetition RE is built to exploit.
func steadyPair(t testing.TB, warmup, measure [][]byte) (*Encoder, *Decoder, int) {
	t.Helper()
	enc := NewEncoder(NewCache(DefaultConfig()))
	dec := NewDecoder(NewCache(DefaultConfig()))
	for _, s := range warmup {
		f, err := enc.Encode(s)
		if err != nil {
			t.Fatal(err)
		}
		out, res, err := dec.Decode(f.Wire)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, s) {
			t.Fatal("warmup decode mismatch")
		}
		enc.NoteAck(res.Ack())
	}
	steady := 0
	for _, s := range measure {
		f, err := enc.Encode(s)
		if err != nil {
			t.Fatal(err)
		}
		steady += len(f.Wire)
		out, res, err := dec.Decode(f.Wire)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, s) {
			t.Fatal("steady decode mismatch")
		}
		enc.NoteAck(res.Ack())
	}
	return enc, dec, steady
}

func zstdTotal(segs [][]byte) int {
	total := 0
	for _, s := range segs {
		out, _ := compression.CompressPayload(s, compression.TypeZSTD, 0)
		total += len(out)
	}
	return total
}

// warmedPair returns an encoder/decoder pair warmed by one full pass
// over warmup with ACKs delivered, and nothing else.
func warmedPair(t testing.TB, warmup [][]byte) (*Encoder, *Decoder) {
	t.Helper()
	enc := NewEncoder(NewCache(DefaultConfig()))
	dec := NewDecoder(NewCache(DefaultConfig()))
	for _, s := range warmup {
		f, err := enc.Encode(s)
		if err != nil {
			t.Fatal(err)
		}
		out, res, err := dec.Decode(f.Wire)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, s) {
			t.Fatal("warmup decode mismatch")
		}
		enc.NoteAck(res.Ack())
	}
	return enc, dec
}

// TestCorpusRatios prints the comparison table the prototype is judged
// by: RE wire bytes vs raw and vs zstd-only on identical corpora, plus
// the RE+zstd composition the coordinator will run. Run with -v to see
// the table; assertions guard against regressions in the wrong
// direction (RE must beat raw on repetitive, must not explode on
// unique bulk).
func TestCorpusRatios(t *testing.T) {
	for _, kind := range []string{"repetitive", "mixed", "unique", "partial"} {
		segs := buildCorpus(kind, 10000)
		raw := 0
		for _, s := range segs {
			raw += len(s)
		}
		// Single measurement pass over the disjoint measure set with
		// a pair warmed only on the warmup set: each segment is
		// encoded exactly once for both the RE and the RE+zstd
		// totals, so no leg can benefit from re-encoding identical
		// bytes.
		enc, dec := warmedPair(t, buildCorpus(kind, 0))
		reTotal, rzTotal := 0, 0
		for _, s := range segs {
			f, err := enc.Encode(s)
			if err != nil {
				t.Fatal(err)
			}
			reTotal += len(f.Wire)
			cout, _ := compression.CompressPayload(f.Wire, compression.TypeZSTD, 0)
			rzTotal += len(cout)
			out, res, err := dec.Decode(f.Wire)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, s) {
				t.Fatal("measure decode mismatch")
			}
			enc.NoteAck(res.Ack())
		}
		zTotal := zstdTotal(segs)
		t.Logf("%-10s raw=%7d RE=%7d (%.3f) zstd=%7d (%.3f) RE+zstd=%7d (%.3f) senderCache=%dB",
			kind, raw, reTotal, float64(reTotal)/float64(raw),
			zTotal, float64(zTotal)/float64(raw),
			rzTotal, float64(rzTotal)/float64(raw), enc.Cache().Bytes())
		switch kind {
		case "repetitive":
			if float64(reTotal) >= 0.5*float64(raw) {
				t.Fatalf("RE must compress repetitive corpus to <50%% of raw, got %.3f", float64(reTotal)/float64(raw))
			}
		case "unique":
			// RE must never materially expand incompressible data:
			// reference-free frames are discarded by the
			// coordinator (§7), but even the raw RE frame must
			// stay within 5% overhead here.
			if float64(reTotal) > 1.05*float64(raw) {
				t.Fatalf("RE expanded unique corpus: %.3f", float64(reTotal)/float64(raw))
			}
			if float64(rzTotal) > 1.05*float64(raw) {
				t.Fatalf("RE+zstd expanded unique corpus: %.3f", float64(rzTotal)/float64(raw))
			}
		}
	}
}

// Benchmarks run 1-core pinned (taskset -c 0, GOMAXPROCS=1) to match
// the 1-vCPU Iran node. Each benchmark encodes rotating corpus
// segments against a warmed pair, so the numbers reflect steady state.

func benchEncode(b *testing.B, kind string) {
	segs := buildCorpus(kind, 10000)
	enc, _, _ := steadyPair(b, buildCorpus(kind, 0), segs)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := enc.Encode(segs[i%len(segs)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeRepetitive(b *testing.B) { benchEncode(b, "repetitive") }
func BenchmarkEncodeMixed(b *testing.B)      { benchEncode(b, "mixed") }
func BenchmarkEncodeUnique(b *testing.B)     { benchEncode(b, "unique") }

func BenchmarkDecodeRepetitive(b *testing.B) {
	segs := buildCorpus("repetitive", 10000)
	enc, dec, _ := steadyPair(b, buildCorpus("repetitive", 0), segs)
	frames := make([][]byte, len(segs))
	for i, s := range segs {
		f, err := enc.Encode(s)
		if err != nil {
			b.Fatal(err)
		}
		frames[i] = f.Wire
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := dec.Decode(frames[i%len(frames)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFingerprint(b *testing.B) {
	chunk := repetitiveSegmentForBench(10000)[:256]
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Fingerprint(chunk)
	}
}

func BenchmarkChunking(b *testing.B) {
	data := repetitiveSegmentForBench(10000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = splitChunks(data)
	}
}
