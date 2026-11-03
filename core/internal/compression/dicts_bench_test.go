package compression

// Benchmarks for the throughput-pack zstd settings.
//
// Run pinned to one core, as on the 1-vCPU target box:
//
//	taskset -c 0 GOMAXPROCS=1 go test ./internal/compression/ -run '^$' -bench 'BenchmarkZSTDMatrix|BenchmarkSmallFrame|BenchmarkDictChoice|BenchmarkPeakHeap' -benchmem -count=1
//
// Corpora are generated deterministically (seed 1) and are synthetic
// only: HTTP/JSON/HTML boilerplate, seeded-PRNG bytes, or a 50/50
// mix. The codec is benchmarked directly (compressZSTD), bypassing
// the CompressPayload entropy/min-size gates, so the incompressible
// corpora measure codec behavior rather than the gate short-circuit.
// Ratio is reported as compressed/original; ns/op, B/op and
// allocs/op come from the testing framework. Level 0 is included
// in the matrix and small-frame benchmarks: with Dict=true it
// resolves to DefaultDictLevel (9) in Configure, so the
// Level0/Dict=true rows ARE the production default; with
// Dict=false Level 0 is the legacy SpeedFastest encoder.

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var benchSink []byte

var (
	corporaOnce sync.Once
	corpusPlain []byte
	corpusMixed []byte
	corpusRand  []byte
)

func benchCorpora() ([]byte, []byte, []byte) {
	corporaOnce.Do(func() {
		corpusPlain = makeCorpusPlain(1 << 20)
		corpusMixed = makeCorpusMixed(1 << 20)
		corpusRand = makeCorpusRandom(1 << 20)
	})
	return corpusPlain, corpusMixed, corpusRand
}

func benchWords(r *rand.Rand) string {
	words := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima", "maple", "novel", "ocean", "piano"}
	return words[r.IntN(len(words))]
}

func makeCorpusPlain(size int) []byte {
	r := rand.New(rand.NewPCG(1, 0))
	var b strings.Builder
	b.Grow(size)
	i := 0
	for b.Len() < size {
		if i%2 == 0 {
			fmt.Fprintf(&b, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: public, max-age=3600\r\nETag: \"synthetic-%d\"\r\n\r\n<!DOCTYPE html><html><head><title>%s %s</title></head><body><article><h1>%s %s</h1><p>The %s %s provides %s for every %s.</p></article></body></html>\n",
				i, benchWords(r), benchWords(r), benchWords(r), benchWords(r), benchWords(r), benchWords(r), benchWords(r), benchWords(r))
		} else {
			fmt.Fprintf(&b, "GET /api/v1/users?page=%d HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n{\"id\":%d,\"name\":\"%s-%s\",\"status\":\"active\",\"email\":\"%s%d@example.com\"}\n",
				i%20+1, 10000+i, benchWords(r), benchWords(r), benchWords(r), i)
		}
		i++
	}
	out := []byte(b.String())
	return out[:size]
}

func makeCorpusMixed(size int) []byte {
	plain := makeCorpusPlain(size)
	r := rand.New(rand.NewPCG(1, 1))
	out := make([]byte, size)
	const block = 4096
	for off := 0; off < size; off += block {
		end := min(off+block, size)
		if (off/block)%2 == 0 {
			copy(out[off:end], plain[off:end])
		} else {
			for i := off; i < end; i++ {
				out[i] = byte(r.Uint64())
			}
		}
	}
	return out
}

func makeCorpusRandom(size int) []byte {
	r := rand.New(rand.NewPCG(1, 2))
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(r.Uint64())
	}
	return out
}

func benchEncode(b *testing.B, data []byte, cfg ZSTDOptions) {
	Configure(cfg)
	b.Cleanup(func() { Configure(ZSTDOptions{}) })
	// Warm the pools once (encoder construction, especially with a
	// large window, is a cold-start cost, not steady state) and
	// capture the deterministic output size for the ratio metric.
	first, err := compressZSTD(data)
	if err != nil {
		b.Fatal(err)
	}
	ratio := float64(len(first)) / float64(len(data))
	compressed := float64(len(first))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := compressZSTD(data)
		if err != nil {
			b.Fatal(err)
		}
		benchSink = out
	}
	b.StopTimer()
	// Report after the loop: metrics reported before ResetTimer are
	// discarded by the testing framework.
	b.ReportMetric(ratio, "ratio")
	b.ReportMetric(compressed, "compressed_bytes")
}

func BenchmarkZSTDMatrix(b *testing.B) {
	plain, mixed, randData := benchCorpora()
	corpora := []struct {
		name string
		data []byte
	}{
		{"Plaintext", plain},
		{"Mixed", mixed},
		{"Random", randData},
	}
	for _, corpus := range corpora {
		for _, level := range []int{0, 1, 3, 9, 19} {
			for _, dict := range []bool{false, true} {
				for _, long := range []bool{false, true} {
					name := fmt.Sprintf("%s/Level%d/Dict=%v/Long=%v", corpus.name, level, dict, long)
					b.Run(name, func(b *testing.B) {
						benchEncode(b, corpus.data, ZSTDOptions{DictEnabled: dict, Level: level, LongEnabled: long})
					})
				}
			}
		}
	}
}

func BenchmarkSmallFrame(b *testing.B) {
	frame := []byte(strings.Repeat("GET /api/v1/users?page=2 HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\nContent-Type: application/json\r\n", 6))
	if len(frame) != 696 {
		b.Fatalf("frame size %d, want 696", len(frame))
	}
	for _, level := range []int{0, 1, 9} {
		for _, dict := range []bool{false, true} {
			for _, long := range []bool{false, true} {
				name := fmt.Sprintf("Frame696/Level%d/Dict=%v/Long=%v", level, dict, long)
				b.Run(name, func(b *testing.B) {
					benchEncode(b, frame, ZSTDOptions{DictEnabled: dict, Level: level, LongEnabled: long})
				})
			}
		}
	}
}

func BenchmarkDictChoice(b *testing.B) {
	plain, _, _ := benchCorpora()
	choices := []struct {
		name    string
		dict    Dictionary
		auto    bool
		enabled bool
	}{
		{"UploadOnly", DictUpload, false, true},
		{"DownloadOnly", DictDownload, false, true},
		{"AutoBoth", DictUpload, true, true},
		{"NoDict", DictUpload, false, false},
	}
	for _, choice := range choices {
		b.Run(choice.name, func(b *testing.B) {
			cfg := ZSTDOptions{DictEnabled: choice.enabled, Level: 9}
			Configure(cfg)
			b.Cleanup(func() { Configure(ZSTDOptions{}) })
			first, err := compressZSTDChoice(plain, choice.dict, choice.auto)
			if err != nil {
				b.Fatal(err)
			}
			ratio := float64(len(first)) / float64(len(plain))
			b.SetBytes(int64(len(plain)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := compressZSTDChoice(plain, choice.dict, choice.auto)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = out
			}
			b.StopTimer()
			b.ReportMetric(ratio, "ratio")
		})
	}
}

func BenchmarkPeakHeap(b *testing.B) {
	plain, _, _ := benchCorpora()
	for _, cfg := range []ZSTDOptions{
		{},
		{DictEnabled: true},
		{DictEnabled: true, Level: 19, LongEnabled: true},
	} {
		// Label the dict-default config by its effective level.
		displayLevel := cfg.Level
		if cfg.DictEnabled && displayLevel == 0 {
			displayLevel = DefaultDictLevel
		}
		name := fmt.Sprintf("Level%d/Dict=%v/Long=%v", displayLevel, cfg.DictEnabled, cfg.LongEnabled)
		b.Run(name, func(b *testing.B) {
			Configure(cfg)
			b.Cleanup(func() { Configure(ZSTDOptions{}) })
			var ms runtime.MemStats
			var peak uint64
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := compressZSTD(plain)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = out
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > peak {
					peak = ms.HeapAlloc
				}
			}
			b.ReportMetric(float64(peak)/(1024*1024), "heap_peak_mb")
		})
	}
}
