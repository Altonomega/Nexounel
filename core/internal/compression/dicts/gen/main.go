//go:build ignore

// Command gen deterministically trains the two shared zstd dictionaries
// shipped with the compression package (upload-v1.dict, download-v1.dict).
//
// The training corpus is SYNTHETIC and general-purpose only: HTTP/1.1
// request/response boilerplate, JSON API bodies and HTML templates built
// from fixed word lists with a fixed PRNG seed. It contains no user
// traffic, no scraped data and nothing specific to any deployment. All
// hostnames use the reserved *.example.com / *.example.org domains and
// all credentials are obviously fake placeholders.
//
// Regenerate with (build constraints are ignored when files are named
// explicitly):
//
//	go run core/internal/compression/dicts/gen/main.go
//
// from the core/ module root. The output must be byte-identical across
// runs; the program prints sizes and dictionary IDs for verification.
// Each dictionary is capped at 64 KiB; generation fails if the cap
// cannot be met. Dictionary IDs are part of the wire format: a new
// dictionary version MUST use new IDs, never reuse an ID with
// different content, because decoders select the dictionary by ID and
// a same-ID content change could decode old frames against the wrong
// dictionary.
package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const (
	// maxDictionarySize is the enforced cap for each shipped dictionary.
	maxDictionarySize = 64 * 1024

	uploadDictID   uint32 = 1
	downloadDictID uint32 = 2

	// historyBudgets, largest first: the generator keeps the largest
	// history whose trained dictionary fits the cap.
	historyBudgetFirst = 48 * 1024

	sampleSeed  uint64 = 42
	sampleCount        = 320
)

var historyBudgets = []int{48 * 1024, 32 * 1024, 24 * 1024, 16 * 1024, 8 * 1024}

var (
	hosts    = []string{"api.example.com", "www.example.com", "cdn.example.com", "app.example.org", "static.example.net", "gateway.example.com"}
	paths    = []string{"/api/v1/users", "/api/v1/orders", "/api/v1/products", "/api/v2/search", "/api/v1/sessions", "/api/v1/settings", "/api/v1/reports", "/api/v1/items"}
	words    = []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima", "maple", "novel", "ocean", "piano", "quartz", "river", "solar", "tango"}
	statuses = []string{"active", "pending", "archived", "disabled", "verified", "suspended"}
	roles    = []string{"member", "editor", "viewer", "admin", "support"}
	agents   = []string{"ExampleAgent/1.0", "ExampleClient/2.4 (compatible; Synthetic)", "Mozilla/5.0 (compatible; ExampleBot/1.0)"}
	methods  = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
)

func pick(r *rand.Rand, list []string) string { return list[r.IntN(len(list))] }

func syntheticID(r *rand.Rand, prefix string) string {
	return fmt.Sprintf("%s-%05d", prefix, r.IntN(90000)+10000)
}

func syntheticToken(r *rand.Rand) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var b strings.Builder
	for i := 0; i < 24; i++ {
		b.WriteByte(alphabet[r.IntN(len(alphabet))])
	}
	return b.String()
}

func jsonObject(r *rand.Rand, i int) string {
	return fmt.Sprintf(`{"id":%d,"name":"%s-%s","status":"%s","role":"%s","email":"%s%d@example.com","score":%d,"active":%v,"tags":["%s","%s"]}`,
		10000+i, pick(r, words), pick(r, words), pick(r, statuses), pick(r, roles),
		pick(r, words), r.IntN(900)+100, r.IntN(100), i%2 == 0, pick(r, words), pick(r, words))
}

func htmlPage(r *rand.Rand, i int) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString(fmt.Sprintf("<title>%s %s — Example Page %d</title>\n", pick(r, words), pick(r, words), i))
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<link rel=\"stylesheet\" href=\"/static/main.css\">\n</head>\n<body>\n")
	b.WriteString("<header><nav><ul><li><a href=\"/\">Home</a></li><li><a href=\"/about\">About</a></li><li><a href=\"/contact\">Contact</a></li></ul></nav></header>\n")
	b.WriteString("<main>\n<article>\n")
	b.WriteString(fmt.Sprintf("<h1>%s %s</h1>\n<p>The %s %s provides %s and %s for every %s. Last updated on 2026-01-%02d.</p>\n",
		pick(r, words), pick(r, words), pick(r, words), pick(r, words), pick(r, words), pick(r, words), pick(r, words), r.IntN(28)+1))
	b.WriteString(fmt.Sprintf("<p>See also: <a href=\"/docs/%s\">%s documentation</a> and <a href=\"/help\">help center</a>.</p>\n", pick(r, words), pick(r, words)))
	b.WriteString("<ul>")
	for j := 0; j < 3+r.IntN(3); j++ {
		b.WriteString(fmt.Sprintf("<li>%s %s %d</li>", pick(r, words), pick(r, words), r.IntN(1000)))
	}
	b.WriteString("</ul>\n</article>\n</main>\n")
	b.WriteString("<footer><p>&copy; 2026 Example Organization. All rights reserved. <a href=\"/privacy\">Privacy</a> <a href=\"/terms\">Terms</a></p></footer>\n")
	b.WriteString("<script src=\"/static/app.js\"></script>\n</body>\n</html>\n")
	return b.String()
}

// uploadSamples returns request-shaped training samples: HTTP requests
// with JSON bodies, query strings and common headers.
func uploadSamples() [][]byte {
	r := rand.New(rand.NewPCG(sampleSeed, 0))
	out := make([][]byte, 0, sampleCount)
	for i := 0; i < sampleCount; i++ {
		method := pick(r, methods)
		host := pick(r, hosts)
		path := pick(r, paths)
		var b strings.Builder
		query := fmt.Sprintf("?page=%d&limit=%d&sort=%s&filter=%s", r.IntN(20)+1, 10+r.IntN(90), pick(r, words), pick(r, statuses))
		b.WriteString(fmt.Sprintf("%s %s%s HTTP/1.1\r\n", method, path, query))
		b.WriteString(fmt.Sprintf("Host: %s\r\n", host))
		b.WriteString(fmt.Sprintf("User-Agent: %s\r\n", pick(r, agents)))
		b.WriteString("Accept: application/json, text/plain, */*\r\n")
		b.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
		b.WriteString("Accept-Encoding: gzip, deflate, br\r\n")
		b.WriteString("Connection: keep-alive\r\n")
		if i%3 == 0 {
			b.WriteString(fmt.Sprintf("Authorization: Bearer synthetic-%s\r\n", syntheticToken(r)))
		}
		if i%4 == 0 {
			b.WriteString(fmt.Sprintf("Cookie: session_id=synthetic-%s; theme=light; locale=en-US\r\n", syntheticToken(r)))
		}
		if i%5 == 0 {
			b.WriteString(fmt.Sprintf("X-Request-Id: %s\r\n", syntheticID(r, "req")))
			b.WriteString(fmt.Sprintf("X-Correlation-Id: %s\r\n", syntheticID(r, "corr")))
		}
		body := ""
		if method == "POST" || method == "PUT" || method == "PATCH" {
			body = jsonObject(r, i)
			b.WriteString("Content-Type: application/json\r\n")
			b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}
		b.WriteString("\r\n")
		b.WriteString(body)
		if i%6 == 0 {
			// A bare JSON API body without HTTP framing, as some
			// upstream payloads carry.
			out = append(out, []byte("{\"query\":\""+pick(r, words)+" "+pick(r, words)+"\",\"variables\":{\"id\":"+fmt.Sprint(1000+i)+",\"limit\":25},\"operationName\":\"Get"+pick(r, words)+"\"}"))
		}
		out = append(out, []byte(b.String()))
	}
	return out
}

// downloadSamples returns response-shaped training samples: HTTP
// responses with JSON bodies and HTML pages.
func downloadSamples() [][]byte {
	r := rand.New(rand.NewPCG(sampleSeed, 1))
	out := make([][]byte, 0, sampleCount)
	for i := 0; i < sampleCount; i++ {
		var b strings.Builder
		isHTML := i%2 == 0
		body := ""
		if isHTML {
			body = htmlPage(r, i)
		} else {
			var items []string
			for j := 0; j < 2+r.IntN(4); j++ {
				items = append(items, jsonObject(r, i*10+j))
			}
			body = fmt.Sprintf(`{"data":[%s],"meta":{"page":%d,"per_page":%d,"total":%d},"links":{"self":"https://api.example.com/api/v1/users?page=%d","next":"https://api.example.com/api/v1/users?page=%d"}}`,
				strings.Join(items, ","), r.IntN(10)+1, 25, 1000+r.IntN(9000), r.IntN(10)+1, r.IntN(10)+2)
		}
		b.WriteString("HTTP/1.1 200 OK\r\n")
		if isHTML {
			b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		} else {
			b.WriteString("Content-Type: application/json; charset=utf-8\r\n")
		}
		b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		b.WriteString("Cache-Control: public, max-age=3600\r\n")
		b.WriteString(fmt.Sprintf("ETag: \"synthetic-%s\"\r\n", syntheticToken(r)))
		b.WriteString("Date: Thu, 01 Jan 2026 00:00:00 GMT\r\n")
		b.WriteString("Server: example-server/1.0\r\n")
		if i%3 == 0 {
			b.WriteString(fmt.Sprintf("Set-Cookie: session_id=synthetic-%s; Path=/; HttpOnly; SameSite=Lax\r\n", syntheticToken(r)))
		}
		b.WriteString("X-Content-Type-Options: nosniff\r\n")
		b.WriteString("X-Frame-Options: DENY\r\n")
		b.WriteString("Connection: keep-alive\r\n")
		b.WriteString("\r\n")
		b.WriteString(body)
		out = append(out, []byte(b.String()))
	}
	return out
}

func buildHistory(samples [][]byte, budget int) []byte {
	var hist []byte
	for _, s := range samples {
		if len(hist) >= budget {
			break
		}
		hist = append(hist, s...)
	}
	if len(hist) > budget {
		hist = hist[:budget]
	}
	return hist
}

func trainDict(id uint32, samples [][]byte) ([]byte, int, error) {
	for _, budget := range historyBudgets {
		hist := buildHistory(samples, budget)
		dict, err := zstd.BuildDict(zstd.BuildDictOptions{
			ID:       id,
			Contents: samples,
			History:  hist,
			Level:    zstd.SpeedBestCompression,
		})
		if err != nil {
			return nil, 0, fmt.Errorf("BuildDict (history %d): %w", budget, err)
		}
		if len(dict) <= maxDictionarySize {
			return dict, budget, nil
		}
	}
	return nil, 0, fmt.Errorf("no history budget produced a dictionary <= %d bytes", maxDictionarySize)
}

func verifyDict(name string, dict []byte, id uint32, samples [][]byte) error {
	info, err := zstd.InspectDictionary(dict)
	if err != nil {
		return fmt.Errorf("%s: InspectDictionary: %w", name, err)
	}
	if info.ID() != id {
		return fmt.Errorf("%s: dict ID %d, want %d", name, info.ID(), id)
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderDict(dict))
	if err != nil {
		return fmt.Errorf("%s: encoder: %w", name, err)
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderDicts(dict))
	if err != nil {
		return fmt.Errorf("%s: decoder: %w", name, err)
	}
	for i, s := range samples[:8] {
		frame := enc.EncodeAll(s, nil)
		// A decoder without the dictionary must fail closed on a
		// dictionary frame (unknown dictionary ID), never silently
		// produce output.
		plainDec, err := zstd.NewReader(nil)
		if err != nil {
			return err
		}
		if _, err := plainDec.DecodeAll(frame, nil); err == nil {
			return fmt.Errorf("%s: sample %d: dict frame decoded without dict (expected unknown-dictionary error)", name, i)
		}
		plainDec.Close()
		back, err := dec.DecodeAll(frame, nil)
		if err != nil {
			return fmt.Errorf("%s: sample %d: decode: %w", name, i, err)
		}
		if !bytes.Equal(back, s) {
			return fmt.Errorf("%s: sample %d: round-trip mismatch", name, i)
		}
	}
	enc.Close()
	dec.Close()
	return nil
}

func main() {
	outDir := "internal/compression/dicts"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	// Allow running from either the core/ module root or the repo root.
	if _, err := os.Stat(filepath.Join(outDir, "gen")); err != nil {
		if _, err2 := os.Stat("core/" + outDir); err2 == nil {
			outDir = "core/" + outDir
		}
	}
	jobs := []struct {
		name    string
		id      uint32
		samples [][]byte
	}{
		{"upload-v1.dict", uploadDictID, uploadSamples()},
		{"download-v1.dict", downloadDictID, downloadSamples()},
	}
	for _, job := range jobs {
		dict, budget, err := trainDict(job.id, job.samples)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			os.Exit(1)
		}
		if err := verifyDict(job.name, dict, job.id, job.samples); err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			os.Exit(1)
		}
		path := filepath.Join(outDir, job.name)
		if err := os.WriteFile(path, dict, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			os.Exit(1)
		}
		sum := sha256.Sum256(dict)
		fmt.Printf("%s: %d bytes (history budget %d, cap %d), id=%d, sha256=%x\n",
			job.name, len(dict), budget, maxDictionarySize, job.id, sum)
	}
}
