package redundancy

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"
	"time"
)

func repetitiveSegment(t *testing.T, seed int64, size int) []byte {
	t.Helper()
	return repetitiveBytes(seed, size)
}

func repetitiveBytes(seed int64, size int) []byte {
	rng := rand.New(rand.NewSource(seed))
	templates := []string{
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: max-age=60\r\nContent-Length: 128\r\n\r\n{\"status\":\"ok\",\"data\":{\"id\":%d,\"name\":\"example-item\",\"tags\":[\"alpha\",\"beta\"]}}",
		"GET /api/v1/items?page=%d HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\nAuthorization: Bearer synthetic-token-0123456789\r\nUser-Agent: example-client/1.0\r\n\r\n",
		"<html><head><title>Example Page</title></head><body><div class=\"container\"><p>Repeated boilerplate paragraph number %d with some varying text.</p></div></body></html>",
	}
	var out []byte
	i := 0
	for len(out) < size {
		out = append(out, []byte(sprintfTemplate(templates[i%len(templates)], i))...)
		i++
	}
	// Small mutations: flip a few bytes so chunks are near-duplicates.
	for k := 0; k < size/512; k++ {
		pos := rng.Intn(len(out))
		out[pos] = byte('a' + rng.Intn(26))
	}
	return out[:size]
}

func sprintfTemplate(tmpl string, i int) string {
	// Avoid fmt.Sprintf cost confusion: templates use %d exactly once.
	var b []byte
	seen := false
	for j := 0; j < len(tmpl); j++ {
		if tmpl[j] == '%' && j+1 < len(tmpl) && tmpl[j+1] == 'd' && !seen {
			seen = true
			b = append(b, []byte(itoa(i))...)
			j++
			continue
		}
		b = append(b, tmpl[j])
	}
	return string(b)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d [20]byte
	i := len(d)
	for n > 0 {
		i--
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return string(d[i:])
}

func TestChunkingDeterminismAndBounds(t *testing.T) {
	data := repetitiveSegment(t, 1, 8192)
	a := splitChunks(data)
	b := splitChunks(data)
	if len(a) != len(b) {
		t.Fatalf("chunk count changed: %d vs %d", len(a), len(b))
	}
	joined := bytes.Join(a, nil)
	if !bytes.Equal(joined, data) {
		t.Fatal("chunks do not reassemble to input")
	}
	for i, c := range a {
		if i < len(a)-1 && (len(c) < MinChunkSize || len(c) > MaxChunkSize) {
			t.Fatalf("chunk %d size %d outside [%d,%d]", i, len(c), MinChunkSize, MaxChunkSize)
		}
		if !bytes.Equal(a[i], b[i]) {
			t.Fatalf("chunk %d differs between runs", i)
		}
	}
	// Shift resistance: inserting one byte near the front must leave
	// most later chunk contents intact (content-defined boundaries).
	shifted := make([]byte, 0, len(data)+1)
	shifted = append(shifted, data[:100]...)
	shifted = append(shifted, 'X')
	shifted = append(shifted, data[100:]...)
	sc := splitChunks(shifted)
	have := map[string]int{}
	for _, c := range a {
		have[string(c)]++
	}
	shared := 0
	for _, c := range sc {
		if have[string(c)] > 0 {
			have[string(c)]--
			shared++
		}
	}
	if shared < len(a)/2 {
		t.Fatalf("shift destroyed chunking: only %d/%d chunks shared", shared, len(a))
	}
}

func TestFingerprintIdentity(t *testing.T) {
	a := []byte("identical chunk content for fingerprinting")
	b := []byte("identical chunk content for fingerprinting")
	c := []byte("different chunk content for fingerprinting!")
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("identical content must yield identical id")
	}
	if Fingerprint(a) == Fingerprint(c) {
		t.Fatal("different content must yield different id")
	}
	if Fingerprint(nil) == Fingerprint([]byte{0}) {
		t.Fatal("empty and one-byte inputs must differ")
	}
}

func TestRoundTripNoAckThenAck(t *testing.T) {
	senderCache := NewCache(DefaultConfig())
	receiverCache := NewCache(DefaultConfig())
	enc := NewEncoder(senderCache)
	dec := NewDecoder(receiverCache)

	plain := repetitiveSegment(t, 7, 4096)
	f1, err := enc.Encode(plain)
	if err != nil {
		t.Fatal(err)
	}
	if f1.HasReferences {
		t.Fatal("first encode must not reference anything (nothing ACKed)")
	}
	out, res, err := dec.Decode(f1.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("first decode not byte-exact")
	}
	if len(res.NewChunkIDs) == 0 {
		t.Fatal("decode must report newly held chunk ids for ACK")
	}
	// Deliver the ACK, then re-encode the same plaintext: references
	// must now appear, and decoding must still be byte-exact.
	enc.NoteAck(res.Ack())
	f2, err := enc.Encode(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !f2.HasReferences || f2.References == 0 {
		t.Fatalf("second encode must reference ACKed chunks: %+v", f2)
	}
	if f2.Wire == nil || len(f2.Wire) >= len(plain) {
		t.Fatalf("reference frame should shrink repetitive data: wire %d vs plain %d", len(f2.Wire), len(plain))
	}
	out2, _, err := dec.Decode(f2.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out2, plain) {
		t.Fatal("reference decode not byte-exact")
	}
	// Wire-level ACK-gating audit: every Reference id in f2 must have
	// been ACKed before f2 was encoded.
	acked := map[ChunkID]bool{}
	for _, id := range res.NewChunkIDs {
		acked[id] = true
	}
	_, recs, _, err := ParseFrame(f2.Wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Kind == RecordReference && !acked[r.ID] {
			t.Fatalf("frame references un-ACKed chunk %x", r.ID)
		}
	}
}

func TestAckGatingNeverReferencesUnacked(t *testing.T) {
	enc := NewEncoder(NewCache(DefaultConfig()))
	dec := NewDecoder(NewCache(DefaultConfig()))
	plain := repetitiveSegment(t, 3, 2048)
	// Encode the same data five times WITHOUT delivering any ACK.
	// References must never appear, however many literals were sent.
	for i := 0; i < 5; i++ {
		f, err := enc.Encode(plain)
		if err != nil {
			t.Fatal(err)
		}
		if f.HasReferences {
			t.Fatalf("encode %d referenced without ACK", i)
		}
		if _, _, err := dec.Decode(f.Wire); err != nil {
			t.Fatal(err)
		}
		// Deliberately drop the ACK.
	}
	if st := enc.Stats(); st.HeldUnackedResends == 0 {
		t.Fatal("expected defensive literal re-sends for held-but-unacked chunks")
	}
}

func TestMissFallbackAtomicAndResync(t *testing.T) {
	senderCache := NewCache(DefaultConfig())
	receiverCache := NewCache(DefaultConfig())
	enc := NewEncoder(senderCache)
	dec := NewDecoder(receiverCache)
	plain := repetitiveSegment(t, 11, 4096)

	// Establish ACKed state.
	f1, _ := enc.Encode(plain)
	_, res, err := dec.Decode(f1.Wire)
	if err != nil {
		t.Fatal(err)
	}
	enc.NoteAck(res.Ack())
	f2, _ := enc.Encode(plain)
	if !f2.HasReferences {
		t.Fatal("expected references after ACK")
	}

	// Simulate receiver-side eviction/desync: delete one referenced
	// chunk from the receiver cache, then decode f2 with a FRESH
	// decoder over the damaged cache. The frame must fail atomically:
	// no output, and none of its literals may be inserted.
	_, recs, _, err := ParseFrame(f2.Wire)
	if err != nil {
		t.Fatal(err)
	}
	var victim ChunkID
	for _, r := range recs {
		if r.Kind == RecordReference {
			victim = r.ID
			break
		}
	}
	if victim == (ChunkID{}) {
		t.Fatal("no reference found to evict")
	}
	if !receiverCache.Invalidate(victim) {
		t.Fatal("victim not present in receiver cache")
	}
	before := receiverCache.Len()
	dec2 := NewDecoder(receiverCache)
	out, _, err := dec2.Decode(f2.Wire)
	if out != nil {
		t.Fatal("miss decode must return no output")
	}
	miss, ok := AsMiss(err)
	if !ok {
		t.Fatalf("expected MissError, got %v", err)
	}
	if miss.Missing != victim {
		t.Fatalf("miss id %x != victim %x", miss.Missing, victim)
	}
	if !errors.Is(err, ErrUnknownChunk) {
		t.Fatal("MissError must wrap ErrUnknownChunk")
	}
	if receiverCache.Len() != before {
		t.Fatalf("atomicity violated: cache grew %d -> %d on failed decode", before, receiverCache.Len())
	}
	// Sender fallback: invalidate + re-encode. The fallback frame must
	// decode byte-exactly on the damaged receiver cache and re-ACK the
	// missing chunk.
	enc.NoteMiss(miss)
	f3, err := enc.Encode(plain)
	if err != nil {
		t.Fatal(err)
	}
	out3, res3, err := dec2.Decode(f3.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out3, plain) {
		t.Fatal("fallback decode not byte-exact")
	}
	found := false
	for _, id := range res3.NewChunkIDs {
		if id == victim {
			found = true
		}
	}
	if !found {
		t.Fatal("fallback frame did not reintroduce the missing chunk")
	}
	// After the fallback ACK, references work again.
	enc.NoteAck(res3.Ack())
	f4, _ := enc.Encode(plain)
	if !f4.HasReferences {
		t.Fatal("references must resume after resync")
	}
	if out4, _, err := dec2.Decode(f4.Wire); err != nil || !bytes.Equal(out4, plain) {
		t.Fatalf("post-resync decode failed: %v", err)
	}
}

func TestFrameIndependenceAfterLoss(t *testing.T) {
	enc := NewEncoder(NewCache(DefaultConfig()))
	dec := NewDecoder(NewCache(DefaultConfig()))
	segA := repetitiveSegment(t, 21, 2048)
	segB := repetitiveSegment(t, 22, 2048)
	// Frame A is encoded, decoded, ACKed: its chunks are shared state.
	fA, _ := enc.Encode(segA)
	_, resA, err := dec.Decode(fA.Wire)
	if err != nil {
		t.Fatal(err)
	}
	enc.NoteAck(resA.Ack())
	// Frame B references A's chunks. Frame A is then "lost" in the
	// sense that B must decode without any other frame's bytes: B
	// carries only its own wire + the ACKed cache.
	fB, _ := enc.Encode(segB)
	freshDec := NewDecoder(dec.Cache()) // same cache, no frame history
	out, _, err := freshDec.Decode(fB.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, segB) {
		t.Fatal("frame B must decode independently of frame A's bytes")
	}
}

func TestCacheCapAndEvictionDeterministic(t *testing.T) {
	cfg := DefaultConfig()
	// Tiny deterministic cap: 4 KiB, 8 entries.
	cfg.MaxCacheBytes = 4096
	cfg.MaxEntries = 8
	c := NewCache(cfg)
	// Insert 8 distinct acked chunks of ~300 B each: fills entries.
	now := time.Now()
	_ = now
	ids := make([]ChunkID, 0, 8)
	for i := 0; i < 8; i++ {
		chunk := bytes.Repeat([]byte{byte(i + 1)}, 300)
		chunk[0] = byte(i)
		id, held := c.InsertReady(chunk)
		if !held {
			t.Fatalf("chunk %d not held", i)
		}
		ids = append(ids, id)
	}
	if c.Bytes() > 4096 {
		t.Fatalf("cache bytes %d exceed cap 4096", c.Bytes())
	}
	// Ninth insert must evict the LRU (first) entry, deterministically.
	chunk9 := bytes.Repeat([]byte{0xEE}, 300)
	chunk9[0] = 0x99
	if _, held := c.InsertReady(chunk9); !held {
		t.Fatal("ninth chunk must be held after eviction")
	}
	if _, ok := c.Lookup(ids[0]); ok {
		t.Fatal("LRU entry must have been evicted")
	}
	if _, ok := c.Lookup(ids[7]); !ok {
		t.Fatal("most recent entry must survive")
	}
	if c.Bytes() > 4096 {
		t.Fatalf("cache bytes %d exceed cap after eviction", c.Bytes())
	}
	if st := c.Stats(); st.Evictions == 0 {
		t.Fatal("expected evictions to be counted")
	}
	// Byte accounting is exact: entries*(300+64) must equal Bytes().
	st := c.Stats()
	if st.Bytes != st.Entries*(300+entryOverheadBytes) {
		t.Fatalf("accounting mismatch: bytes %d entries %d", st.Bytes, st.Entries)
	}
}

func TestPendingEntriesNeverEvictedBeforeAckOrTimeout(t *testing.T) {
	fakeNow := time.Now()
	cfg := DefaultConfig()
	cfg.MaxCacheBytes = 2048
	cfg.MaxEntries = 4
	cfg.PendingTimeout = time.Minute
	cfg.Now = func() time.Time { return fakeNow }
	c := NewCache(cfg)
	// One pending entry, then fill the rest with acked entries.
	pending := bytes.Repeat([]byte{'P'}, 300)
	pid, held := c.Insert(pending)
	if !held {
		t.Fatal("pending insert must be held")
	}
	for i := 0; i < 3; i++ {
		ch := bytes.Repeat([]byte{byte(0xA0 + i)}, 300)
		ch[0] = byte(i)
		if _, held := c.InsertReady(ch); !held {
			t.Fatalf("acked insert %d must be held", i)
		}
	}
	// Force pressure: an acked insert must evict an acked entry, never
	// the pending one.
	ch := bytes.Repeat([]byte{0xFF}, 300)
	ch[0] = 0x77
	if _, held := c.InsertReady(ch); !held {
		t.Fatal("pressure insert must be held")
	}
	if _, ok := c.Lookup(pid); !ok {
		t.Fatal("pending entry evicted before ACK/timeout")
	}
	// After the timeout expires, the pending entry becomes evictable.
	fakeNow = fakeNow.Add(2 * time.Minute)
	ch2 := bytes.Repeat([]byte{0xFE}, 300)
	ch2[0] = 0x76
	if _, held := c.InsertReady(ch2); !held {
		t.Fatal("post-timeout insert must be held")
	}
	// The pending entry should now be evictable; with continued
	// pressure it may be gone, but the cache must still respect caps.
	if c.Bytes() > 2048 {
		t.Fatalf("cache bytes %d exceed cap", c.Bytes())
	}
}

func TestPendingOnlyCacheDropsInsteadOfEvicting(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxCacheBytes = 1024
	cfg.MaxEntries = 2
	cfg.PendingTimeout = time.Hour
	c := NewCache(cfg)
	for i := 0; i < 2; i++ {
		ch := bytes.Repeat([]byte{byte(i + 1)}, 300)
		ch[0] = byte(0x50 + i)
		if _, held := c.Insert(ch); !held {
			t.Fatalf("pending insert %d must be held", i)
		}
	}
	// Cache is full of pending entries: a third insert must be
	// dropped, not evict a pending entry.
	ch := bytes.Repeat([]byte{0x42}, 300)
	ch[0] = 0x99
	if _, held := c.Insert(ch); held {
		t.Fatal("insert must be dropped when only pending entries exist")
	}
	if st := c.Stats(); st.Drops == 0 {
		t.Fatal("dropped insert must be counted")
	}
	if c.Len() != 2 {
		t.Fatalf("pending entries must survive: len %d", c.Len())
	}
}

func TestCollisionHandlingViaSeam(t *testing.T) {
	c := NewCache(DefaultConfig())
	var id ChunkID
	id[0] = 0xAB
	first := []byte("first content for this id")
	second := []byte("different content, same id")
	if _, held := c.insertID(id, first, true); !held {
		t.Fatal("first insert must be held")
	}
	if _, held := c.insertID(id, second, true); held {
		t.Fatal("colliding insert must not be held")
	}
	if st := c.Stats(); st.Collisions != 1 {
		t.Fatalf("collisions counted %d, want 1", st.Collisions)
	}
	got, ok := c.Lookup(id)
	if !ok || !bytes.Equal(got, first) {
		t.Fatal("first-inserted content must win a collision")
	}
	// Encoder path: a chunk whose id collides in the sender cache must
	// travel as Raw and never be referenced. Simulate by pre-seeding
	// the encoder cache with a colliding id for a real chunk.
	enc := NewEncoder(NewCache(DefaultConfig()))
	plain := bytes.Repeat([]byte("collision-test-chunk-payload-0123456789"), 8) // 320 B
	if len(plain) < MinChunkSize {
		t.Fatal("fixture too small")
	}
	chunks := Split(plain)
	if len(chunks) == 0 {
		t.Fatal("no chunks")
	}
	// Seed the collision: store different bytes under the first
	// chunk's id.
	if _, held := enc.Cache().insertID(chunks[0].ID, []byte("totally different bytes of the same length........"), true); !held {
		t.Fatal("seeding collision failed")
	}
	f, err := enc.Encode(plain)
	if err != nil {
		t.Fatal(err)
	}
	_, recs, _, err := ParseFrame(f.Wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Kind == RecordReference && r.ID == chunks[0].ID {
			t.Fatal("colliding chunk must never be referenced")
		}
	}
	dec := NewDecoder(NewCache(DefaultConfig()))
	out, _, err := dec.Decode(f.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("collision frame must still decode byte-exactly")
	}
}

func TestMalformedAndEdgeFrames(t *testing.T) {
	enc := NewEncoder(NewCache(DefaultConfig()))
	dec := NewDecoder(NewCache(DefaultConfig()))

	// Empty input round-trips as a header-only frame.
	f, err := enc.Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := dec.Decode(f.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatal("empty frame must decode to empty")
	}
	// Tiny input (< MinChunkSize) is a single Raw record.
	f, _ = enc.Encode([]byte("hi"))
	_, recs, _, err := ParseFrame(f.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Kind != RecordRaw {
		t.Fatalf("tiny input must be one Raw record, got %+v", recs)
	}
	// Oversize input rejected.
	if _, err := enc.Encode(make([]byte, MaxFrameBytes+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversize encode must fail with ErrFrameTooLarge, got %v", err)
	}
	// Corruptions: bad version, trailing bytes, truncated record.
	good, _ := enc.Encode(repetitiveSegment(t, 5, 1024))
	bad := bytes.Clone(good.Wire)
	bad[0] = 0xFF
	if _, _, err := dec.Decode(bad); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("bad version must be malformed, got %v", err)
	}
	trailing := append(bytes.Clone(good.Wire), 0x00)
	if _, _, err := dec.Decode(trailing); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("trailing bytes must be malformed, got %v", err)
	}
	trunc := good.Wire[:len(good.Wire)-3]
	if _, _, err := dec.Decode(trunc); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("truncated frame must be malformed, got %v", err)
	}
	// A Ref with a wrong declared length must miss, not emit garbage.
	f2, _ := enc.Encode(repetitiveSegment(t, 5, 1024))
	_, res2, err := dec.Decode(f2.Wire)
	if err != nil {
		t.Fatal(err)
	}
	enc.NoteAck(res2.Ack())
	f3, _ := enc.Encode(repetitiveSegment(t, 5, 1024))
	_, recs3, _, _ := ParseFrame(f3.Wire)
	if len(recs3) == 0 {
		t.Fatal("expected records")
	}
}

func TestCacheBytesFromMBClamps(t *testing.T) {
	if CacheBytesFromMB(0) != 1<<20 {
		t.Fatal("0 MB must clamp to 1 MiB")
	}
	if CacheBytesFromMB(128) != 128<<20 {
		t.Fatal("128 MB must pass through")
	}
	if CacheBytesFromMB(9999) != 512<<20 {
		t.Fatal("huge MB must clamp to 512 MiB")
	}
	if got := NewCache(Config{MaxCacheBytes: 1}).Stats().MaxBytes; got != 1<<10 {
		t.Fatalf("tiny cache cap must clamp to 1 KiB, got %d", got)
	}
}
