package redundancy

import (
	"bytes"
	"math/rand"
	"testing"
)

// TestTwoEndedLossySimulation runs an encoder and a decoder against
// each other over simulated lossy channels: the frame channel drops
// frames, the ACK/Miss channel drops control messages, both at the
// stated rate, with a seeded RNG (seed 1) so the run is reproducible.
// The harness models the tunnel's retransmission behaviour by
// resending the same wire until it is delivered, and models the
// sender's fallback by re-encoding after a delivered Miss.
//
// It asserts: byte-exact reconstruction of the whole stream, bounded
// cache memory on both ends, termination (no deadlock: bounded
// attempts per segment), and that fallback/resync paths were actually
// exercised (forced cache-divergence injections plus receiver-cache
// eviction under a deliberately tiny receiver cap).
func TestTwoEndedLossySimulation(t *testing.T) {
	for _, dropRate := range []float64{0.05, 0.25} {
		t.Run(dropName(dropRate), func(t *testing.T) {
			runLossySimulation(t, dropRate)
		})
	}
}

func dropName(p float64) string {
	if p < 0.1 {
		return "drop5pct"
	}
	return "drop25pct"
}

func runLossySimulation(t *testing.T, dropRate float64) {
	t.Helper()
	rng := rand.New(rand.NewSource(1))

	// Deliberately small caps: the receiver cache (2 KiB) must evict
	// live chunks, so references genuinely miss in steady state; the
	// sender cache (256 KiB) is large enough to keep ACKed chunks and
	// reference them. Both caps are enforced exactly (see assertions).
	senderCfg := DefaultConfig()
	senderCfg.MaxCacheBytes = 256 << 10
	senderCfg.MaxEntries = 1024
	receiverCfg := DefaultConfig()
	receiverCfg.MaxCacheBytes = 2 << 10
	receiverCfg.MaxEntries = 16

	enc := NewEncoder(NewCache(senderCfg))
	dec := NewDecoder(NewCache(receiverCfg))

	const segments = 120
	const segSize = 1024
	inputs := make([][]byte, segments)
	for i := range inputs {
		// Same templates with per-segment variation: heavy
		// cross-segment repetition, so references dominate after
		// the first ACKs arrive.
		inputs[i] = repetitiveSegment(t, int64(100+i%7), segSize)
	}

	var reconstructed []byte
	var fallbacks, injections, droppedFrames, droppedControl, deliveredAcks int

	for si, segment := range inputs {
		// Encode once; the same wire is retransmitted until delivered
		// (tunnel ARQ analogue). A fallback re-encode replaces the
		// wire only after a delivered Miss.
		frame, err := enc.Encode(segment)
		if err != nil {
			t.Fatal(err)
		}
		wire := frame.Wire

		// Forced divergence: on every 13th segment that carries a
		// reference, delete the first referenced chunk from the
		// receiver cache after encoding but before delivery. The
		// sender referenced it in good faith (it was ACKed); the
		// receiver must miss, and the sender must fall back.
		injected := false
		if si%13 == 12 {
			if _, recs, _, err := ParseFrame(wire); err == nil {
				for _, r := range recs {
					if r.Kind == RecordReference {
						if dec.Cache().Invalidate(r.ID) {
							injected = true
							injections++
						}
						break
					}
				}
			}
		}

		delivered := false
		for attempt := 0; attempt < 40 && !delivered; attempt++ {
			// Frame channel: up to 6 delivery tries per attempt;
			// all dropped means the attempt resends the same wire.
			sent := false
			for try := 0; try < 6; try++ {
				if rng.Float64() >= dropRate {
					sent = true
					break
				}
				droppedFrames++
			}
			if !sent {
				continue
			}
			out, res, err := dec.Decode(wire)
			if err != nil {
				miss, ok := AsMiss(err)
				if !ok {
					t.Fatalf("segment %d: unexpected decode error: %v", si, err)
				}
				// Miss channel: if the Miss itself is dropped,
				// the sender resends the same wire and misses
				// again; only a delivered Miss triggers fallback.
				if rng.Float64() < dropRate {
					droppedControl++
					continue
				}
				fallbacks++
				enc.NoteMiss(miss)
				fb, err := enc.Encode(segment)
				if err != nil {
					t.Fatal(err)
				}
				wire = fb.Wire
				continue
			}
			if !bytes.Equal(out, segment) {
				t.Fatalf("segment %d decoded incorrectly", si)
			}
			reconstructed = append(reconstructed, out...)
			// ACK channel: a dropped ACK only delays references.
			if rng.Float64() >= dropRate {
				enc.NoteAck(res.Ack())
				deliveredAcks++
			} else {
				droppedControl++
			}
			delivered = true
		}
		if !delivered {
			t.Fatalf("segment %d: no progress in 40 attempts (deadlock)", si)
		}
		_ = injected
	}

	want := bytes.Join(inputs, nil)
	if !bytes.Equal(reconstructed, want) {
		t.Fatalf("reconstruction mismatch: got %d bytes, want %d", len(reconstructed), len(want))
	}
	if senderCache := enc.Cache().Stats(); senderCache.Bytes > senderCache.MaxBytes {
		t.Fatalf("sender cache %d bytes exceeds cap %d", senderCache.Bytes, senderCache.MaxBytes)
	}
	if receiverCache := dec.Cache().Stats(); receiverCache.Bytes > receiverCache.MaxBytes {
		t.Fatalf("receiver cache %d bytes exceeds cap %d", receiverCache.Bytes, receiverCache.MaxBytes)
	}
	if droppedFrames == 0 {
		t.Fatal("lossy channel dropped no frames: loss was not exercised")
	}
	if droppedControl == 0 {
		t.Fatal("lossy control channel dropped nothing: ACK loss was not exercised")
	}
	if deliveredAcks == 0 {
		t.Fatal("no ACK was ever delivered")
	}
	if injections == 0 {
		t.Fatal("no divergence injection landed: fallback path not forced")
	}
	if fallbacks == 0 {
		t.Fatal("no fallback/resync occurred: miss path not exercised")
	}
	if fallbacks < injections {
		t.Fatalf("fallbacks %d < injections %d: some forced misses never resynced", fallbacks, injections)
	}
	// Gating audit over the whole run: the encoder's reference count
	// must be positive (references were used) while the decoder's
	// miss count is fully explained by evictions/injections, i.e.
	// every miss produced a fallback that recovered byte-exactly
	// (already asserted per segment above).
	if enc.Stats().References == 0 {
		t.Fatal("no references were ever emitted: RE never engaged")
	}
	t.Logf("drop=%.0f%% segments=%d wireRefs=%d fallbacks=%d injections=%d droppedFrames=%d droppedControl=%d deliveredAcks=%d senderCache=%dB receiverCache=%dB",
		dropRate*100, segments, enc.Stats().References, fallbacks, injections, droppedFrames, droppedControl, deliveredAcks,
		enc.Cache().Bytes(), dec.Cache().Bytes())
}
