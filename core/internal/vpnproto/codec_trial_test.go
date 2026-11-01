// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"bytes"
	"testing"

	"github.com/MNSH-Nexo/Nexounel/core/internal/compression"
	Enums "github.com/MNSH-Nexo/Nexounel/core/internal/enums"
	"github.com/MNSH-Nexo/Nexounel/core/internal/security"
)

// A 32-char shared key works for every method: deriveKey hashes/pads it per
// method, so one key string interoperates across the whole set.
const autoDetectKey = "0123456789abcdef0123456789abcdef"

func TestParseFromLabelsAnyMatchingDefersInflation(t *testing.T) {
	codec, err := security.NewCodec(3, autoDetectKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("compressible-native-payload-"), 32)
	labels, err := BuildEncodedAuto(BuildOptions{
		SessionID:       300,
		PacketType:      Enums.PACKET_STREAM_DATA,
		SessionCookie:   9,
		StreamID:        4,
		SequenceNum:     7,
		CompressionType: compression.TypeZLIB,
		Payload:         payload,
	}, codec, 1)
	if err != nil {
		t.Fatal(err)
	}

	packet, _, err := ParseFromLabelsAnyMatching(labels, []*security.Codec{codec}, 0, func(Packet) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if !packet.HasCompressionType || packet.CompressionType != compression.TypeZLIB {
		t.Fatalf("compression metadata was not preserved: %+v", packet)
	}
	if bytes.Equal(packet.Payload, payload) {
		t.Fatal("admission parser inflated payload on the reader path")
	}
	inflated, err := InflatePayload(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inflated.Payload, payload) {
		t.Fatal("worker inflation did not restore the original payload")
	}
}

// With a single configured codec, frames decode if and only if they were
// encrypted with that codec's method. A frame from any other AES-GCM method
// fails authentication and is rejected — there is no trial across methods.
func TestParseInflatedFromLabelsAnyDecodesConfiguredMethodOnly(t *testing.T) {
	payload := []byte("single-method-only")

	for _, method := range security.AllMethods {
		codec, err := security.NewCodec(method, autoDetectKey)
		if err != nil {
			t.Fatalf("NewCodec(%d): %v", method, err)
		}
		labels, err := BuildEncodedAuto(BuildOptions{
			PacketType: Enums.PACKET_PING,
			Payload:    payload,
		}, codec, compression.DefaultMinSize)
		if err != nil {
			t.Fatalf("BuildEncodedAuto(method %d): %v", method, err)
		}

		packet, detectedIdx, err := ParseInflatedFromLabelsAny(labels, []*security.Codec{codec}, 0)
		if err != nil {
			t.Fatalf("method %d: own frame failed to parse: %v", method, err)
		}
		if detectedIdx != 0 || packet.PacketType != Enums.PACKET_PING || !bytes.Equal(packet.Payload, payload) {
			t.Fatalf("method %d: unexpected parse result idx=%d packet=%+v", method, detectedIdx, packet)
		}

		for _, other := range security.AllMethods {
			if other == method {
				continue
			}
			otherCodec, err := security.NewCodec(other, autoDetectKey)
			if err != nil {
				t.Fatalf("NewCodec(%d): %v", other, err)
			}
			otherLabels, err := BuildEncodedAuto(BuildOptions{
				PacketType: Enums.PACKET_PING,
				Payload:    payload,
			}, otherCodec, compression.DefaultMinSize)
			if err != nil {
				t.Fatalf("BuildEncodedAuto(method %d): %v", other, err)
			}
			if _, _, err := ParseInflatedFromLabelsAny(otherLabels, []*security.Codec{codec}, 0); err == nil {
				t.Fatalf("method %d frame decoded with method %d codec: cross-method frames must be rejected", other, method)
			}
		}
	}
}

func TestParseInflatedFromLabelsAnySingleCodecDecodes(t *testing.T) {
	codec, err := security.NewCodec(3, autoDetectKey) // AES-128-GCM
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	labels, err := BuildEncodedAuto(BuildOptions{
		PacketType: Enums.PACKET_PONG,
		Payload:    []byte("x"),
	}, codec, compression.DefaultMinSize)
	if err != nil {
		t.Fatalf("BuildEncodedAuto: %v", err)
	}

	_, idx, err := ParseInflatedFromLabelsAny(labels, []*security.Codec{codec}, 0)
	if err != nil || idx != 0 {
		t.Fatalf("single-codec decode: idx=%d err=%v, want idx=0", idx, err)
	}
}

func TestParseInflatedFromLabelsAnyEmptySet(t *testing.T) {
	if _, _, err := ParseInflatedFromLabelsAny("abc", nil, 0); err == nil {
		t.Fatal("expected error for empty codec set")
	}
}

func TestMatchingParserKeepsUnambiguousNativeFastPath(t *testing.T) {
	codec, err := security.NewCodec(3, autoDetectKey)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	labels, err := BuildEncodedAuto(BuildOptions{
		SessionID:     300,
		SessionCookie: 0x5A,
		PacketType:    Enums.PACKET_PONG,
		Payload:       []byte("native-fast-path"),
	}, codec, compression.DefaultMinSize)
	if err != nil {
		t.Fatalf("BuildEncodedAuto: %v", err)
	}

	matchCalls := 0
	packet, _, err := ParseInflatedFromLabelsAnyMatching(labels, []*security.Codec{codec}, 0, func(Packet) bool {
		matchCalls++
		return false
	})
	if err != nil {
		t.Fatalf("ParseInflatedFromLabelsAnyMatching: %v", err)
	}
	if packet.SessionID != 300 || packet.LegacySessionID || packet.PacketType != Enums.PACKET_PONG {
		t.Fatalf("unexpected native packet: %+v", packet)
	}
	if matchCalls != 0 {
		t.Fatalf("unambiguous native frame performed %d session matches, want zero", matchCalls)
	}
}

func TestMatchingParserResolvesAmbiguousLegacyFrame(t *testing.T) {
	codec, err := security.NewCodec(3, autoDetectKey)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	labels, err := BuildEncodedAuto(BuildOptions{
		SessionID:       16,
		SessionCookie:   6,
		PacketType:      Enums.PACKET_PING,
		Payload:         []byte("PO:test"),
		LegacySessionID: true,
	}, codec, compression.DefaultMinSize)
	if err != nil {
		t.Fatalf("BuildEncodedAuto: %v", err)
	}

	packet, _, err := ParseInflatedFromLabelsAnyMatching(labels, []*security.Codec{codec}, 0, func(candidate Packet) bool {
		return candidate.LegacySessionID && candidate.SessionID == 16 && candidate.SessionCookie == 6
	})
	if err != nil {
		t.Fatalf("ParseInflatedFromLabelsAnyMatching: %v", err)
	}
	if !packet.LegacySessionID || packet.SessionID != 16 || packet.PacketType != Enums.PACKET_PING {
		t.Fatalf("unexpected resolved legacy packet: %+v", packet)
	}
}
