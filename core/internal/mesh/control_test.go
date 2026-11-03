package mesh

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestControlFrameRoundTripAllKinds(t *testing.T) {
	cases := []struct {
		kind    FrameKind
		payload any
	}{
		{KindHeartbeat, Heartbeat{NodeID: "node-1", Role: "plain", Version: "0.2.0", Term: Term{Number: 1}, CapacityBps: 1234.5, SentAt: time.Now().UTC().Truncate(time.Second)}},
		{KindTable, TablePush{Table: Table{Term: Term{Number: 1}, Version: 3, ChiefID: "node-1", Members: []Member{{ID: "node-1", State: StateActive, TenureSeq: 1}}, Weights: map[string]float64{"node-1": 1}}}},
		{KindTable, TablePush{Table: Table{Term: Term{Number: 1}, Version: 1}, Snapshot: &Snapshot{Table: Table{Term: Term{Number: 1}}, Signature: "ab"}}},
		{KindConfig, ConfigPush{Version: 7, TOML: "NODE_ID=node-1\n"}},
		{KindRotation, RotationOrder{NodeID: "node-1", NewKeyHex: strings.Repeat("ab", 32), Reason: "scheduled"}},
		{KindTerm, TermAnnouncement{Term: Term{Number: 2}, StepDown: true, Reason: "operator"}},
		{KindAck, Ack{For: KindConfig, AppliedVersion: 7, Message: "applied"}},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, tc.kind, tc.payload); err != nil {
			t.Fatalf("WriteFrame %s: %v", tc.kind, err)
		}
		f, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame %s: %v", tc.kind, err)
		}
		if f.Version != ControlFrameVersion || f.Kind != tc.kind {
			t.Fatalf("kind %s: got version=%d kind=%q", tc.kind, f.Version, f.Kind)
		}
		// Decode back into the same shape and compare JSON.
		want, _ := json.Marshal(tc.payload)
		var got json.RawMessage
		if err := f.Decode(&got); err != nil {
			t.Fatalf("Decode %s: %v", tc.kind, err)
		}
		if string(got) != string(want) {
			t.Fatalf("kind %s: payload mismatch\nwant %s\n got %s", tc.kind, want, got)
		}
	}
}

func TestControlFrameRejectsBadVersion(t *testing.T) {
	env, _ := json.Marshal(Frame{Version: 99, Kind: KindHeartbeat, Payload: json.RawMessage(`{}`)})
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(env)))
	buf.Write(hdr[:])
	buf.Write(env)
	if _, err := ReadFrame(&buf); err == nil || !strings.Contains(err.Error(), "version 99") {
		t.Fatalf("expected version error, got %v", err)
	}
}

func TestControlFrameRejectsUnknownKind(t *testing.T) {
	env, _ := json.Marshal(Frame{Version: 1, Kind: "bogus", Payload: json.RawMessage(`{}`)})
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(env)))
	buf.Write(hdr[:])
	buf.Write(env)
	if _, err := ReadFrame(&buf); err == nil || !strings.Contains(err.Error(), "unknown control frame kind") {
		t.Fatalf("expected kind error, got %v", err)
	}
}

func TestControlFrameRejectsOversizedLength(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxControlFrameBytes+1)
	buf.Write(hdr[:])
	if _, err := ReadFrame(&buf); err == nil || !strings.Contains(err.Error(), "out of bounds") {
		t.Fatalf("expected bounds error, got %v", err)
	}
}

func TestControlFrameRejectsZeroLength(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0})
	if _, err := ReadFrame(&buf); err == nil || !strings.Contains(err.Error(), "out of bounds") {
		t.Fatalf("expected bounds error, got %v", err)
	}
}

func TestControlFrameCleanEOF(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestControlFrameTruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 100)
	buf.Write(hdr[:])
	buf.WriteString("short")
	if _, err := ReadFrame(&buf); err == nil || !strings.Contains(err.Error(), "body") {
		t.Fatalf("expected body error, got %v", err)
	}
}

func TestControlFrameRejectsEmptyPayload(t *testing.T) {
	// An envelope with no payload key at all (a null payload would
	// unmarshal to the four bytes "null", which is not empty).
	env := []byte(`{"version":1,"kind":"ack"}`)
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(env)))
	buf.Write(hdr[:])
	buf.Write(env)
	if _, err := ReadFrame(&buf); err == nil || !strings.Contains(err.Error(), "empty payload") {
		t.Fatalf("expected empty-payload error, got %v", err)
	}
}

func TestControlFrameWriteRejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, KindConfig, ConfigPush{TOML: strings.Repeat("x", MaxControlFrameBytes)}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestControlFrameWriteRejectsUnknownKind(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, "bogus", nil); err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

func TestControlFrameDecodeEmptyPayload(t *testing.T) {
	f := Frame{Version: 1, Kind: KindAck}
	var ack Ack
	if err := f.Decode(&ack); err == nil {
		t.Fatal("expected error decoding empty payload")
	}
}

func TestControlFrameMultipleSequential(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, KindHeartbeat, Heartbeat{NodeID: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, KindAck, Ack{For: KindHeartbeat}); err != nil {
		t.Fatal(err)
	}
	f1, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if f1.Kind != KindHeartbeat || f2.Kind != KindAck {
		t.Fatalf("kinds out of order: %q %q", f1.Kind, f2.Kind)
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after two frames, got %v", err)
	}
}
