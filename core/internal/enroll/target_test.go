package enroll

import (
	"bytes"
	"testing"
)

func TestMarshalParseTargetRoundTrip(t *testing.T) {
	for _, target := range []string{EnrollmentTarget, ControlTarget} {
		payload, err := MarshalTarget(target)
		if err != nil {
			t.Fatalf("MarshalTarget(%q): %v", target, err)
		}
		if len(payload) < 6 {
			t.Fatalf("MarshalTarget(%q): payload too short to be distinguishable from a port: %d bytes", target, len(payload))
		}
		got, ok := ParseTarget(payload)
		if !ok || got != target {
			t.Fatalf("ParseTarget(MarshalTarget(%q)) = %q, %v", target, got, ok)
		}
	}
}

func TestParseTargetRejectsPortPayloads(t *testing.T) {
	// Empty (legacy fixed port) and 2-byte port payloads are never
	// reserved targets.
	for _, payload := range [][]byte{nil, {}, {0x27, 0x10}, {0x00, 0x50}} {
		if target, ok := ParseTarget(payload); ok {
			t.Fatalf("ParseTarget(%x) = %q, true: port payload parsed as reserved", payload, target)
		}
	}
}

func TestParseTargetRejectsMalformedReserved(t *testing.T) {
	cases := [][]byte{
		[]byte("NXCT"),               // magic only, no version/name
		[]byte("NXCT\x01"),           // no name
		[]byte("NXCT\x02enroll"),     // wrong version
		[]byte("NXCU\x01enroll"),     // wrong magic
		[]byte("NXCT\x01Enroll"),     // uppercase
		[]byte("NXCT\x01enroll\x00"), // NUL in name
		[]byte("NXCT\x01" + string(bytes.Repeat([]byte("a"), 33))), // name too long
	}
	for _, payload := range cases {
		if target, ok := ParseTarget(payload); ok {
			t.Fatalf("ParseTarget(%q) = %q, true: malformed reserved payload accepted", payload, target)
		}
	}
}

func TestMarshalTargetRejectsInvalidNames(t *testing.T) {
	for _, target := range []string{"", "ENROLL", "enroll-me", "enroll/x", string(bytes.Repeat([]byte("a"), 33))} {
		if _, err := MarshalTarget(target); err == nil {
			t.Fatalf("MarshalTarget(%q) accepted an invalid target name", target)
		}
	}
}

func TestAllowedTargetMatrix(t *testing.T) {
	// The session-layer restriction, fail-closed both ways: a
	// bootstrap session opens ONLY the enrollment target, a normal
	// session opens anything EXCEPT it, unknown kinds open nothing.
	cases := []struct {
		kind   SessionKind
		target string
		want   bool
	}{
		{SessionKindBootstrap, EnrollmentTarget, true},
		{SessionKindBootstrap, ControlTarget, false},
		{SessionKindBootstrap, "other", false},
		{SessionKindNormal, EnrollmentTarget, false},
		{SessionKindNormal, ControlTarget, true},
		{SessionKindNormal, "other", true},
		{SessionKind(99), EnrollmentTarget, false},
		{SessionKind(99), ControlTarget, false},
	}
	for _, tc := range cases {
		if got := AllowedTarget(tc.kind, tc.target); got != tc.want {
			t.Fatalf("AllowedTarget(%d, %q) = %v, want %v", tc.kind, tc.target, got, tc.want)
		}
	}
}
