package udpserver

import (
	"encoding/binary"
	"testing"

	"github.com/Altonomega/Nexounel/core/internal/config"
)

func portPayload(port int) []byte {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	return p
}

func TestResolveStreamTargetPortLegacyIgnoresPayload(t *testing.T) {
	cfg := config.ServerConfig{ForwardIP: "127.0.0.1", ForwardPort: 9000}
	for _, payload := range [][]byte{nil, {}, portPayload(10001), {1, 2, 3}, portPayload(0)} {
		port, ok := resolveStreamTargetPort(payload, cfg)
		if !ok || port != 9000 {
			t.Fatalf("payload %v: got (%d, %v), want (9000, true)", payload, port, ok)
		}
	}
}

func TestResolveStreamTargetPortAllowlist(t *testing.T) {
	cfg := config.ServerConfig{ForwardIP: "127.0.0.1", ForwardPort: 9000, ForwardPortRange: "10001-10010"}
	cases := []struct {
		name    string
		payload []byte
		port    int
		ok      bool
	}{
		{"in range low", portPayload(10001), 10001, true},
		{"in range high", portPayload(10010), 10010, true},
		{"below range", portPayload(10000), 0, false},
		{"above range", portPayload(10011), 0, false},
		{"port zero", portPayload(0), 0, false},
		{"one byte", []byte{0x27}, 0, false},
		{"three bytes", []byte{0x27, 0x11, 0x00}, 0, false},
		// Fixed port is outside the allowlist: no legacy fallback.
		{"empty payload fixed outside", nil, 0, false},
		{"empty payload fixed outside 2", []byte{}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port, ok := resolveStreamTargetPort(tc.payload, cfg)
			if ok != tc.ok || port != tc.port {
				t.Fatalf("got (%d, %v), want (%d, %v)", port, ok, tc.port, tc.ok)
			}
		})
	}
}

func TestResolveStreamTargetPortAllowlistEmptyPayloadFallback(t *testing.T) {
	cfg := config.ServerConfig{ForwardIP: "127.0.0.1", ForwardPort: 10005, ForwardPortRange: "10001-10010"}
	port, ok := resolveStreamTargetPort(nil, cfg)
	if !ok || port != 10005 {
		t.Fatalf("got (%d, %v), want (10005, true)", port, ok)
	}
}

func TestResolveStreamTargetPortAllowlistNoFixedPort(t *testing.T) {
	// ForwardPort 0 with an allowlist: ranged requests still resolve.
	cfg := config.ServerConfig{ForwardIP: "127.0.0.1", ForwardPort: 0, ForwardPortRange: "10001-10010"}
	port, ok := resolveStreamTargetPort(portPayload(10007), cfg)
	if !ok || port != 10007 {
		t.Fatalf("got (%d, %v), want (10007, true)", port, ok)
	}
	if _, ok := resolveStreamTargetPort(nil, cfg); ok {
		t.Fatal("empty payload with no fixed port must be rejected")
	}
}
