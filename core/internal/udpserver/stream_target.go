package udpserver

import (
	"encoding/binary"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
)

// resolveStreamTargetPort decides which port a TCP-forward STREAM_SYN
// should be dialed on.
//
// Without a FORWARD_PORT_RANGE allowlist it returns the legacy fixed
// FORWARD_PORT for every payload, preserving upstream behavior exactly
// (the payload is ignored).
//
// With an allowlist configured, the 2-byte big-endian payload carried by
// the client (the accepted connection's local port) must fall inside
// the allowlist, or the stream is rejected (ok=false, fail closed, no
// dial). An empty payload falls back to the fixed FORWARD_PORT, but
// only when that port is itself inside the allowlist; a malformed
// payload (any length other than 0 or 2) is always rejected.
//
// This is a pure function: no I/O, no server state.
func resolveStreamTargetPort(payload []byte, cfg config.ServerConfig) (int, bool) {
	lo, hi, ranged, err := cfg.ForwardPortRangeBounds()
	if err != nil || !ranged {
		return cfg.ForwardPort, true
	}
	if len(payload) == 0 {
		if cfg.ForwardPort >= lo && cfg.ForwardPort <= hi {
			return cfg.ForwardPort, true
		}
		return 0, false
	}
	if len(payload) != 2 {
		return 0, false
	}
	port := int(binary.BigEndian.Uint16(payload))
	if port < lo || port > hi {
		return 0, false
	}
	return port, true
}
