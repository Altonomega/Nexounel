// Reserved stream targets: the STREAM_SYN payload framing that
// addresses a stream at an intercepted handler (enrollment,
// control) instead of a forward port.
//
// Normal STREAM_SYN payloads are empty (legacy fixed forward port)
// or a 2-byte big-endian port. A reserved payload is longer, starts
// with a 4-byte magic, and carries a short target name. The two
// shapes cannot collide: resolveStreamTargetPort rejects every
// payload whose length is neither 0 nor 2, so a reserved payload
// can never be mistaken for a port, and a port payload can never
// parse as a reserved target. The server checks the reserved
// framing BEFORE the port resolution, and anything that is neither
// a valid port payload nor a valid reserved payload is rejected
// fail-closed with no dial.
package enroll

import (
	"errors"
)

// reservedTargetMagic marks a STREAM_SYN payload as a reserved
// target address. It is not a secret: it only routes the stream.
const reservedTargetMagic = "NXCT"

// reservedTargetVersion is the only supported framing version.
const reservedTargetVersion = 1

// reservedTargetMaxName bounds the target name: short identifiers
// only ("enroll", "control"). Longer names are rejected, never
// truncated.
const reservedTargetMaxName = 32

// MarshalTarget encodes target as a reserved STREAM_SYN payload.
// Unknown targets are encoded verbatim: addressing is not
// authorization. The server enforces AllowedTarget per session
// kind and rejects targets it does not serve.
func MarshalTarget(target string) ([]byte, error) {
	if err := validateTargetName(target); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 5+len(target))
	out = append(out, reservedTargetMagic...)
	out = append(out, reservedTargetVersion)
	out = append(out, target...)
	return out, nil
}

// ParseTarget decodes a STREAM_SYN payload. It reports whether the
// payload is a reserved target address: false for every other
// shape (empty, 2-byte port, or anything else), including payloads
// that start with the magic but are otherwise malformed — those
// are not reserved targets, and the caller's port path rejects
// them fail-closed.
func ParseTarget(payload []byte) (string, bool) {
	if len(payload) < 5+1 || len(payload) > 5+reservedTargetMaxName {
		return "", false
	}
	if string(payload[:4]) != reservedTargetMagic {
		return "", false
	}
	if payload[4] != reservedTargetVersion {
		return "", false
	}
	target := string(payload[5:])
	if err := validateTargetName(target); err != nil {
		return "", false
	}
	return target, true
}

func validateTargetName(target string) error {
	if target == "" {
		return errors.New("reserved target name is empty")
	}
	if len(target) > reservedTargetMaxName {
		return errors.New("reserved target name is too long")
	}
	for _, r := range target {
		if r < 'a' || r > 'z' {
			return errors.New("reserved target name must be lowercase ASCII letters")
		}
	}
	return nil
}

// IsReservedTarget reports whether payload carries the reserved
// magic prefix, regardless of validity: for logging only, never
// for routing decisions (ParseTarget decides).
func IsReservedTarget(payload []byte) bool {
	return len(payload) >= 4 && string(payload[:4]) == reservedTargetMagic
}

// TargetName normalizes a caller-supplied target for logging: the
// raw name when valid, "<invalid>" otherwise. It never echoes
// payload bytes verbatim into logs.
func TargetName(payload []byte) string {
	if target, ok := ParseTarget(payload); ok {
		return target
	}
	if IsReservedTarget(payload) {
		return "<invalid>"
	}
	return "<port>"
}
