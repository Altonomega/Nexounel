package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePortRange parses a port range written as "lo-hi" or a single port
// "p" (equivalent to "p-p"). Ports must be in 1..65535 with lo <= hi.
// It never touches the network or the filesystem.
func ParsePortRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("empty port range")
	}
	parts := strings.SplitN(s, "-", 2)
	parse := func(p string) (int, error) {
		p = strings.TrimSpace(p)
		if p == "" {
			return 0, fmt.Errorf("invalid port range %q", s)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("invalid port %q in range %q", p, s)
		}
		return n, nil
	}
	lo, err := parse(parts[0])
	if err != nil {
		return 0, 0, err
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = parse(parts[1])
		if err != nil {
			return 0, 0, err
		}
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("invalid port range %q: end before start", s)
	}
	return lo, hi, nil
}

// validNodeID reports whether id is a usable node identifier:
// 1..64 chars, ASCII letters/digits/'-'/'_', starting alphanumeric.
// Shared by client NODE_ID and server registry validation so both sides
// enforce the same rule.
func validNodeID(id string) bool {
	id = strings.TrimSpace(id)
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for i, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case (r == '-' || r == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}
