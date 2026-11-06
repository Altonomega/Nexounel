// Bootstrap sessions: trial decryption against pending join-token
// keys.
//
// A brand-new node has no registry key, so it cannot open a normal
// session — yet the DNS tunnel is its only path to the mother.
// Enrollment solves this with a bootstrap session keyed by the
// token-derived key (enroll.BootstrapKey). The panel pushes the
// derived key to the server over the control socket when it issues
// a token (add-bootstrap-key) and removes it when the token is
// consumed, revoked, or expires.
//
// Trial design: the normal ingress path trial-decrypts against the
// node codec set first, exactly as before. Only when no node codec
// authenticates the frame does handleTunnelCandidate fall back to
// the bootstrap set. Normal traffic pays nothing for the fallback
// (it runs only on frames the node trial already rejected), and
// the codec-snapshot, preferred-codec, and swap machinery is
// untouched: bootstrap codecs live in a separate atomic snapshot,
// appended to nothing, tried last, and never attributed to a node.
//
// A frame that decrypts under a bootstrap codec yields a session
// of kind bootstrap (see sessionRecord.Kind), restricted at the
// session layer to the enrollment target only. The bootstrap codec
// is single-purpose: it authenticates bootstrap sessions and
// nothing else, and it dies with the token.
package udpserver

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/security"
	VpnProto "github.com/Altonomega/Nexounel/core/internal/vpnproto"
)

// maxBootstrapKeys bounds the pending bootstrap set: trial cost
// and memory stay trivial, and a runaway issuer cannot flood the
// server with keys. Outstanding tokens are few by construction
// (one per pending join); 64 is generous.
const maxBootstrapKeys = 64

// bootstrapSweepInterval bounds how long an expired key can linger
// in the snapshot between sweeps. Expiry is also enforced at
// session creation, so a missed sweep is never an authentication
// hole, only a stale entry.
const bootstrapSweepInterval = time.Minute

// bootstrapKeyEntry is one pending bootstrap key: the token
// fingerprint that names it, the codec built from the derived key,
// and the token expiry after which it authenticates nothing.
type bootstrapKeyEntry struct {
	fingerprint string
	codec       *security.Codec
	expiresAt   time.Time
}

// bootstrapCodecSet is one immutable snapshot of the pending set,
// swapped atomically like the node codec set.
type bootstrapCodecSet struct {
	entries []bootstrapKeyEntry
}

// bootstrapState lives on the Server: the atomic snapshot plus the
// mutex guarding rebuilds and the last-sweep watermark. It is a
// value field so a zero Server (as tests build) stays usable: the
// zero mutex, atomic pointer, and atomic counter are all valid.
type bootstrapState struct {
	mu        sync.Mutex
	snapshot  atomic.Pointer[bootstrapCodecSet]
	lastSweep atomic.Int64 // unix nanos
}

// bootstrapState returns the server's bootstrap-key state.
func (s *Server) bootstrapState() *bootstrapState {
	return &s.bootstrap
}

// AddBootstrapKey implements control.BootstrapKeyStore: install the
// derived key for fingerprint until expiresAt. It validates its
// inputs defensively (the control handler validates too) and
// refuses to grow the set past the cap. Re-adding a fingerprint
// replaces its key and expiry (re-issue).
func (s *Server) AddBootstrapKey(fingerprint string, key []byte, expiresAt time.Time) error {
	if s == nil {
		return errors.New("bootstrap keys require a server")
	}
	if !validBootstrapFingerprint(fingerprint) {
		return errors.New("bootstrap fingerprint must be 64 lowercase hex chars")
	}
	if len(key) != 32 {
		return errors.New("bootstrap key must be 32 bytes")
	}
	if !expiresAt.After(time.Now()) {
		return errors.New("bootstrap key expiry must be in the future")
	}
	codec, err := security.NewCodec(s.cfg.DataEncryptionMethod, hex.EncodeToString(key))
	if err != nil {
		return fmt.Errorf("build bootstrap codec: %w", err)
	}
	st := s.bootstrapState()
	st.mu.Lock()
	defer st.mu.Unlock()
	current := st.snapshot.Load()
	entries := make([]bootstrapKeyEntry, 0, maxBootstrapKeys)
	now := time.Now()
	replaced := false
	if current != nil {
		for _, e := range current.entries {
			if e.fingerprint == fingerprint {
				entries = append(entries, bootstrapKeyEntry{fingerprint: fingerprint, codec: codec, expiresAt: expiresAt})
				replaced = true
				continue
			}
			if e.expiresAt.After(now) {
				entries = append(entries, e)
			}
		}
	}
	if !replaced {
		if len(entries) >= maxBootstrapKeys {
			return fmt.Errorf("bootstrap key set is full (%d pending keys)", maxBootstrapKeys)
		}
		entries = append(entries, bootstrapKeyEntry{fingerprint: fingerprint, codec: codec, expiresAt: expiresAt})
	}
	st.snapshot.Store(&bootstrapCodecSet{entries: entries})
	st.lastSweep.Store(now.UnixNano())
	return nil
}

// RemoveBootstrapKey implements control.BootstrapKeyStore: drop
// the key for fingerprint. Removing an unknown fingerprint
// succeeds (idempotent).
func (s *Server) RemoveBootstrapKey(fingerprint string) error {
	if s == nil {
		return errors.New("bootstrap keys require a server")
	}
	if !validBootstrapFingerprint(fingerprint) {
		return errors.New("bootstrap fingerprint must be 64 lowercase hex chars")
	}
	st := s.bootstrapState()
	st.mu.Lock()
	defer st.mu.Unlock()
	current := st.snapshot.Load()
	if current == nil {
		return nil
	}
	entries := make([]bootstrapKeyEntry, 0, len(current.entries))
	now := time.Now()
	for _, e := range current.entries {
		if e.fingerprint == fingerprint {
			continue
		}
		if e.expiresAt.After(now) {
			entries = append(entries, e)
		}
	}
	st.snapshot.Store(&bootstrapCodecSet{entries: entries})
	st.lastSweep.Store(now.UnixNano())
	return nil
}

// validBootstrapFingerprint reports whether fp is a token
// fingerprint: 64 lowercase hex chars (SHA-256 hex). Shared with
// the control handler's validation so both layers refuse the same
// malformed names.
func validBootstrapFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, r := range fp {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// bootstrapSnapshot loads the current pending set (possibly nil
// when no keys were ever installed).
func (s *Server) bootstrapSnapshot() *bootstrapCodecSet {
	if s == nil {
		return nil
	}
	return s.bootstrapState().snapshot.Load()
}

// bootstrapFingerprintForCodec attributes a decrypting codec to a
// pending bootstrap key by pointer identity, skipping expired
// entries: an expired key authenticates no new session even if its
// snapshot entry lingers until the next sweep. It returns false
// for node codecs and unknown codecs.
func (s *Server) bootstrapFingerprintForCodec(codec *security.Codec) (string, bool) {
	if s == nil || codec == nil {
		return "", false
	}
	set := s.bootstrapSnapshot()
	if set == nil {
		return "", false
	}
	now := time.Now()
	for _, e := range set.entries {
		if e.codec == codec {
			if !e.expiresAt.After(now) {
				return "", false
			}
			return e.fingerprint, true
		}
	}
	return "", false
}

// sweepBootstrapKeys drops expired entries. It runs under the
// rebuild mutex on add/remove and opportunistically (at most once
// a minute) from the trial path, so the set cannot grow stale
// without bound.
func (s *Server) sweepBootstrapKeys() {
	if s == nil {
		return
	}
	st := s.bootstrapState()
	now := time.Now()
	if now.UnixNano()-st.lastSweep.Load() < bootstrapSweepInterval.Nanoseconds() {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if now.UnixNano()-st.lastSweep.Load() < bootstrapSweepInterval.Nanoseconds() {
		return
	}
	current := st.snapshot.Load()
	if current == nil {
		st.lastSweep.Store(now.UnixNano())
		return
	}
	entries := make([]bootstrapKeyEntry, 0, len(current.entries))
	for _, e := range current.entries {
		if e.expiresAt.After(now) {
			entries = append(entries, e)
		}
	}
	st.snapshot.Store(&bootstrapCodecSet{entries: entries})
	st.lastSweep.Store(now.UnixNano())
}

// bootstrapTrialCodecs returns the unexpired bootstrap codecs and
// their parallel fingerprints for one trial. Empty when no pending
// keys exist. Callers sweep opportunistically first so expired
// entries do not accumulate between add/remove rebuilds.
func (s *Server) bootstrapTrialCodecs() ([]*security.Codec, []string) {
	set := s.bootstrapSnapshot()
	if set == nil || len(set.entries) == 0 {
		return nil, nil
	}
	s.sweepBootstrapKeys()
	now := time.Now()
	codecs := make([]*security.Codec, 0, len(set.entries))
	fingerprints := make([]string, 0, len(set.entries))
	for _, e := range set.entries {
		if !e.expiresAt.After(now) {
			continue
		}
		codecs = append(codecs, e.codec)
		fingerprints = append(fingerprints, e.fingerprint)
	}
	return codecs, fingerprints
}

// tryBootstrapTrial trial-decrypts labels against the pending
// bootstrap set (unexpired entries only) and returns the decoded
// packet with the fingerprint of the key that authenticated it.
// inflate selects the inflating parse (synchronous ingress path);
// match selects the candidate matcher (strict admission). The
// broad variant (match=false) mirrors the node-codec admission
// fallback: the worker applies strict semantics downstream.
// False means no bootstrap key authenticated the frame: the caller
// answers with no data, exactly as for a wrong-key frame.
func (s *Server) tryBootstrapTrial(labels string, inflate, match bool) (VpnProto.Packet, string, bool) {
	codecs, fingerprints := s.bootstrapTrialCodecs()
	if len(codecs) == 0 {
		return VpnProto.Packet{}, "", false
	}
	var packet VpnProto.Packet
	var idx int
	var err error
	switch {
	case match && inflate:
		packet, idx, err = VpnProto.ParseInflatedFromLabelsAnyMatching(labels, codecs, 0, s.matchesInboundPacketCandidate)
	case match:
		packet, idx, err = VpnProto.ParseFromLabelsAnyMatching(labels, codecs, 0, s.matchesInboundPacketCandidate)
	default:
		packet, idx, err = VpnProto.ParseFromLabelsAny(labels, codecs, 0)
	}
	if err != nil || idx < 0 || idx >= len(fingerprints) {
		return VpnProto.Packet{}, "", false
	}
	return packet, fingerprints[idx], true
}

// tryBootstrapDecrypt is the synchronous-path bootstrap trial:
// inflating parse with the candidate matcher.
func (s *Server) tryBootstrapDecrypt(labels string) (VpnProto.Packet, string, bool) {
	return s.tryBootstrapTrial(labels, true, true)
}
