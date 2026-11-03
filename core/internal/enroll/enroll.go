// Package enroll implements the outbound-only manual node join (§3):
// join-token issuance and lifecycle, the token-bound bootstrap
// session key, the public bootstrap capability, and the enrollment
// request/response framing.
//
// The bootstrap paradox: a brand-new node has no key, so it cannot
// open a normal keyed session — yet the only reliable path from the
// node to the mother is the DNS tunnel itself. The design separates
// two things that must not be confused:
//
//   - the bootstrap capability: a published, non-secret label that
//     identifies a session as an enrollment session. It grants access
//     to exactly one endpoint (the enrollment handler) and to nothing
//     else. It is shipped in the installer and is not a credential.
//   - the join token: the actual secret. Single-use, short-lived,
//     ≥128 bits of entropy, bound to one pre-registered node identity.
//
// The bootstrap session key is derived from the token with HKDF, so
// only the token holder can decrypt the enrollment exchange even
// though the DNS queries themselves are observable.
//
// Storage note (spec discrepancy D-1, recorded in docs and the
// milestone report): the spec says the panel stores "only a hash of
// the token", but the token-bound session encryption requires the
// server side to decrypt the bootstrap session, which is impossible
// from a hash alone. This package therefore stores the DERIVED
// bootstrap key (HKDF output, 32 bytes) alongside the hash. The raw
// token is never stored, never logged, and the derived key is
// single-purpose — it decrypts bootstrap sessions only, is useless
// after the token burns or expires, and is deleted with the entry.
// The security property the spec intends (no recoverable token on
// disk) is preserved; the letter ("hash only") cannot hold together
// with token-bound encryption and is resolved in favor of the
// encryption requirement.
package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
)

// CapabilityLabel is the published, non-secret bootstrap capability
// (§3.1). A session presenting it is a bootstrap session: restricted
// to the enrollment target, rate-limited, and carrying no forward
// traffic. The label alone decrypts nothing.
const CapabilityLabel = "nexounel-bootstrap-v1"

// EnrollmentTarget is the reserved stream target identifier for the
// enrollment handler. It is never a real forward port: the server
// intercepts it instead of dialing.
const EnrollmentTarget = "enroll"

// ControlTarget is the reserved stream target identifier for
// node-to-mother control streams (§4.2). Like the enrollment target
// it is intercepted, never dialed.
const ControlTarget = "control"

// SessionKind distinguishes normal keyed sessions from bootstrap
// sessions at the session layer.
type SessionKind int

const (
	// SessionKindNormal is a keyed data-plane session.
	SessionKindNormal SessionKind = iota
	// SessionKindBootstrap is an enrollment session presenting the
	// bootstrap capability.
	SessionKindBootstrap
)

// AllowedTarget enforces the session-layer restriction fail-closed:
// a bootstrap session may open ONLY the enrollment target; a normal
// session may open anything except the enrollment target (the
// control target is how its own control stream is addressed).
// Unknown kinds are denied everything.
func AllowedTarget(kind SessionKind, target string) bool {
	switch kind {
	case SessionKindBootstrap:
		return target == EnrollmentTarget
	case SessionKindNormal:
		return target != EnrollmentTarget
	default:
		return false
	}
}

// TokenSizeBytes is the raw entropy of a join token: 256 bits, above
// the spec's ≥128-bit floor.
const TokenSizeBytes = 32

// MaxTokenTTL bounds token lifetime: 24 hours (§3.1).
const MaxTokenTTL = 24 * time.Hour

// MaxVerificationFailures burns a token: five failed enrollment
// attempts after successful verification (§3.2).
const MaxVerificationFailures = 5

// GenerateToken mints a fresh join token: 32 random bytes in
// unpadded base64url (43 characters). It carries no identity: the
// binding to a node identity lives in the pending-join store.
func GenerateToken() (string, error) {
	raw := make([]byte, TokenSizeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate join token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// TokenFingerprint returns the full SHA-256 hex of the token string:
// the store key. It is not reversible and is safe to log.
func TokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// DisplayFingerprint returns the short loggable fingerprint (first
// 16 hex chars), matching the "fingerprint, never the value" rule.
func DisplayFingerprint(token string) string {
	fp := TokenFingerprint(token)
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}

// bootstrapSalt and bootstrapInfo fix the HKDF domain separation for
// bootstrap session keys. Both are public constants: the secrecy
// lives entirely in the token. The salt is fixed (not random) because
// both sides must derive the same key from the token alone, with no
// prior communication — the standard construction for a
// password-derived session key with a public salt.
var bootstrapSalt = sha256.Sum256([]byte("nexounel-bootstrap-v1:salt"))

const bootstrapInfo = "nexounel-bootstrap-v1"

// BootstrapKey derives the 32-byte bootstrap session key from a join
// token: HKDF-SHA256 over the token bytes with the fixed context.
// Only the token holder can derive it. The token string must decode
// to exactly TokenSizeBytes; anything else is rejected so a
// truncated or mistyped token can never derive a weak key.
func BootstrapKey(token string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return nil, fmt.Errorf("join token is not valid base64url: %w", err)
	}
	if len(raw) != TokenSizeBytes {
		return nil, fmt.Errorf("join token decodes to %d bytes, want %d", len(raw), TokenSizeBytes)
	}
	return deriveBootstrapKey(raw, bootstrapInfo), nil
}

// BootstrapKeyString returns the bootstrap key as lowercase hex: the
// form fed to the session codec as its raw key string (the codec
// hashes it per method, as with every key string).
func BootstrapKeyString(token string) (string, error) {
	key, err := BootstrapKey(token)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func deriveBootstrapKey(tokenBytes []byte, info string) []byte {
	reader := hkdf.New(sha256.New, tokenBytes, bootstrapSalt[:], []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(reader, out); err != nil {
		// HKDF-Expand over SHA-256 cannot short-read 32 bytes; a
		// failure here would be a programming error, not an input
		// problem. Fail closed with zeros rather than a partial key.
		return make([]byte, 32)
	}
	return out
}

// Errors for the token lifecycle. The enrollment handler maps these
// to wire error codes so the node can distinguish permanent failures
// (stop retrying, ask the operator for a fresh token) from transient
// ones (keep retrying within the TTL).
var (
	// ErrUnknownToken: no pending join matches the token fingerprint.
	ErrUnknownToken = errors.New("unknown join token")
	// ErrTokenExpired: the token's TTL elapsed.
	ErrTokenExpired = errors.New("join token expired")
	// ErrTokenUsed: the token already enrolled a node (single-use).
	ErrTokenUsed = errors.New("join token already used")
	// ErrTokenBurned: the token burned after too many failed attempts.
	ErrTokenBurned = errors.New("join token burned after too many failed attempts")
	// ErrTokenRevoked: the operator revoked the pending join.
	ErrTokenRevoked = errors.New("join token revoked")
)

// pendingJoin is one pending enrollment: the hash, the derived
// bootstrap key (see the package doc, D-1), expiry, and attempt
// accounting. The raw token is never held here.
type pendingJoin struct {
	nodeID       string
	fingerprint  string
	bootstrapKey []byte
	expiresAt    time.Time
	attempts     int
	used         bool
	burned       bool
	revoked      bool
}

// PendingView is the operator-visible pending join: fingerprints and
// state only, never token or key material.
type PendingView struct {
	NodeID      string
	Fingerprint string // display fingerprint (16 hex chars)
	ExpiresAt   time.Time
	Attempts    int
	Used        bool
	Burned      bool
	Revoked     bool
}

// PendingStore is the panel-side pending-join store: in-memory,
// mutex-guarded, single-use tokens with attempt counting and burn.
// It holds no raw tokens. Persistence across panel restarts is the
// panel's job (re-issue after restart); a restart invalidates
// outstanding tokens rather than risking double enrollment.
type PendingStore struct {
	mu      sync.Mutex
	entries map[string]*pendingJoin
	now     func() time.Time
}

// NewPendingStore builds an empty store. now, when non-nil, overrides
// the clock (tests); nil means time.Now.
func NewPendingStore(now func() time.Time) *PendingStore {
	if now == nil {
		now = time.Now
	}
	return &PendingStore{entries: make(map[string]*pendingJoin), now: now}
}

// Issue pre-registers nodeID and returns a fresh single-use token
// plus its pending view. The token is shown exactly once by the
// caller (the panel) and never stored. ttl <= 0 means the 24 h
// default; ttl > 24 h is refused.
func (s *PendingStore) Issue(nodeID string, ttl time.Duration) (string, PendingView, error) {
	if err := multisession.ValidateNodeID(nodeID); err != nil {
		return "", PendingView{}, err
	}
	if ttl <= 0 {
		ttl = MaxTokenTTL
	}
	if ttl > MaxTokenTTL {
		return "", PendingView{}, fmt.Errorf("join token TTL %s exceeds the %s maximum", ttl, MaxTokenTTL)
	}
	token, err := GenerateToken()
	if err != nil {
		return "", PendingView{}, err
	}
	key, err := BootstrapKey(token)
	if err != nil {
		return "", PendingView{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fp := TokenFingerprint(token)
	if _, dup := s.entries[fp]; dup {
		// Cryptographically negligible (256-bit space); treat as a
		// hard error rather than overwriting an outstanding token.
		return "", PendingView{}, errors.New("join token fingerprint collision: retry issuance")
	}
	now := s.now()
	s.entries[fp] = &pendingJoin{
		nodeID:       strings.TrimSpace(nodeID),
		fingerprint:  fp,
		bootstrapKey: key,
		expiresAt:    now.Add(ttl),
	}
	return token, PendingView{
		NodeID:      strings.TrimSpace(nodeID),
		Fingerprint: DisplayFingerprint(token),
		ExpiresAt:   now.Add(ttl),
	}, nil
}

// lookup finds an entry by token fingerprint without mutating it.
func (s *PendingStore) lookup(token string) (*pendingJoin, error) {
	fp := TokenFingerprint(token)
	entry, ok := s.entries[fp]
	if !ok {
		return nil, ErrUnknownToken
	}
	now := s.now()
	if entry.revoked {
		return nil, ErrTokenRevoked
	}
	if entry.burned {
		return nil, ErrTokenBurned
	}
	if entry.used {
		return nil, ErrTokenUsed
	}
	if !now.Before(entry.expiresAt) {
		return nil, ErrTokenExpired
	}
	return entry, nil
}

// Verify checks that token can enroll (hash, expiry, state) without
// consuming it. The caller consumes with Consume once enrollment
// succeeds. Verification alone never burns a token: burn counts
// failed enrollment attempts (RecordFailure), not lookups.
func (s *PendingStore) Verify(token string) (nodeID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.lookup(token)
	if err != nil {
		return "", err
	}
	return entry.nodeID, nil
}

// BootstrapKeyFor returns the derived bootstrap key for a verified
// token, so the enrollment handler can decrypt the bootstrap
// session. It performs the same checks as Verify and never returns
// key material for an unusable token.
func (s *PendingStore) BootstrapKeyFor(token string) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.lookup(token)
	if err != nil {
		return nil, "", err
	}
	return append([]byte(nil), entry.bootstrapKey...), entry.nodeID, nil
}

// Consume atomically verifies and burns the token: the single-use
// guarantee. A token that enrolled once can never enroll a second
// node — the second Consume reports ErrTokenUsed. A failed registry
// write must NOT consume the token (the node may retry within the
// TTL), so callers consume only after the registry write succeeds.
func (s *PendingStore) Consume(token string) (nodeID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.lookup(token)
	if err != nil {
		return "", err
	}
	entry.used = true
	return entry.nodeID, nil
}

// RecordFailure counts one failed enrollment attempt for a verified
// token (post-verification failures: session setup, key issuance,
// registry write). At MaxVerificationFailures the token burns and
// can never enroll. Failures for unknown tokens are unattributable
// and ignored.
func (s *PendingStore) RecordFailure(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.lookup(token)
	if err != nil {
		return
	}
	entry.attempts++
	if entry.attempts >= MaxVerificationFailures {
		entry.burned = true
	}
}

// Revoke deletes the pending join for nodeID (operator action). The
// token can never enroll afterwards; an already-enrolled node is
// unaffected (revocation of an enrolled node is a registry removal,
// not a pending-join operation).
func (s *PendingStore) Revoke(nodeID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fp, entry := range s.entries {
		if entry.nodeID == nodeID {
			delete(s.entries, fp)
			return true
		}
	}
	return false
}

// Sweep drops expired and used entries. Callers run it on a ticker;
// entries are also lazily refused by lookup, so a missed sweep is
// never a security hole, only a memory one.
func (s *PendingStore) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	dropped := 0
	for fp, entry := range s.entries {
		if entry.used || entry.burned || !now.Before(entry.expiresAt) {
			delete(s.entries, fp)
			dropped++
		}
	}
	return dropped
}

// List returns operator-visible pending joins, sorted by node ID.
// It never exposes token or key material.
func (s *PendingStore) List() []PendingView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PendingView, 0, len(s.entries))
	for _, entry := range s.entries {
		out = append(out, PendingView{
			NodeID:      entry.nodeID,
			Fingerprint: entry.fingerprint[:16],
			ExpiresAt:   entry.expiresAt,
			Attempts:    entry.attempts,
			Used:        entry.used,
			Burned:      entry.burned,
			Revoked:     entry.revoked,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// Enrollment wire framing (versioned JSON over the bootstrap
// session, which is encrypted with the token-derived key, so the
// token itself is confidentiality-protected in transit).

// EnrollmentVersion is the only supported framing version.
const EnrollmentVersion = 1

// EnrollmentRequest is the node's enrollment presentation: identity,
// token, and capability. The token field is a secret: it must never
// be logged, and this struct deliberately has no String method.
type EnrollmentRequest struct {
	Version    int    `json:"version"`
	NodeID     string `json:"node_id"`
	Token      string `json:"token"`
	Capability string `json:"capability"`
}

// EnrollmentResponse is the handler's answer: on success, the node's
// identity, per-node key, node configuration (TOML text), and mesh
// control secret; on failure, an error code distinguishing
// permanent from transient failures (§3.5). Key and secret fields
// are secrets: never log a response.
type EnrollmentResponse struct {
	Version           int    `json:"version"`
	NodeID            string `json:"node_id"`
	NodeKey           string `json:"node_key,omitempty"`
	NodeConfig        string `json:"node_config,omitempty"`
	MeshControlSecret string `json:"mesh_control_secret,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"`
	Error             string `json:"error,omitempty"`
}

// Enrollment error codes (wire values for ErrorCode).
const (
	ErrCodeUnknownToken = "token_unknown"
	ErrCodeExpiredToken = "token_expired"
	ErrCodeUsedToken    = "token_used"
	ErrCodeBurnedToken  = "token_burned"
	ErrCodeRevokedToken = "token_revoked"
	ErrCodeFailed       = "enrollment_failed"
)

// MarshalRequest encodes a request, stamping the framing version and
// the bootstrap capability.
func MarshalRequest(req EnrollmentRequest) ([]byte, error) {
	req.Version = EnrollmentVersion
	req.Capability = CapabilityLabel
	if strings.TrimSpace(req.NodeID) == "" || strings.TrimSpace(req.Token) == "" {
		return nil, errors.New("enrollment request requires node id and token")
	}
	return json.Marshal(req)
}

// ParseRequest decodes and validates a request: framing version and
// capability must match, and identity/token must be present. The
// token itself is verified against the store by the caller.
func ParseRequest(data []byte) (EnrollmentRequest, error) {
	var req EnrollmentRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return req, fmt.Errorf("decode enrollment request: %w", err)
	}
	if req.Version != EnrollmentVersion {
		return req, fmt.Errorf("unsupported enrollment version %d, want %d", req.Version, EnrollmentVersion)
	}
	if req.Capability != CapabilityLabel {
		return req, fmt.Errorf("enrollment capability mismatch")
	}
	if strings.TrimSpace(req.NodeID) == "" || strings.TrimSpace(req.Token) == "" {
		return req, errors.New("enrollment request requires node id and token")
	}
	return req, nil
}

// MarshalResponse encodes a response, stamping the framing version.
func MarshalResponse(resp EnrollmentResponse) ([]byte, error) {
	resp.Version = EnrollmentVersion
	return json.Marshal(resp)
}

// ParseResponse decodes and validates a response's framing version.
func ParseResponse(data []byte) (EnrollmentResponse, error) {
	var resp EnrollmentResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return resp, fmt.Errorf("decode enrollment response: %w", err)
	}
	if resp.Version != EnrollmentVersion {
		return resp, fmt.Errorf("unsupported enrollment version %d, want %d", resp.Version, EnrollmentVersion)
	}
	return resp, nil
}

// MapStoreError converts a token-lifecycle error to its wire code.
func MapStoreError(err error) string {
	switch {
	case errors.Is(err, ErrUnknownToken):
		return ErrCodeUnknownToken
	case errors.Is(err, ErrTokenExpired):
		return ErrCodeExpiredToken
	case errors.Is(err, ErrTokenUsed):
		return ErrCodeUsedToken
	case errors.Is(err, ErrTokenBurned):
		return ErrCodeBurnedToken
	case errors.Is(err, ErrTokenRevoked):
		return ErrCodeRevokedToken
	default:
		return ErrCodeFailed
	}
}
