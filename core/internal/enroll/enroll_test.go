package enroll

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestGenerateToken(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		if len(tok) != 43 {
			t.Errorf("token length = %d, want 43 (32 bytes base64url)", len(tok))
		}
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil || len(raw) != TokenSizeBytes {
			t.Errorf("token must decode to %d bytes: %v", TokenSizeBytes, err)
		}
		if seen[tok] {
			t.Error("duplicate token generated")
		}
		seen[tok] = true
	}
}

func TestBootstrapKeyGoldenVector(t *testing.T) {
	// Cross-implementation check: token = base64url(bytes 0..31),
	// HKDF-SHA256 with the fixed salt/info. Expected value computed
	// independently (Python hashlib/hmac HKDF).
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	key, err := BootstrapKey(token)
	if err != nil {
		t.Fatalf("BootstrapKey: %v", err)
	}
	const want = "460d9068f449040a5eb231b2073e00ab04147e8b1ba2e3b553049a44e189babf"
	if got := strings.ToLower(hexEncode(key)); got != want {
		t.Errorf("bootstrap key = %s, want %s", got, want)
	}
	// Determinism: same token, same key.
	key2, _ := BootstrapKey(token)
	if string(key) != string(key2) {
		t.Error("bootstrap derivation must be deterministic")
	}
	// Distinct tokens → distinct keys.
	tok2, _ := GenerateToken()
	key3, err := BootstrapKey(tok2)
	if err != nil {
		t.Fatalf("BootstrapKey: %v", err)
	}
	if string(key) == string(key3) {
		t.Error("distinct tokens must derive distinct keys")
	}
	// Distinct context → distinct keys (domain separation).
	other := deriveBootstrapKey(raw, "nexounel-bootstrap-v1:other")
	if string(key) == string(other) {
		t.Error("distinct HKDF info must derive distinct keys")
	}
	// Malformed tokens rejected: bad base64, short payload.
	if _, err := BootstrapKey("not!base64"); err == nil {
		t.Error("invalid base64 token must be rejected")
	}
	short := base64.RawURLEncoding.EncodeToString([]byte("short"))
	if _, err := BootstrapKey(short); err == nil {
		t.Error("short token must be rejected")
	}
	// Hex form round-trips through the codec key-string shape.
	hexKey, err := BootstrapKeyString(token)
	if err != nil || len(hexKey) != 64 {
		t.Errorf("BootstrapKeyString = %q (err %v), want 64 hex chars", hexKey, err)
	}
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0xf]
	}
	return string(out)
}

func TestPendingStoreLifecycle(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	s := NewPendingStore(clock)

	token, view, err := s.Issue("node-1", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if view.NodeID != "node-1" || view.Fingerprint != DisplayFingerprint(token) {
		t.Errorf("pending view = %+v", view)
	}
	// The raw token is never recoverable from the store listing.
	for _, v := range s.List() {
		if strings.Contains(v.Fingerprint, token) || v.Fingerprint == token {
			t.Error("listing must never expose token material")
		}
	}
	// Verify does not consume: repeated verification succeeds.
	for i := 0; i < 3; i++ {
		if id, err := s.Verify(token); err != nil || id != "node-1" {
			t.Errorf("Verify #%d = (%q, %v)", i, id, err)
		}
	}
	// Bootstrap key retrieval matches the direct derivation.
	key, id, err := s.BootstrapKeyFor(token)
	if err != nil || id != "node-1" {
		t.Fatalf("BootstrapKeyFor = (%q, %v)", id, err)
	}
	wantKey, _ := BootstrapKey(token)
	if string(key) != string(wantKey) {
		t.Error("stored bootstrap key must equal the direct derivation")
	}
	// Consume: single-use. Second consume → ErrTokenUsed.
	if id, err := s.Consume(token); err != nil || id != "node-1" {
		t.Fatalf("Consume = (%q, %v)", id, err)
	}
	if _, err := s.Consume(token); err != ErrTokenUsed {
		t.Errorf("second Consume = %v, want ErrTokenUsed", err)
	}
	// Replay of the same token for verification is rejected too.
	if _, err := s.Verify(token); err != ErrTokenUsed {
		t.Errorf("Verify after consume = %v, want ErrTokenUsed", err)
	}
	// Unknown token: generic, unattributable.
	if _, err := s.Verify("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err != ErrUnknownToken {
		t.Errorf("unknown token = %v, want ErrUnknownToken", err)
	}
}

func TestPendingStoreExpiryAndBurn(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	s := NewPendingStore(clock)

	token, _, err := s.Issue("node-2", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Four failures: still verifiable. Fifth: burned.
	for i := 0; i < MaxVerificationFailures-1; i++ {
		s.RecordFailure(token)
	}
	if _, err := s.Verify(token); err != nil {
		t.Fatalf("token must survive %d failures: %v", MaxVerificationFailures-1, err)
	}
	s.RecordFailure(token)
	if _, err := s.Verify(token); err != ErrTokenBurned {
		t.Errorf("after %d failures Verify = %v, want ErrTokenBurned", MaxVerificationFailures, err)
	}
	if _, err := s.Consume(token); err != ErrTokenBurned {
		t.Errorf("burned token Consume = %v, want ErrTokenBurned", err)
	}
	// Failures for unknown tokens are ignored, never panic.
	s.RecordFailure("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	// Expiry: TTL honored exactly.
	token2, _, err := s.Issue("node-3", 30*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	now = now.Add(29 * time.Minute)
	if _, err := s.Verify(token2); err != nil {
		t.Errorf("token must verify before expiry: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.Verify(token2); err != ErrTokenExpired {
		t.Errorf("Verify after expiry = %v, want ErrTokenExpired", err)
	}
	// Sweep drops expired/used/burned entries.
	if dropped := s.Sweep(); dropped < 2 {
		t.Errorf("Sweep dropped %d, want >= 2", dropped)
	}
}

func TestPendingStoreIssueValidation(t *testing.T) {
	s := NewPendingStore(nil)
	if _, _, err := s.Issue("bad id!", time.Hour); err == nil {
		t.Error("invalid node id must be refused")
	}
	if _, _, err := s.Issue("node-1", 25*time.Hour); err == nil {
		t.Error("TTL over 24h must be refused")
	}
	if _, _, err := s.Issue("node-1", 0); err != nil {
		t.Errorf("zero TTL must default to 24h: %v", err)
	}
	// Revoke removes the pending join; the token dies with it.
	token, _, err := s.Issue("node-9", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !s.Revoke("node-9") {
		t.Error("Revoke must report the removed join")
	}
	if _, err := s.Verify(token); err != ErrUnknownToken {
		t.Errorf("revoked token Verify = %v, want ErrUnknownToken", err)
	}
	if s.Revoke("node-9") {
		t.Error("second Revoke must report nothing removed")
	}
}

func TestEnrollmentFraming(t *testing.T) {
	data, err := MarshalRequest(EnrollmentRequest{NodeID: "node-1", Token: "tok"})
	if err != nil {
		t.Fatalf("MarshalRequest: %v", err)
	}
	req, err := ParseRequest(data)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.Version != EnrollmentVersion || req.Capability != CapabilityLabel || req.NodeID != "node-1" || req.Token != "tok" {
		t.Errorf("request round-trip = %+v", req)
	}
	// Wrong version / capability / missing fields rejected.
	bad := []byte(`{"version":2,"node_id":"n","token":"t","capability":"` + CapabilityLabel + `"}`)
	if _, err := ParseRequest(bad); err == nil {
		t.Error("version 2 must be rejected")
	}
	bad = []byte(`{"version":1,"node_id":"n","token":"t","capability":"other"}`)
	if _, err := ParseRequest(bad); err == nil {
		t.Error("wrong capability must be rejected")
	}
	bad = []byte(`{"version":1,"node_id":"","token":"t","capability":"` + CapabilityLabel + `"}`)
	if _, err := ParseRequest(bad); err == nil {
		t.Error("empty node id must be rejected")
	}
	if _, err := MarshalRequest(EnrollmentRequest{NodeID: "n"}); err == nil {
		t.Error("missing token must be refused at marshal")
	}
	// Response round-trip, including the error shape.
	respData, err := MarshalResponse(EnrollmentResponse{NodeID: "node-1", NodeKey: "abc", ErrorCode: ErrCodeFailed, Error: "boom"})
	if err != nil {
		t.Fatalf("MarshalResponse: %v", err)
	}
	resp, err := ParseResponse(respData)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.NodeKey != "abc" || resp.ErrorCode != ErrCodeFailed {
		t.Errorf("response round-trip = %+v", resp)
	}
	if _, err := ParseResponse([]byte(`{"version":99}`)); err == nil {
		t.Error("response with wrong version must be rejected")
	}
	// Error mapping.
	if got := MapStoreError(ErrTokenExpired); got != ErrCodeExpiredToken {
		t.Errorf("MapStoreError(expired) = %q", got)
	}
	if got := MapStoreError(ErrUnknownToken); got != ErrCodeUnknownToken {
		t.Errorf("MapStoreError(unknown) = %q", got)
	}
	if got := MapStoreError(ErrTokenBurned); got != ErrCodeBurnedToken {
		t.Errorf("MapStoreError(burned) = %q", got)
	}
	if got := MapStoreError(nil); got != ErrCodeFailed {
		t.Errorf("MapStoreError(nil) = %q, want enrollment_failed", got)
	}
}

func TestAllowedTarget(t *testing.T) {
	// Bootstrap sessions: enrollment target only, fail-closed.
	if !AllowedTarget(SessionKindBootstrap, EnrollmentTarget) {
		t.Error("bootstrap session must reach the enrollment target")
	}
	if AllowedTarget(SessionKindBootstrap, ControlTarget) {
		t.Error("bootstrap session must not reach the control target")
	}
	if AllowedTarget(SessionKindBootstrap, "10101") {
		t.Error("bootstrap session must never carry forward traffic")
	}
	// Normal sessions: everything except the enrollment target.
	if AllowedTarget(SessionKindNormal, EnrollmentTarget) {
		t.Error("normal session must not reach the enrollment target")
	}
	if !AllowedTarget(SessionKindNormal, ControlTarget) {
		t.Error("normal session must reach its control target")
	}
	if !AllowedTarget(SessionKindNormal, "10101") {
		t.Error("normal session must reach forward ports")
	}
	// Unknown kinds: deny everything.
	if AllowedTarget(SessionKind(99), EnrollmentTarget) {
		t.Error("unknown session kind must be denied")
	}
}
