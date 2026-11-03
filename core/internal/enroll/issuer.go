// Enrollment issuance transport: the server-side enrollment
// handler talks to the panel's loopback enrollment API through
// this interface. The panel owns the pending-join store and the
// atomic issuance transaction (verify, issue key/config, registry
// write, token burn); the handler only relays.
//
// The loopback binding is the trust boundary: the API listens on
// 127.0.0.1 only, reachable solely by processes on the mother
// host. The request carries a token fingerprint (a hash, safe to
// transport), never the token; the response carries key material
// and must never be logged.
package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrIssuerUnavailable marks a transient issuer failure: the panel
// is down, unreachable, or answered unexpectedly. The node must
// retry with backoff. It is distinct from a response carrying a
// permanent token error code.
var ErrIssuerUnavailable = errors.New("enrollment issuer unavailable")

// Issuer verifies an enrollment request against the pending-join
// store and, on success, issues the node's key, config, and mesh
// control secret. Implementations must be safe for concurrent use.
type Issuer interface {
	// Issue relays one enrollment request. The fingerprint
	// identifies the pending join (TokenFingerprint of the
	// request token); req carries the node's presentation.
	// A nil error with a response carrying ErrorCode means the
	// panel answered and refused (permanent or transient per
	// code); ErrIssuerUnavailable means no usable answer.
	Issue(ctx context.Context, fingerprint string, req EnrollmentRequest) (EnrollmentResponse, error)
}

// issueWireRequest is the loopback API request envelope: the
// fingerprint selects the pending join, the inner request is the
// node's signed-by-token presentation.
type issueWireRequest struct {
	Fingerprint string            `json:"fingerprint"`
	Request     EnrollmentRequest `json:"request"`
}

// HTTPIssuer is an Issuer over loopback HTTP: POST {endpoint} with
// the wire envelope, expecting an EnrollmentResponse. The endpoint
// is a full URL (the panel's loopback enrollment API). No auth
// header: loopback-only binding is the boundary, and the client
// must refuse non-loopback endpoints.
type HTTPIssuer struct {
	Endpoint string
	Client   *http.Client // nil means a 10s-timeout default client
}

// Issue implements Issuer.
func (h HTTPIssuer) Issue(ctx context.Context, fingerprint string, req EnrollmentRequest) (EnrollmentResponse, error) {
	if err := ctx.Err(); err != nil {
		return EnrollmentResponse{}, err
	}
	if strings.TrimSpace(h.Endpoint) == "" {
		return EnrollmentResponse{}, fmt.Errorf("%w: no enrollment issuer endpoint configured", ErrIssuerUnavailable)
	}
	if !isLoopbackURL(h.Endpoint) {
		return EnrollmentResponse{}, fmt.Errorf("%w: refusing non-loopback issuer endpoint", ErrIssuerUnavailable)
	}
	if strings.TrimSpace(req.NodeID) == "" || strings.TrimSpace(req.Token) == "" {
		return EnrollmentResponse{}, errors.New("enrollment request requires node id and token")
	}
	// Stamp the framing version and capability here, not in the
	// caller: the panel validates both, and a caller that forgets
	// them must not produce a request the panel rejects for a
	// framing reason instead of a token reason.
	req.Version = EnrollmentVersion
	req.Capability = CapabilityLabel
	body, err := json.Marshal(issueWireRequest{Fingerprint: fingerprint, Request: req})
	if err != nil {
		return EnrollmentResponse{}, fmt.Errorf("%w: encode enrollment request: %v", ErrIssuerUnavailable, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.Endpoint, bytes.NewReader(body))
	if err != nil {
		return EnrollmentResponse{}, fmt.Errorf("%w: build enrollment request: %v", ErrIssuerUnavailable, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return EnrollmentResponse{}, fmt.Errorf("%w: %v", ErrIssuerUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return EnrollmentResponse{}, fmt.Errorf("%w: read enrollment response: %v", ErrIssuerUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return EnrollmentResponse{}, fmt.Errorf("%w: issuer answered HTTP %d", ErrIssuerUnavailable, resp.StatusCode)
	}
	parsed, err := ParseResponse(data)
	if err != nil {
		return EnrollmentResponse{}, fmt.Errorf("%w: decode enrollment response: %v", ErrIssuerUnavailable, err)
	}
	return parsed, nil
}

// isLoopbackURL reports whether rawURL addresses a loopback host:
// 127.0.0.0/8, ::1, or localhost. Anything else (including a bare
// hostname that could resolve elsewhere) is refused.
func isLoopbackURL(rawURL string) bool {
	lower := strings.ToLower(strings.TrimSpace(rawURL))
	for _, prefix := range []string{"http://127.", "http://[::1]", "http://localhost", "http://localhost:"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// PermanentErrorCode reports whether an enrollment error code is a
// permanent token failure: the operator must issue a fresh token,
// and retrying is pointless. Every other code (including an empty
// code on a malformed response, and ErrCodeFailed) is transient:
// the node retries with backoff until the token expires.
func PermanentErrorCode(code string) bool {
	switch code {
	case ErrCodeUnknownToken, ErrCodeExpiredToken, ErrCodeUsedToken, ErrCodeBurnedToken, ErrCodeRevokedToken:
		return true
	default:
		return false
	}
}
