package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
)

// Loopback enrollment API (§3.4): the endpoint the tunnel server's
// enrollment handler relays bootstrap requests to.
//
// Trust boundary: the listener binds a loopback address ONLY (the
// panel refuses any other bind address at startup, and the handler
// refuses any non-loopback remote address). There is no session
// authentication on this API — reachability is confined to
// processes on the mother host, and the request itself proves
// token possession: the fingerprint must be the hash of the
// presented token, and the token must verify against the
// pending-join store. The response carries key material and must
// never be logged.
//
// Transaction discipline (the spec's atomic issuance): verify the
// token, issue or re-issue the key, write the registry, reload the
// running server (best-effort, restart fallback), and only then
// consume the token. A failed registry write does NOT burn the
// token: the node may retry within the TTL. Post-verification
// failures are counted toward the token's burn limit (D-3).

// EnrollmentHandler returns the HTTP handler for the loopback
// enrollment API: POST /enroll only, loopback remotes only. Every
// other path is a JSON 404; every non-POST method is 405.
func (s *Server) EnrollmentHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setSecurityHeaders(w)
		if !isLoopbackRemoteAddr(r.RemoteAddr) {
			writeAPIError(w, http.StatusForbidden, "enrollment API is loopback-only")
			return
		}
		if r.URL.Path != "/enroll" {
			writeAPIError(w, http.StatusNotFound, "not found")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleEnrollmentIssue(w, r)
	})
}

// isLoopbackRemoteAddr reports whether RemoteAddr ("ip:port") is a
// loopback address. Unparseable remotes are refused: the API fails
// closed when it cannot prove the caller is local.
func isLoopbackRemoteAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// enrollWireRequest is the loopback envelope the issuer posts: the
// fingerprint selects the pending join, the inner request is the
// node's token presentation kept as raw JSON so ParseRequest can
// validate the framing (version, capability, presence) on the
// exact bytes the node framed. The fingerprint is a hash (safe to
// transport); the token inside the request is the secret, and the
// handler never logs it.
type enrollWireRequest struct {
	Fingerprint string          `json:"fingerprint"`
	Request     json.RawMessage `json:"request"`
}

// handleEnrollmentIssue serves one enrollment issuance. Malformed
// envelopes get HTTP 400 (the issuer maps non-200 to "unavailable",
// a transient the node retries). Well-formed requests — including
// every token refusal — get HTTP 200 with an EnrollmentResponse,
// so the node can tell permanent token failures (fresh token
// needed) from transient ones (retry).
func (s *Server) handleEnrollmentIssue(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid enrollment request: read body")
		return
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var wire enrollWireRequest
	if err := dec.Decode(&wire); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid enrollment request: "+err.Error())
		return
	}
	req, err := enroll.ParseRequest(wire.Request)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid enrollment request: "+err.Error())
		return
	}
	// The fingerprint must be the hash of the presented token. A
	// mismatch means the caller does not hold the token the
	// fingerprint names: refuse as an unknown token, permanently.
	if enroll.TokenFingerprint(req.Token) != strings.TrimSpace(wire.Fingerprint) {
		s.writeEnrollmentRefusal(w, enroll.ErrCodeUnknownToken, "join token fingerprint mismatch")
		return
	}
	resp := s.issueEnrollment(r.Context(), req)
	data, err = enroll.MarshalResponse(resp)
	if err != nil {
		// MarshalResponse cannot fail on a well-formed response;
		// treat it as issuer-unavailable (transient) rather than
		// inventing a refusal the panel did not classify.
		writeAPIError(w, http.StatusInternalServerError, "encode enrollment response")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// writeEnrollmentRefusal answers a token refusal with HTTP 200 and
// a classified error code. The node distinguishes permanent from
// transient by the code; the message names no secret material.
func (s *Server) writeEnrollmentRefusal(w http.ResponseWriter, code, message string) {
	data, err := enroll.MarshalResponse(enroll.EnrollmentResponse{ErrorCode: code, Error: message})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "encode enrollment response")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// issueEnrollment runs the atomic issuance transaction. It holds
// enrollMu for the whole sequence: verify, key/config issuance,
// registry write, server reload, token consume. Concurrent
// enrollments for the same node cannot interleave registry writes
// or double-issue keys.
func (s *Server) issueEnrollment(ctx context.Context, req enroll.EnrollmentRequest) enroll.EnrollmentResponse {
	store := s.joinStore()
	if store == nil {
		return enroll.EnrollmentResponse{ErrorCode: enroll.ErrCodeFailed, Error: "enrollment is unavailable: no pending-join store"}
	}
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()

	nodeID, err := store.Verify(req.Token)
	if err != nil {
		return enroll.EnrollmentResponse{ErrorCode: enroll.MapStoreError(err), Error: "join token cannot enroll"}
	}
	// The token is bound to one identity: a presentation for any
	// other node ID is refused as unknown, permanently.
	if strings.TrimSpace(req.NodeID) != nodeID {
		return enroll.EnrollmentResponse{ErrorCode: enroll.ErrCodeUnknownToken, Error: "join token is bound to a different node id"}
	}
	// Post-verification failures count toward the burn limit
	// (D-3). fail records one and answers transiently.
	fail := func(format string, args ...any) enroll.EnrollmentResponse {
		store.RecordFailure(req.Token)
		return enroll.EnrollmentResponse{ErrorCode: enroll.ErrCodeFailed, Error: fmt.Sprintf(format, args...)}
	}

	// Idempotent re-issue: a node already in the registry with an
	// inline key receives the SAME key, never a second one — the
	// retry-after-a-lost-response case, and the fresh-token
	// re-enrollment of a node whose key the panel already holds.
	// A key_file entry cannot be re-issued: the panel does not
	// hold that key.
	key, exists, keyFile, err := RegistryNodeKey(s.cfg.RegistryFile, nodeID)
	if err != nil {
		return fail("read node registry: %v", err)
	}
	if exists && keyFile {
		return fail("node %s is registered via a key file: the panel cannot re-issue its key", nodeID)
	}
	if !exists {
		key, err = GenerateNodeKey()
		if err != nil {
			return fail("generate node key: %v", err)
		}
	}

	params, ok := s.joinParams[enroll.TokenFingerprint(req.Token)]
	if !ok {
		return fail("no issuance record for this join token: re-issue a token from the panel")
	}
	secret, err := s.loadMeshSecret()
	if err != nil {
		return fail("mesh control secret unavailable: %v", err)
	}

	keyFilePath, _, resolversFilePath, _ := s.provisionPaths()
	meshSecretPath := filepath.Join(filepath.Dir(keyFilePath), "mesh-control-secret.key")
	// The issued config is installed by the node itself, at its
	// own config path; the panel only renders its text.
	nodeConfig := BuildNodeConfigWithMeshSecret(PendingNode{
		ID: nodeID, ConnectAddress: params.ConnectAddress,
		ListenPort: params.ListenPort, ForwardRange: params.ForwardRange,
	}, keyFilePath, resolversFilePath, meshSecretPath)

	// Registry write first: the file is the durable truth. A
	// failure here must NOT consume the token.
	if !exists {
		if err := AddNodeToRegistry(s.cfg.RegistryFile, nodeID, key); err != nil {
			return fail("write node registry: %v", err)
		}
	}

	// Reload the running server, best-effort: a dead or absent
	// socket falls back to the restart flow, and the panel says
	// so via the restart banner (markRestartNeeded). The node
	// already holds a valid key and config either way.
	result := s.controlApply(ctx, func(cmdCtx context.Context, c controlClient) error {
		return c.ReloadRegistry(cmdCtx)
	})
	if !result.LiveApplied {
		s.markRestartNeeded()
		s.log.Warnf("mesh: enrollment of node %q wrote the registry but the running server did not reload; restart applies it", nodeID)
	}

	// Consume last: only a fully issued enrollment burns the token.
	if _, err := store.Consume(req.Token); err != nil {
		// The registry already holds the node; the token state
		// changed under us (near-impossible under enrollMu).
		// Fail transiently and loudly rather than answering
		// success for a token that may still be live.
		s.log.Warnf("mesh: enrollment of node %q issued but the token could not be consumed: %v", nodeID, err)
		return fail("enrollment issued but the token could not be consumed: %v", err)
	}
	delete(s.joinParams, enroll.TokenFingerprint(req.Token))

	// Drop the pushed bootstrap key, best-effort: the token is
	// burned, so a lingering key cannot enroll a second node
	// (the handler relays to this API and gets token_used).
	// Expiry enforces the rest server-side.
	if err := s.dropBootstrapKey(ctx, enroll.TokenFingerprint(req.Token)); err != nil {
		s.log.Warnf("mesh: could not remove consumed bootstrap key %s: %v", shortFingerprint(enroll.TokenFingerprint(req.Token)), err)
	}

	return enroll.EnrollmentResponse{
		NodeID: nodeID, NodeKey: key,
		NodeConfig: nodeConfig, MeshControlSecret: secret,
	}
}
