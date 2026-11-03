package panel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
)

// Join-token issuance and lifecycle, panel side (§3.2, §3.4).
//
// The panel owns the pending-join store: it issues single-use tokens
// (shown exactly once), pushes the derived bootstrap key to the
// tunnel server over the control socket at issuance, and removes
// that key when the token is consumed, revoked, or swept. The raw
// token is never stored — only its fingerprint (a hash) and the
// derived bootstrap key live in the store — and never logged.
//
// The store is in-memory: a panel restart invalidates outstanding
// tokens rather than risking double enrollment. Expired keys are
// also refused server-side (bootstrap-key expiry), so a missed
// sweep is cleanup-only, never an authentication hole.
//
// Concurrency: every mutation of the store, the issuance records,
// and the enrollment transaction serializes on enrollMu. Enrollment
// is rare; a 3 s socket timeout bounds the hold.

// errJoinValidation marks input problems in a join-token request
// (bad node ID, connect address, port, range, or TTL). Handlers map
// it to 400; operational failures (store/socket) are 422 or an
// error banner.
var errJoinValidation = errors.New("invalid join-token request")

// joinParams is one token issuance: the node identity the token is
// bound to plus the node-config values the enrollment API will
// issue to that node. The operator supplies them at issuance time
// (the same fields the wizard collects); the enrollment request
// itself carries only identity and token, so the panel must already
// know what config to build.
type joinParams struct {
	NodeID         string
	ConnectAddress string
	ListenPort     int
	ForwardRange   string
	TTLHours       int
}

// normalizeJoinParams validates and normalizes issuance input.
// An empty listen port defaults to 18000 (the wizard default); an
// empty TTL defaults to 24 h (the store maximum).
func normalizeJoinParams(p joinParams) (joinParams, error) {
	p.NodeID = strings.TrimSpace(p.NodeID)
	if err := multisession.ValidateNodeID(p.NodeID); err != nil {
		return joinParams{}, fmt.Errorf("%w: %v", errJoinValidation, err)
	}
	p.ConnectAddress = strings.ToLower(strings.TrimSpace(p.ConnectAddress))
	if p.ConnectAddress == "" || len(p.ConnectAddress) > 253 || !strings.Contains(p.ConnectAddress, ".") {
		return joinParams{}, fmt.Errorf("%w: connect address %q must be a domain with at least one dot", errJoinValidation, p.ConnectAddress)
	}
	for _, label := range strings.Split(p.ConnectAddress, ".") {
		if !domainLabelPattern.MatchString(label) {
			return joinParams{}, fmt.Errorf("%w: connect address %q has an invalid label %q", errJoinValidation, p.ConnectAddress, label)
		}
	}
	if p.ListenPort == 0 {
		p.ListenPort = 18000
	}
	if p.ListenPort < 1 || p.ListenPort > 65535 {
		return joinParams{}, fmt.Errorf("%w: invalid listen port %d", errJoinValidation, p.ListenPort)
	}
	p.ForwardRange = strings.TrimSpace(p.ForwardRange)
	if _, _, err := config.ParsePortRange(p.ForwardRange); err != nil {
		return joinParams{}, fmt.Errorf("%w: invalid forward range %q: %v", errJoinValidation, p.ForwardRange, err)
	}
	if p.TTLHours == 0 {
		p.TTLHours = 24
	}
	if p.TTLHours < 1 || p.TTLHours > 24 {
		return joinParams{}, fmt.Errorf("%w: TTL %d hours is outside 1-24", errJoinValidation, p.TTLHours)
	}
	return p, nil
}

// PendingJoinView is one outstanding join for display: fingerprints
// and state only, never token or key material.
type PendingJoinView struct {
	NodeID      string    `json:"node_id"`
	Fingerprint string    `json:"fingerprint"`
	ExpiresAt   time.Time `json:"expires_at"`
	Attempts    int       `json:"attempts"`
	Used        bool      `json:"used"`
	Burned      bool      `json:"burned"`
	Revoked     bool      `json:"revoked"`
}

// pushBootstrapKey installs a pending join's derived bootstrap key
// on the tunnel server. A missing or dead control socket FAILS the
// issuance: handing out a token the server cannot honor would send
// the node into futile bootstrap retries, so the token is rolled
// back instead (see issueJoinToken).
func (s *Server) pushBootstrapKey(ctx context.Context, fingerprint, keyHex string, expiresAt time.Time) error {
	path, configured := s.resolveControlSocketPath()
	if !configured {
		return errors.New(controlSocketNotConfiguredNote)
	}
	pushCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.newControlClient(path).AddBootstrapKey(pushCtx, fingerprint, keyHex, expiresAt)
}

// dropBootstrapKey removes a pending join's bootstrap key from the
// tunnel server. Best-effort: an unconfigured or dead socket leaves
// the key to expire server-side (bootstrap keys carry the token
// expiry and are refused after it), and a consumed token can never
// enroll a second node even while its key lingers.
func (s *Server) dropBootstrapKey(ctx context.Context, fingerprint string) error {
	path, configured := s.resolveControlSocketPath()
	if !configured {
		return nil
	}
	dropCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.newControlClient(path).RemoveBootstrapKey(dropCtx, fingerprint)
}

// issueJoinToken mints one single-use join token for p.NodeID,
// records the issuance parameters for the enrollment API, and
// pushes the derived bootstrap key to the server. The token is
// returned for exactly one display by the caller and never stored.
// If the bootstrap-key push fails, the pending join is rolled back
// exactly (RemoveByFingerprint) so no unusable token survives.
func (s *Server) issueJoinToken(ctx context.Context, p joinParams) (string, enroll.PendingView, error) {
	p, err := normalizeJoinParams(p)
	if err != nil {
		return "", enroll.PendingView{}, err
	}
	store := s.joinStore()
	if store == nil {
		return "", enroll.PendingView{}, errors.New("join-token store is unavailable")
	}
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	if s.joinParams == nil {
		s.joinParams = make(map[string]joinParams)
	}
	token, view, err := store.Issue(p.NodeID, time.Duration(p.TTLHours)*time.Hour)
	if err != nil {
		return "", enroll.PendingView{}, err
	}
	fingerprint := enroll.TokenFingerprint(token)
	rollback := func(err error) (string, enroll.PendingView, error) {
		delete(s.joinParams, fingerprint)
		store.RemoveByFingerprint(fingerprint)
		return "", enroll.PendingView{}, err
	}
	key, _, err := store.BootstrapKeyFor(token)
	if err != nil {
		return rollback(fmt.Errorf("read bootstrap key for the new join: %w", err))
	}
	s.joinParams[fingerprint] = p
	if err := s.pushBootstrapKey(ctx, fingerprint, hex.EncodeToString(key), view.ExpiresAt); err != nil {
		return rollback(fmt.Errorf("push bootstrap key to the server: %w", err))
	}
	return token, view, nil
}

// revokeJoinToken deletes one pending join for nodeID and drops its
// pushed bootstrap key (best-effort). It reports whether a join
// was present; revoking an absent or already-enrolled node is not
// an error. Revocation of an enrolled node stays a registry
// removal, not this operation.
func (s *Server) revokeJoinToken(ctx context.Context, nodeID string) (bool, error) {
	store := s.joinStore()
	if store == nil {
		return false, errors.New("join-token store is unavailable")
	}
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	fingerprint, ok := store.RevokeFingerprint(nodeID)
	if !ok {
		return false, nil
	}
	delete(s.joinParams, fingerprint)
	if err := s.dropBootstrapKey(ctx, fingerprint); err != nil {
		s.log.Warnf("mesh: could not remove revoked bootstrap key %s: %v", shortFingerprint(fingerprint), err)
	}
	return true, nil
}

// sweepJoinTokens drops expired, used, and burned joins and removes
// each dropped join's pushed bootstrap key. It runs on mesh/enroll
// reads (dashboard and API), not on a ticker: expiry is enforced
// lazily by the store and server-side regardless, so a read-driven
// sweep is cleanup, and no background goroutine is owed a
// lifecycle. Socket removals are best-effort and never fail the
// read that triggered them.
func (s *Server) sweepJoinTokens(ctx context.Context) {
	store := s.joinStore()
	if store == nil {
		return
	}
	dropped := store.SweepFingerprints()
	if len(dropped) == 0 {
		return
	}
	s.enrollMu.Lock()
	for _, fp := range dropped {
		delete(s.joinParams, fp)
	}
	s.enrollMu.Unlock()
	for _, fp := range dropped {
		if err := s.dropBootstrapKey(ctx, fp); err != nil {
			s.log.Warnf("mesh: could not remove swept bootstrap key %s: %v", shortFingerprint(fp), err)
		}
	}
}

// pendingJoinViews lists outstanding joins after a sweep, so the
// list never shows a token that already expired, burned, or was
// consumed. It never exposes token or key material.
func (s *Server) pendingJoinViews(ctx context.Context) []PendingJoinView {
	s.sweepJoinTokens(ctx)
	store := s.joinStore()
	if store == nil {
		return []PendingJoinView{}
	}
	views := store.List()
	out := make([]PendingJoinView, 0, len(views))
	for _, v := range views {
		out = append(out, PendingJoinView{
			NodeID: v.NodeID, Fingerprint: v.Fingerprint,
			ExpiresAt: v.ExpiresAt, Attempts: v.Attempts,
			Used: v.Used, Burned: v.Burned, Revoked: v.Revoked,
		})
	}
	return out
}

// generateMeshSecret mints the mesh-wide control secret (§8.3): 32
// random bytes, hex-encoded. It is one value shared by every
// enrolled node, used only for peer-control HMACs — never a
// data-plane key.
func generateMeshSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate mesh control secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// loadMeshSecret returns the mesh-wide control secret from
// MeshSecretFile, generating and storing it (0600, atomic) on
// first use. A present-but-short file fails closed: silently
// replacing an operator file, or enrolling nodes with a weak
// secret, would both be worse than a loud transient failure the
// operator fixes. The secret value is never logged.
func (s *Server) loadMeshSecret() (string, error) {
	path := strings.TrimSpace(s.cfg.MeshSecretFile)
	if path == "" {
		return "", errors.New("mesh_secret_file is not configured in the panel config")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("read mesh control secret file: %w", err)
		}
		secret, err := generateMeshSecret()
		if err != nil {
			return "", err
		}
		if err := writeKeyFileAtomic(path, secret); err != nil {
			return "", fmt.Errorf("write mesh control secret file: %w", err)
		}
		return secret, nil
	}
	secret := strings.TrimSpace(string(data))
	if len(secret) < 16 {
		return "", fmt.Errorf("mesh control secret file %s holds %d characters, need at least 16", path, len(secret))
	}
	return secret, nil
}

// shortFingerprint renders the first 16 hex chars of a full token
// fingerprint for logs. The fingerprint is a hash, safe to log;
// the short form keeps log lines readable.
func shortFingerprint(fingerprint string) string {
	if len(fingerprint) > 16 {
		return fingerprint[:16]
	}
	return fingerprint
}
