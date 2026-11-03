// Enrollment handler: the server side of the bootstrap
// enrollment exchange (§3.4).
//
// The handler runs detached on a reserved stream inside a
// bootstrap session (see processReservedStreamSyn). It reads one
// JSON enrollment request, relays it to the panel's loopback
// enrollment API through the configured Issuer, and relays the
// response back. On success it drops the bootstrap key (the panel
// burned the token; the server-side drop is defense-in-depth so a
// replayed token cannot open a second bootstrap session).
//
// Failure discipline, all fail-closed:
//   - no issuer configured, issuer unreachable, or rate-limited:
//     transient (enrollment_failed) — the node retries with
//     backoff, the token is untouched;
//   - panel refusal: relayed verbatim — the panel classified it
//     permanent (fresh token needed) or transient;
//   - malformed request: transient, logged, nothing burned;
//   - the response carries key material: it is relayed, never
//     logged. Logs name fingerprints and node IDs only.
package udpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
)

// enrollmentExchangeBudget bounds one enrollment exchange on a
// reserved stream: the request read, the issuer round-trip, and
// the response write. Enrollment is rare and small; a stuck
// stream must not hold a handler goroutine open.
const enrollmentExchangeBudget = 60 * time.Second

// enrollmentIssuerTimeout bounds the panel round-trip inside the
// exchange budget.
const enrollmentIssuerTimeout = 15 * time.Second

// maxEnrollmentAttemptsPerMinute bounds global enrollment
// attempts at the handler: enrollment is rare (one per new node),
// so a burst is abuse until proven otherwise.
const maxEnrollmentAttemptsPerMinute = 30

// enrollmentRateLimiter is a fixed-window global attempt limiter.
// The zero value is usable.
type enrollmentRateLimiter struct {
	mu          sync.Mutex
	windowStart time.Time
	attempts    int
}

func (l *enrollmentRateLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.windowStart) >= time.Minute {
		l.windowStart = now
		l.attempts = 0
	}
	if l.attempts >= maxEnrollmentAttemptsPerMinute {
		return false
	}
	l.attempts++
	return true
}

// SetEnrollmentIssuer installs the panel loopback issuer the
// enrollment handler relays through. A nil issuer means
// enrollment is unavailable: attempts fail transiently (the
// panel-down case in §3.5) and the node retries.
func (s *Server) SetEnrollmentIssuer(issuer enroll.Issuer) {
	if s == nil {
		return
	}
	s.enrollmentIssuerMu.Lock()
	defer s.enrollmentIssuerMu.Unlock()
	s.enrollmentIssuer = issuer
}

func (s *Server) getEnrollmentIssuer() enroll.Issuer {
	if s == nil {
		return nil
	}
	s.enrollmentIssuerMu.RLock()
	defer s.enrollmentIssuerMu.RUnlock()
	return s.enrollmentIssuer
}

// serveEnrollmentStream runs one enrollment exchange on conn (the
// handler end of the reserved stream's pipe). record is the
// bootstrap session record: its fingerprint names the pending
// join. The handler closes conn when it returns.
func (s *Server) serveEnrollmentStream(conn net.Conn, record *sessionRecord) {
	defer conn.Close()
	if s == nil || record == nil {
		return
	}
	fingerprint := record.BootstrapFingerprint
	nodeLog := func() string {
		if fingerprint == "" {
			return "unknown"
		}
		if len(fingerprint) > 16 {
			return fingerprint[:16]
		}
		return fingerprint
	}

	failTransient := func(reason string) {
		resp, err := enroll.MarshalResponse(enroll.EnrollmentResponse{ErrorCode: enroll.ErrCodeFailed, Error: reason})
		if err != nil {
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write(resp)
	}

	if !s.enrollLimiter.allow(time.Now()) {
		if s.log != nil {
			s.log.Warnf("enrollment rate-limited (fingerprint %s)", nodeLog())
		}
		failTransient("enrollment rate-limited, retry later")
		return
	}
	if fingerprint == "" {
		// A bootstrap session without a fingerprint must not exist
		// (the kind is only set from a bootstrap codec match). Fail
		// closed and loud rather than issuing anything.
		if s.log != nil {
			s.log.Errorf("enrollment stream on a session without a bootstrap fingerprint (session %d)", record.ID)
		}
		failTransient("enrollment unavailable")
		return
	}
	issuer := s.getEnrollmentIssuer()
	if issuer == nil {
		if s.log != nil {
			s.log.Warnf("enrollment attempted with no issuer configured (fingerprint %s)", nodeLog())
		}
		failTransient("enrollment unavailable: panel issuer is not configured")
		return
	}

	_ = conn.SetDeadline(time.Now().Add(enrollmentExchangeBudget))
	dec := json.NewDecoder(conn)
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		if s.log != nil {
			s.log.Warnf("enrollment request decode failed (fingerprint %s): %v", nodeLog(), err)
		}
		failTransient("malformed enrollment request")
		return
	}
	req, err := enroll.ParseRequest(raw)
	if err != nil {
		if s.log != nil {
			s.log.Warnf("enrollment request invalid (fingerprint %s): %v", nodeLog(), err)
		}
		failTransient("invalid enrollment request")
		return
	}
	if err := multisession.ValidateNodeID(req.NodeID); err != nil {
		if s.log != nil {
			s.log.Warnf("enrollment node id invalid (fingerprint %s): %v", nodeLog(), err)
		}
		failTransient("invalid node identity")
		return
	}

	issueCtx, cancel := context.WithTimeout(context.Background(), enrollmentIssuerTimeout)
	defer cancel()
	resp, err := issuer.Issue(issueCtx, fingerprint, req)
	if err != nil {
		if errors.Is(err, enroll.ErrIssuerUnavailable) {
			if s.log != nil {
				s.log.Warnf("enrollment issuer unavailable (fingerprint %s, node %q)", nodeLog(), req.NodeID)
			}
			failTransient("enrollment issuer unavailable, retry later")
			return
		}
		if s.log != nil {
			s.log.Warnf("enrollment issue failed (fingerprint %s, node %q): %v", nodeLog(), req.NodeID, err)
		}
		failTransient("enrollment failed")
		return
	}
	if resp.ErrorCode == "" {
		// Success: the panel burned the token. Drop the bootstrap
		// key so the token cannot open a second bootstrap
		// session. A failure here is logged but does not fail
		// the relay: the panel's burn is authoritative, and the
		// key expires with the token regardless.
		if err := s.RemoveBootstrapKey(fingerprint); err != nil && s.log != nil {
			s.log.Warnf("dropping consumed bootstrap key failed (fingerprint %s): %v", nodeLog(), err)
		}
		if s.log != nil {
			s.log.Infof("enrollment succeeded (fingerprint %s, node %q)", nodeLog(), resp.NodeID)
		}
	} else if s.log != nil {
		s.log.Warnf("enrollment refused (fingerprint %s, node %q, code %s)", nodeLog(), req.NodeID, resp.ErrorCode)
	}
	data, err := enroll.MarshalResponse(resp)
	if err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(data)
}
