package panel

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Dashboard mesh handlers: join-token issuance and revocation.
// Both run behind requireAuth (session + form CSRF) and re-render
// the dashboard from the shared service layer. An issued token is
// shown for exactly one render, like a generated node key: it is
// never stored beyond the pending-join store's hash and never
// logged.

func (s *Server) handleMeshIssue(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	fail := func(errMsg string) {
		s.renderDashboard(w, r, sess, s.loadDashboard(r.Context()), errMsg, "")
	}
	ttlHours, err := strconv.Atoi(strings.TrimSpace(r.FormValue("ttl_hours")))
	if err != nil && strings.TrimSpace(r.FormValue("ttl_hours")) != "" {
		fail("TTL must be a number of hours between 1 and 24.")
		return
	}
	listenPort, err := strconv.Atoi(strings.TrimSpace(r.FormValue("listen_port")))
	if err != nil && strings.TrimSpace(r.FormValue("listen_port")) != "" {
		fail("Listen port must be a number between 1 and 65535.")
		return
	}
	params := joinParams{
		NodeID:         r.FormValue("node_id"),
		ConnectAddress: r.FormValue("connect_address"),
		ListenPort:     listenPort,
		ForwardRange:   r.FormValue("forward_range"),
		TTLHours:       ttlHours,
	}
	token, view, err := s.issueJoinToken(r.Context(), params)
	if err != nil {
		if errors.Is(err, errJoinValidation) {
			fail("Could not issue a join token: " + err.Error())
			return
		}
		fail("Could not issue a join token: " + err.Error() + " No token was issued.")
		return
	}
	content := s.loadDashboard(r.Context())
	content.ShownToken = token
	content.ShownTokenNodeID = view.NodeID
	content.ShownTokenFingerprint = view.Fingerprint
	content.ShownTokenExpires = view.ExpiresAt.UTC().Format(time.RFC3339)
	message := "Join token issued for node " + view.NodeID + ". " +
		"Copy it now: it is shown once and will not be displayed again. " +
		"The token expires at " + content.ShownTokenExpires + "."
	s.renderDashboard(w, r, sess, content, "", message)
}

func (s *Server) handleMeshRevoke(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	nodeID := strings.TrimSpace(r.FormValue("node_id"))
	if r.FormValue("confirm") != "yes" {
		s.renderDashboard(w, r, sess, s.loadDashboard(r.Context()), "Revocation requires confirmation.", "")
		return
	}
	revoked, err := s.revokeJoinToken(r.Context(), nodeID)
	if err != nil {
		s.renderDashboard(w, r, sess, s.loadDashboard(r.Context()), "Could not revoke the join token: "+err.Error(), "")
		return
	}
	if !revoked {
		s.renderDashboard(w, r, sess, s.loadDashboard(r.Context()), "", "No pending join token exists for node "+nodeID+".")
		return
	}
	s.renderDashboard(w, r, sess, s.loadDashboard(r.Context()), "", "Pending join token for node "+nodeID+" was revoked. It can never enroll.")
}
