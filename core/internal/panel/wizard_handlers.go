package panel

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type wizardContent struct {
	Domain             string
	Subdomain          string
	MotherIP           string
	NodeID             string
	ListenPort         int
	ForwardRange       string
	Errors             []string
	Results            []RecordVerification
	Passed             bool
	Pending            *PendingNode
	RevocationGuidance bool
}

func (s *Server) getPending(token string) (PendingNode, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	pending, ok := s.pending[token]
	if !ok {
		return PendingNode{}, false
	}
	if time.Since(pending.CreatedAt) > 30*time.Minute {
		delete(s.pending, token)
		return PendingNode{}, false
	}
	return pending, true
}

func (s *Server) setPending(token string, pending PendingNode) {
	s.pendingMu.Lock()
	s.pending[token] = pending
	s.pendingMu.Unlock()
}

func (s *Server) clearPending(token string) {
	s.pendingMu.Lock()
	delete(s.pending, token)
	s.pendingMu.Unlock()
}

func (s *Server) handleWizard(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	switch r.Method {
	case http.MethodGet:
		pending, ok := s.getPending(sess.Token)
		content := wizardContent{ListenPort: 18000}
		if ok {
			content.Pending = &pending
		}
		data := s.pageData(r, sess, "Setup wizard")
		data.Content = content
		s.render(w, r, "wizard", data)
	case http.MethodPost:
		s.handleWizardPost(w, r, sess)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (s *Server) wizardFormInput(r *http.Request) (WizardInput, []string) {
	listenPort, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("listen_port")))
	input, err := NormalizeWizardInput(
		r.FormValue("domain"), r.FormValue("subdomain"), r.FormValue("mother_ip"),
		r.FormValue("node_id"), listenPort, r.FormValue("forward_range"),
	)
	if err != nil {
		return WizardInput{}, []string{err.Error()}
	}
	return input, nil
}

func (s *Server) wizardEcho(r *http.Request) wizardContent {
	listenPort, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("listen_port")))
	if listenPort == 0 {
		listenPort = 18000
	}
	return wizardContent{
		Domain: r.FormValue("domain"), Subdomain: r.FormValue("subdomain"),
		MotherIP: r.FormValue("mother_ip"), NodeID: r.FormValue("node_id"),
		ListenPort: listenPort, ForwardRange: r.FormValue("forward_range"),
	}
}

func (s *Server) renderWizard(w http.ResponseWriter, r *http.Request, sess *Session, content wizardContent) {
	data := s.pageData(r, sess, "Setup wizard")
	data.Content = content
	s.render(w, r, "wizard", data)
}

func (s *Server) handleWizardPost(w http.ResponseWriter, r *http.Request, sess *Session) {
	action := r.FormValue("action")
	switch action {
	case "cancel":
		s.clearPending(sess.Token)
		http.Redirect(w, r, s.cfg.WebPath+"/wizard", http.StatusFound)
		return
	case "confirm":
		s.handleWizardConfirm(w, r, sess)
		return
	case "verify-manual":
		input, errs := s.wizardFormInput(r)
		content := s.wizardEcho(r)
		if len(errs) > 0 {
			content.Errors = errs
			s.renderWizard(w, r, sess, content)
			return
		}
		results := VerifyDNSRecords(r.Context(), s.dnsResolver, input.Domain, input.Subdomain, input.MotherIP)
		content.Results = results
		content.Passed = VerificationPassed(results)
		if !content.Passed {
			content.Errors = []string{"DNS verification did not pass. Create the records shown, wait for propagation, and try again."}
			s.renderWizard(w, r, sess, content)
			return
		}
		pending, err := NewPendingNode(input)
		if err != nil {
			content.Errors = []string{err.Error()}
			s.renderWizard(w, r, sess, content)
			return
		}
		s.setPending(sess.Token, pending)
		content.Pending = &pending
		s.renderWizard(w, r, sess, content)
	case "create-auto":
		s.handleWizardAuto(w, r, sess)
	default:
		data := s.pageData(r, sess, "Setup wizard")
		data.Error = "Unknown wizard action."
		s.render(w, r, "wizard", dataWithContent(data, wizardContent{ListenPort: 18000}))
	}
}

func (s *Server) handleWizardConfirm(w http.ResponseWriter, r *http.Request, sess *Session) {
	pending, ok := s.getPending(sess.Token)
	if !ok {
		data := s.pageData(r, sess, "Setup wizard")
		data.Error = "No pending node issuance. Run the wizard verification step first."
		s.render(w, r, "wizard", dataWithContent(data, wizardContent{ListenPort: 18000}))
		return
	}
	if err := AddNodeToRegistry(s.cfg.RegistryFile, pending.ID, pending.Key); err != nil {
		data := s.pageData(r, sess, "Setup wizard")
		data.Error = fmt.Sprintf("Could not register the node: %s", err.Error())
		content := wizardContent{Pending: &pending}
		s.render(w, r, "wizard", dataWithContent(data, content))
		return
	}
	s.clearPending(sess.Token)
	s.markRestartNeeded()
	data := s.pageData(r, sess, "Node registered")
	data.Message = fmt.Sprintf("Node %s is registered. Restart the server from Status to apply the registry change, then provision the node from Nodes.", pending.ID)
	s.render(w, r, "message", dataWithContent(data, messageContent{
		Heading: "Node registered",
		Body:    fmt.Sprintf("Node %s is registered in the registry. The node key was shown once and will not be displayed again; re-issue it with rotation if it was lost. Restart the server to apply the change, then provision the node.", pending.ID),
		Link:    s.cfg.WebPath + "/nodes", LinkText: "Go to Nodes",
	}))
}

func (s *Server) handleWizardAuto(w http.ResponseWriter, r *http.Request, sess *Session) {
	input, errs := s.wizardFormInput(r)
	content := s.wizardEcho(r)
	if len(errs) > 0 {
		content.Errors = errs
		s.renderWizard(w, r, sess, content)
		return
	}
	// The authorization lives only in this request's locals. It is
	// never written to disk, logs or config, and is zeroed after use.
	email := strings.TrimSpace(r.FormValue("cf_email"))
	auth := CloudflareAuth{Email: email}
	if email != "" {
		auth.Key = []byte(r.FormValue("cf_api_key"))
	} else {
		auth.Token = []byte(r.FormValue("cf_api_token"))
	}
	defer auth.Zero()
	if !auth.Valid() {
		content.Errors = []string{"Enter a Cloudflare Global API key with an email, or a scoped API token."}
		s.renderWizard(w, r, sess, content)
		return
	}
	client := NewCloudflareClient(s.cloudflareBase, s.httpClient)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	zoneID, err := client.ListZones(ctx, auth, input.Domain)
	if err != nil {
		content.Errors = []string{fmt.Sprintf("Could not find the Cloudflare zone: %s", err.Error())}
		s.renderWizard(w, r, sess, content)
		return
	}
	for _, record := range BuildDNSRecords(input) {
		if _, err := client.CreateDNSRecord(ctx, auth, zoneID, record); err != nil {
			content.Errors = []string{fmt.Sprintf("Could not create the %s record: %s", record.Type, err.Error())}
			s.renderWizard(w, r, sess, content)
			return
		}
	}
	results := client.VerifyRecords(ctx, s.dnsResolver, input.Domain, input.Subdomain, input.MotherIP)
	content.Results = results
	content.Passed = VerificationPassed(results)
	if !content.Passed {
		content.Errors = []string{"Records were created but DNS verification did not pass yet. Wait for propagation and re-run verification from the manual path."}
		s.renderWizard(w, r, sess, content)
		return
	}
	pending, err := NewPendingNode(input)
	if err != nil {
		content.Errors = []string{err.Error()}
		s.renderWizard(w, r, sess, content)
		return
	}
	s.setPending(sess.Token, pending)
	content.Pending = &pending
	content.RevocationGuidance = true
	s.renderWizard(w, r, sess, content)
}
