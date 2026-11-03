package panel

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/MNSH-Nexo/Nexounel/core/internal/security"
)

// Dashboard POST handlers. All run behind requireAuth (session +
// form CSRF). Each re-renders the dashboard from the shared service
// layer so the page always reflects the state after the operation,
// including a shown-once key for exactly one render.

func (s *Server) handleCompressionSettings(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	fail := func(errMsg string) {
		s.renderDashboard(w, r, sess, s.loadDashboard(r.Context()), errMsg, "")
	}
	if r.FormValue("confirm") != "yes" {
		fail("Changing compression settings requires confirmation.")
		return
	}
	dictEnabled := r.FormValue("dict_enabled") == "yes"
	longEnabled := r.FormValue("long_enabled") == "yes"
	level, err := strconv.Atoi(strings.TrimSpace(r.FormValue("zstd_level")))
	if err != nil || level < 0 || level > 22 {
		fail("Invalid zstd level: must be a number between 0 and 22.")
		return
	}
	update := CompressionSettingsUpdate{
		DictEnabled: &dictEnabled, Level: &level, LongEnabled: &longEnabled,
	}
	if err := ApplyCompressionSettingsUpdate(s.cfg.ServerConfig, s.cfg.NodeConfig, update); err != nil {
		fail("Could not write compression settings: " + err.Error())
		return
	}
	s.markRestartNeeded()
	content := s.loadDashboard(r.Context())
	message := "Compression settings written to the server and node config files. " +
		"Restart the server (below) and restart the node service on the node host to apply them."
	if content.Compression.Warning != "" {
		message += " Warning: " + content.Compression.Warning
	}
	s.renderDashboard(w, r, sess, content, "", message)
}

func (s *Server) handleRegistryReload(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	result := s.registryReload(r.Context())
	content := s.loadDashboard(r.Context())
	if !result.Control.Configured {
		s.renderDashboard(w, r, sess, content, "", "Control socket is not configured. Restart the server to apply registry changes.")
		return
	}
	if !result.LiveApplied {
		s.renderDashboard(w, r, sess, content, "", "Registry reload did not reach the running server ("+result.Error+"). Restart the server to apply the registry change.")
		return
	}
	s.renderDashboard(w, r, sess, content, "", "Registry reloaded by the running server without a restart.")
}

func (s *Server) handleRegistryAdd(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	nodeID := strings.TrimSpace(r.FormValue("node_id"))
	result, generated, err := s.registryAdd(r.Context(), nodeID, strings.TrimSpace(r.FormValue("key")))
	if err != nil {
		s.renderDashboard(w, r, sess, s.loadDashboard(r.Context()), "Could not add the node: "+err.Error(), "")
		return
	}
	content := s.loadDashboard(r.Context())
	if generated != "" {
		content.ShownKey = generated
		content.ShownNodeID = nodeID
		content.ShownFingerprint = security.KeyFingerprint(generated)
	}
	message := "Node " + nodeID + " was added to the registry."
	if !result.LiveApplied {
		message += " The running server did not apply it live; restart the server to apply the change."
	}
	s.renderDashboard(w, r, sess, content, "", message)
}

func (s *Server) handleRegistryRemove(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	nodeID := strings.TrimSpace(r.FormValue("node_id"))
	if r.FormValue("confirm") != "yes" {
		s.renderDashboard(w, r, sess, s.loadDashboard(r.Context()), "Removal requires confirmation.", "")
		return
	}
	result, err := s.registryRemove(r.Context(), nodeID)
	if err != nil {
		s.renderDashboard(w, r, sess, s.loadDashboard(r.Context()), "Could not remove the node: "+err.Error(), "")
		return
	}
	message := "Node " + nodeID + " was removed from the registry."
	if !result.LiveApplied {
		message += " The running server did not apply it live; restart the server to apply the change. The remote node service was left running."
	}
	s.renderDashboard(w, r, sess, s.loadDashboard(r.Context()), "", message)
}

func (s *Server) handleRegistryRotate(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	nodeID := strings.TrimSpace(r.FormValue("node_id"))
	result, newKey, err := s.registryRotate(r.Context(), nodeID)
	if err != nil {
		s.renderDashboard(w, r, sess, s.loadDashboard(r.Context()), "Could not rotate the node key: "+err.Error(), "")
		return
	}
	content := s.loadDashboard(r.Context())
	content.ShownKey = newKey
	content.ShownNodeID = nodeID
	content.ShownFingerprint = security.KeyFingerprint(newKey)
	message := "A new key was issued for node " + nodeID + " and written to the registry. " +
		"Deliver the new key to the node (Nodes: rotate/deliver) before it can connect with it."
	if !result.LiveApplied {
		message += " The running server did not apply it live; restart the server to apply the change."
	}
	s.renderDashboard(w, r, sess, content, "", message)
}
