package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Altonomega/Nexounel/core/internal/security"
)

// JSON agent API.
//
// All routes live under the same secret web path as the UI and require
// the same session cookie. Unauthenticated requests get 401 JSON
// (never a redirect, never data). State-changing requests additionally
// require CSRF via the X-CSRF-Token header, validated against the
// session with the same ValidCSRF check the form flow uses; JSON
// bodies carry no form field, so the header is the only CSRF channel
// for /api/*. GET requests need authentication but no CSRF token.
// Unknown /api/* paths get 404 JSON. Every handler below reads through
// the shared service layer in service.go — the same functions the
// dashboard renders — so UI and API cannot drift.
//
// Documented in docs/PANEL-AGENT-API.md.

type apiErrorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, apiErrorBody{Error: message})
}

// requireAPIAuth enforces session authentication and, for
// state-changing methods, header CSRF, with JSON error semantics.
func (s *Server) requireAPIAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessionFromRequest(r)
		if sess == nil || !sess.Authenticated || sess.Username != s.cfg.Username {
			writeAPIError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !ValidCSRF(sess, r.Header.Get("X-CSRF-Token")) {
				writeAPIError(w, http.StatusForbidden, "invalid or missing X-CSRF-Token header")
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	switch s.subPath(r.URL.Path) {
	case "/api/health":
		s.requireAPIAuth(s.handleAPIHealth).ServeHTTP(w, r)
	case "/api/status":
		s.requireAPIAuth(s.handleAPIStatus).ServeHTTP(w, r)
	case "/api/sessions":
		s.requireAPIAuth(s.handleAPISessions).ServeHTTP(w, r)
	case "/api/compression":
		s.requireAPIAuth(s.handleAPICompression).ServeHTTP(w, r)
	case "/api/registry":
		s.requireAPIAuth(s.handleAPIRegistry).ServeHTTP(w, r)
	case "/api/mesh":
		s.requireAPIAuth(s.handleAPIMesh).ServeHTTP(w, r)
	default:
		writeAPIError(w, http.StatusNotFound, "not found")
	}
}

// --- Response shapes (DTOs) ---

type apiNodeView struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
}

func apiNodes(nodes []RegistryNodeView) []apiNodeView {
	out := make([]apiNodeView, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, apiNodeView{ID: n.ID, Fingerprint: n.Fingerprint})
	}
	return out
}

type apiHealth struct {
	Up                bool           `json:"up"`
	Error             string         `json:"error,omitempty"`
	Details           *HealthDetails `json:"details,omitempty"`
	MetricsAvailable  bool           `json:"metrics_available"`
	MetricsValueCount int            `json:"metrics_value_count"`
}

func apiHealthFrom(h ServerHealth) apiHealth {
	return apiHealth{
		Up: h.Up, Error: h.Error, Details: h.Details,
		MetricsAvailable: h.MetricsAvailable, MetricsValueCount: h.MetricsValueCount,
	}
}

type apiResolverEntry struct {
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Domain      string `json:"domain"`
	UploadMTU   int    `json:"upload_mtu"`
	DownloadMTU int    `json:"download_mtu"`
	LastSeen    string `json:"last_seen"`
}

type apiResolverClass struct {
	DownloadMTU int `json:"download_mtu"`
	UploadMTU   int `json:"upload_mtu"`
	Count       int `json:"count"`
}

type apiResolver struct {
	Available  bool               `json:"available"`
	SourceFile string             `json:"source_file,omitempty"`
	Note       string             `json:"note,omitempty"`
	Total      int                `json:"total_resolvers"`
	Entries    []apiResolverEntry `json:"entries"`
	Classes    []apiResolverClass `json:"classes"`
}

func apiResolverFrom(r ResolverHealth) apiResolver {
	out := apiResolver{Available: r.Available, SourceFile: r.SourceFile, Note: r.Note, Total: r.EntryTotal()}
	out.Entries = make([]apiResolverEntry, 0, len(r.Entries))
	for _, e := range r.Entries {
		out.Entries = append(out.Entries, apiResolverEntry{
			IP: e.IP, Port: e.Port, Domain: e.Domain,
			UploadMTU: e.UploadMTU, DownloadMTU: e.DownloadMTU,
			LastSeen: e.LastSeen.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	out.Classes = make([]apiResolverClass, 0, len(r.Classes))
	for _, c := range r.Classes {
		out.Classes = append(out.Classes, apiResolverClass{DownloadMTU: c.DownloadMTU, UploadMTU: c.UploadMTU, Count: c.Count})
	}
	return out
}

type apiStatus struct {
	Server        apiHealth          `json:"server"`
	Nodes         []apiNodeView      `json:"nodes"`
	RegistryError string             `json:"registry_error,omitempty"`
	Resolver      apiResolver        `json:"resolver"`
	Sessions      []SessionView      `json:"sessions"`
	SessionsNote  string             `json:"sessions_note,omitempty"`
	Control       ControlSocketState `json:"control"`
	Compression   CompressionStatus  `json:"compression"`
	ConfigFiles   ConfigFileState    `json:"config_files"`
	RestartNeeded bool               `json:"restart_needed"`
	Mesh          MeshView           `json:"mesh"`
	PendingJoins  []PendingJoinView  `json:"pending_joins"`
}

func (s *Server) apiStatusFrom(ctxContent statusContent) apiStatus {
	sessions := ctxContent.Sessions
	if sessions == nil {
		sessions = []SessionView{}
	}
	pending := ctxContent.PendingJoins
	if pending == nil {
		pending = []PendingJoinView{}
	}
	return apiStatus{
		Server:        apiHealthFrom(ctxContent.Health),
		Nodes:         apiNodes(ctxContent.Nodes),
		RegistryError: ctxContent.RegistryError,
		Resolver:      apiResolverFrom(ctxContent.Resolver),
		Sessions:      sessions,
		SessionsNote:  ctxContent.SessionsNote,
		Control:       ctxContent.Control,
		Compression:   ctxContent.Compression,
		ConfigFiles:   ctxContent.ConfigFiles,
		RestartNeeded: ctxContent.RestartNeeded,
		Mesh:          ctxContent.Mesh,
		PendingJoins:  pending,
	}
}

func (s *Server) handleAPIHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	health := FetchServerHealth(r.Context(), s.cfg.MetricsAddr, s.httpClient)
	s.restartMu.Lock()
	needed := s.restartNeeded
	s.restartMu.Unlock()
	writeJSON(w, http.StatusOK, struct {
		OK            bool               `json:"ok"`
		Server        apiHealth          `json:"server"`
		Control       ControlSocketState `json:"control"`
		RestartNeeded bool               `json:"restart_needed"`
	}{
		OK: true, Server: apiHealthFrom(health),
		Control: s.controlSocketState(r.Context()), RestartNeeded: needed,
	})
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.apiStatusFrom(s.loadDashboard(r.Context())))
}

func (s *Server) handleAPISessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	sessions, ctrl := s.liveSessions(r.Context())
	if sessions == nil {
		sessions = []SessionView{}
	}
	note := ""
	if !ctrl.Configured {
		note = controlSocketNotConfiguredNote
	} else if !ctrl.Available {
		note = ctrl.Error
	}
	writeJSON(w, http.StatusOK, struct {
		Sessions []SessionView      `json:"sessions"`
		Control  ControlSocketState `json:"control"`
		Note     string             `json:"note,omitempty"`
	}{Sessions: sessions, Control: ctrl, Note: note})
}

type apiCompressionUpdate struct {
	DictEnabled *bool `json:"dict_enabled"`
	Level       *int  `json:"level"`
	LongEnabled *bool `json:"long_enabled"`
}

func (s *Server) handleAPICompression(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, loadCompressionStatus(s.cfg.ServerConfig, s.cfg.NodeConfig))
	case http.MethodPost:
		var update apiCompressionUpdate
		dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&update); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		if update.Level != nil && (*update.Level < 0 || *update.Level > 22) {
			writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("invalid level %d: must be between 0 and 22", *update.Level))
			return
		}
		if err := ApplyCompressionSettingsUpdate(s.cfg.ServerConfig, s.cfg.NodeConfig, CompressionSettingsUpdate{
			DictEnabled: update.DictEnabled, Level: update.Level, LongEnabled: update.LongEnabled,
		}); err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		s.markRestartNeeded()
		status := loadCompressionStatus(s.cfg.ServerConfig, s.cfg.NodeConfig)
		writeJSON(w, http.StatusOK, struct {
			Applied             bool              `json:"applied"`
			Compression         CompressionStatus `json:"compression"`
			RestartNeeded       bool              `json:"restart_needed"`
			NodeRestartGuidance string            `json:"node_restart_guidance"`
		}{
			Applied: true, Compression: status, RestartNeeded: true,
			NodeRestartGuidance: "Restart the server from the dashboard and restart the node service on the node host to apply the new settings.",
		})
	default:
		w.Header().Set("Allow", "GET, POST")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

type apiRegistryRequest struct {
	Action  string `json:"action"`
	NodeID  string `json:"node_id"`
	Key     string `json:"key"`
	Confirm bool   `json:"confirm"`
}

type apiRegistryResult struct {
	Action         string             `json:"action"`
	NodeID         string             `json:"node_id,omitempty"`
	FileWritten    bool               `json:"file_written"`
	LiveApplied    bool               `json:"live_applied"`
	Control        ControlSocketState `json:"control"`
	RestartNeeded  bool               `json:"restart_needed"`
	Error          string             `json:"error,omitempty"`
	KeyShownOnce   string             `json:"key_shown_once,omitempty"`
	KeyFingerprint string             `json:"key_fingerprint,omitempty"`
}

func (s *Server) handleAPIRegistry(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		nodes, regErr := ListRegistryNodes(s.cfg.RegistryFile)
		body := struct {
			Nodes         []apiNodeView      `json:"nodes"`
			RegistryError string             `json:"registry_error,omitempty"`
			Control       ControlSocketState `json:"control"`
		}{Nodes: apiNodes(nodes), Control: s.controlSocketState(r.Context())}
		if regErr != nil {
			body.RegistryError = regErr.Error()
		}
		writeJSON(w, http.StatusOK, body)
	case http.MethodPost:
		var req apiRegistryRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		s.handleAPIRegistryPost(w, r, req)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleAPIRegistryPost(w http.ResponseWriter, r *http.Request, req apiRegistryRequest) {
	nodeID := strings.TrimSpace(req.NodeID)
	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case "reload":
		result := s.registryReload(r.Context())
		writeJSON(w, http.StatusOK, apiRegistryResult{
			Action: "reload", FileWritten: result.FileWritten, LiveApplied: result.LiveApplied,
			Control: result.Control, RestartNeeded: result.RestartNeeded, Error: result.Error,
		})
	case "add":
		if nodeID == "" {
			writeAPIError(w, http.StatusBadRequest, "node_id is required")
			return
		}
		result, generated, err := s.registryAdd(r.Context(), nodeID, strings.TrimSpace(req.Key))
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		body := apiRegistryResult{
			Action: "add", NodeID: nodeID, FileWritten: result.FileWritten,
			LiveApplied: result.LiveApplied, Control: result.Control,
			RestartNeeded: result.RestartNeeded, Error: result.Error,
		}
		// The key is shown once, only when it was generated here.
		// A caller-supplied key is never echoed back.
		if generated != "" {
			body.KeyShownOnce = generated
			body.KeyFingerprint = security.KeyFingerprint(generated)
		} else {
			body.KeyFingerprint = security.KeyFingerprint(strings.TrimSpace(req.Key))
		}
		writeJSON(w, http.StatusOK, body)
	case "remove":
		if nodeID == "" {
			writeAPIError(w, http.StatusBadRequest, "node_id is required")
			return
		}
		if !req.Confirm {
			writeAPIError(w, http.StatusBadRequest, "confirm must be true to remove a node")
			return
		}
		result, err := s.registryRemove(r.Context(), nodeID)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, apiRegistryResult{
			Action: "remove", NodeID: nodeID, FileWritten: result.FileWritten,
			LiveApplied: result.LiveApplied, Control: result.Control,
			RestartNeeded: result.RestartNeeded, Error: result.Error,
		})
	case "rotate":
		if nodeID == "" {
			writeAPIError(w, http.StatusBadRequest, "node_id is required")
			return
		}
		result, newKey, err := s.registryRotate(r.Context(), nodeID)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, apiRegistryResult{
			Action: "rotate", NodeID: nodeID, FileWritten: result.FileWritten,
			LiveApplied: result.LiveApplied, Control: result.Control,
			RestartNeeded: result.RestartNeeded, Error: result.Error,
			KeyShownOnce: newKey, KeyFingerprint: security.KeyFingerprint(newKey),
		})
	default:
		writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("unknown registry action %q: want reload, add, remove or rotate", req.Action))
	}
}

// --- Mesh endpoints ---

// apiMeshRequest selects a mesh mutation. Issue fields mirror the
// dashboard form; ttl_hours is optional (1-24, default 24).
type apiMeshRequest struct {
	Action         string `json:"action"`
	NodeID         string `json:"node_id"`
	ConnectAddress string `json:"connect_address"`
	ListenPort     int    `json:"listen_port"`
	ForwardRange   string `json:"forward_range"`
	TTLHours       int    `json:"ttl_hours"`
	Confirm        bool   `json:"confirm"`
}

func (s *Server) handleAPIMesh(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		mesh := s.liveMesh(r.Context())
		pending := s.pendingJoinViews(r.Context())
		if pending == nil {
			pending = []PendingJoinView{}
		}
		writeJSON(w, http.StatusOK, struct {
			Mesh         MeshView          `json:"mesh"`
			PendingJoins []PendingJoinView `json:"pending_joins"`
		}{Mesh: mesh, PendingJoins: pending})
	case http.MethodPost:
		var req apiMeshRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		s.handleAPIMeshPost(w, r, req)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleAPIMeshPost(w http.ResponseWriter, r *http.Request, req apiMeshRequest) {
	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case "issue":
		params, err := normalizeJoinParams(joinParams{
			NodeID:         req.NodeID,
			ConnectAddress: req.ConnectAddress,
			ListenPort:     req.ListenPort,
			ForwardRange:   req.ForwardRange,
			TTLHours:       req.TTLHours,
		})
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		token, view, err := s.issueJoinToken(r.Context(), params)
		if err != nil {
			if errors.Is(err, errJoinValidation) {
				writeAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			// Operational failure (store or bootstrap-key push):
			// no token was issued. The message names node IDs
			// and socket state only, never token material.
			writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		// The token is shown once, in this response only.
		writeJSON(w, http.StatusOK, struct {
			Action           string `json:"action"`
			NodeID           string `json:"node_id"`
			TokenShownOnce   string `json:"token_shown_once"`
			TokenFingerprint string `json:"token_fingerprint"`
			ExpiresAt        string `json:"expires_at"`
			ConnectAddress   string `json:"connect_address"`
			ListenPort       int    `json:"listen_port"`
			ForwardRange     string `json:"forward_range"`
		}{
			Action: "issue", NodeID: view.NodeID,
			TokenShownOnce: token, TokenFingerprint: view.Fingerprint,
			ExpiresAt:      view.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			ConnectAddress: params.ConnectAddress,
			ListenPort:     params.ListenPort,
			ForwardRange:   params.ForwardRange,
		})
	case "revoke":
		if strings.TrimSpace(req.NodeID) == "" {
			writeAPIError(w, http.StatusBadRequest, "node_id is required")
			return
		}
		if !req.Confirm {
			writeAPIError(w, http.StatusBadRequest, "confirm must be true to revoke a join token")
			return
		}
		revoked, err := s.revokeJoinToken(r.Context(), strings.TrimSpace(req.NodeID))
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Action  string `json:"action"`
			NodeID  string `json:"node_id"`
			Revoked bool   `json:"revoked"`
		}{Action: "revoke", NodeID: strings.TrimSpace(req.NodeID), Revoked: revoked})
	default:
		writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("unknown mesh action %q: want issue or revoke", req.Action))
	}
}
