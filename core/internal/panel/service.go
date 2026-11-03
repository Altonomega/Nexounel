package panel

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/compression"
	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	"github.com/MNSH-Nexo/Nexounel/core/internal/control"
)

// This file is the single service layer shared by the dashboard UI and
// the JSON agent API. Both surfaces call the same functions below for
// server health, live sessions, resolver health, compression status and
// registry operations, so the two can never drift apart. The UI renders
// these values as HTML; the API serialises them as JSON.

// controlClient is the panel's view of the control socket: the subset of
// control.Client the panel uses, plus Ping. The interface (and the
// socket-path override / client factory seams on Server) exist so tests
// can run the whole service layer against a fake socket server without
// a live tunnel server.
type controlClient interface {
	Ping(ctx context.Context) error
	ReloadRegistry(ctx context.Context) error
	AddNode(ctx context.Context, nodeID, key string) error
	RemoveNode(ctx context.Context, nodeID string) error
	RotateKey(ctx context.Context, nodeID, key string) error
	ListSessions(ctx context.Context) ([]control.SessionSummary, error)
}

// realControlClient adapts control.Client to controlClient.
type realControlClient struct{ client control.Client }

func (r realControlClient) Ping(ctx context.Context) error {
	_, err := r.client.Call(ctx, control.Request{Command: control.CmdPing})
	return err
}

func (r realControlClient) ReloadRegistry(ctx context.Context) error {
	return r.client.ReloadRegistry(ctx)
}

func (r realControlClient) AddNode(ctx context.Context, nodeID, key string) error {
	return r.client.AddNode(ctx, nodeID, key)
}

func (r realControlClient) RemoveNode(ctx context.Context, nodeID string) error {
	return r.client.RemoveNode(ctx, nodeID)
}

func (r realControlClient) RotateKey(ctx context.Context, nodeID, key string) error {
	return r.client.RotateKey(ctx, nodeID, key)
}

func (r realControlClient) ListSessions(ctx context.Context) ([]control.SessionSummary, error) {
	return r.client.ListSessions(ctx)
}

func (s *Server) newControlClient(socketPath string) controlClient {
	if s.controlClientFactory != nil {
		return s.controlClientFactory(socketPath)
	}
	// Short timeout: a dead socket must degrade the dashboard to
	// "unavailable", never stall a page load.
	return realControlClient{client: control.Client{SocketPath: socketPath, Timeout: 3 * time.Second}}
}

// resolveControlSocketPath reads the socket path from the server config
// file (CONTROL_SOCKET_PATH). The second result reports whether a socket
// is configured at all; an empty path, a missing file, or an unparseable
// config all mean "not configured", and callers degrade gracefully.
// Tests may override the path (including forcing it empty) via
// controlSocketPathOverride.
func (s *Server) resolveControlSocketPath() (string, bool) {
	if s.controlSocketPathOverride != nil {
		path := strings.TrimSpace(*s.controlSocketPathOverride)
		return path, path != ""
	}
	cfg, err := config.LoadServerConfig(s.cfg.ServerConfig)
	if err != nil {
		return "", false
	}
	path := strings.TrimSpace(cfg.ControlSocketPath)
	return path, path != ""
}

// ControlSocketState is the honest, degraded view of the control socket:
// configured + reachable, or configured-but-dead, or not configured.
type ControlSocketState struct {
	Configured bool   `json:"configured"`
	Reachable  bool   `json:"reachable"`
	Available  bool   `json:"available"`
	Error      string `json:"error,omitempty"`
}

// controlSocketNotConfiguredNote is the exact text shown (UI and API)
// when no control socket is configured. It names the config key to set.
const controlSocketNotConfiguredNote = "unavailable (control socket not configured — set CONTROL_SOCKET_PATH in the server config)"

// controlSocketState pings the socket when one is configured. Any error
// (dial failure, timeout, protocol error) degrades to unreachable; it
// never propagates as a page error.
func (s *Server) controlSocketState(ctx context.Context) ControlSocketState {
	path, configured := s.resolveControlSocketPath()
	if !configured {
		return ControlSocketState{Configured: false, Error: controlSocketNotConfiguredNote}
	}
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.newControlClient(path).Ping(pingCtx); err != nil {
		return ControlSocketState{Configured: true, Error: "unavailable (control socket unreachable: " + err.Error() + ")"}
	}
	return ControlSocketState{Configured: true, Reachable: true, Available: true}
}

// SessionView is one live session for display. Byte counters are
// deliberately absent: the control socket reports membership, the
// metrics endpoint owns counters.
type SessionView struct {
	SessionID     uint16    `json:"session_id"`
	NodeID        string    `json:"node_id"`
	UploadMTU     uint16    `json:"upload_mtu"`
	DownloadMTU   uint16    `json:"download_mtu"`
	CreatedAt     time.Time `json:"created_at"`
	LastActivity  time.Time `json:"last_activity"`
	ActiveStreams int       `json:"active_streams"`
}

func sessionViews(in []control.SessionSummary) []SessionView {
	views := make([]SessionView, 0, len(in))
	for _, s := range in {
		views = append(views, SessionView{
			SessionID: s.SessionID, NodeID: s.NodeID,
			UploadMTU: s.UploadMTU, DownloadMTU: s.DownloadMTU,
			CreatedAt: s.CreatedAt, LastActivity: s.LastActivity,
			ActiveStreams: s.ActiveStreams,
		})
	}
	return views
}

// liveSessions returns the live sessions via the control socket, or an
// empty list plus the degraded socket state when the socket is absent
// or dead. It never returns an error: callers render the state.
func (s *Server) liveSessions(ctx context.Context) ([]SessionView, ControlSocketState) {
	state := s.controlSocketState(ctx)
	if !state.Available {
		return nil, state
	}
	path, _ := s.resolveControlSocketPath()
	listCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	summaries, err := s.newControlClient(path).ListSessions(listCtx)
	if err != nil {
		return nil, ControlSocketState{
			Configured: true,
			Error:      "unavailable (control socket error: " + err.Error() + ")",
		}
	}
	return sessionViews(summaries), state
}

// ConfigFileState reports whether the server and node config files
// exist and parse. Error text comes from the config loaders and names
// paths only, never secret material.
type ConfigFileState struct {
	ServerPath        string `json:"server_path"`
	NodePath          string `json:"node_path"`
	ServerPresent     bool   `json:"server_present"`
	ServerParseable   bool   `json:"server_parseable"`
	ServerError       string `json:"server_error,omitempty"`
	NodePresent       bool   `json:"node_present"`
	NodeParseable     bool   `json:"node_parseable"`
	NodeError         string `json:"node_error,omitempty"`
	ControlConfigured bool   `json:"control_socket_configured"`
}

func checkConfigFile(path string, load func(string) error) (present, parseable bool, errText string) {
	if _, err := os.Stat(path); err != nil {
		return false, false, ""
	}
	if err := load(path); err != nil {
		return true, false, err.Error()
	}
	return true, true, ""
}

func (s *Server) configFileState() ConfigFileState {
	serverPresent, serverParseable, serverErr := checkConfigFile(s.cfg.ServerConfig, func(path string) error {
		_, err := config.LoadServerConfig(path)
		return err
	})
	nodePresent, nodeParseable, nodeErr := checkConfigFile(s.cfg.NodeConfig, func(path string) error {
		_, err := config.LoadClientConfig(path)
		return err
	})
	_, configured := s.resolveControlSocketPath()
	return ConfigFileState{
		ServerPath: s.cfg.ServerConfig, NodePath: s.cfg.NodeConfig,
		ServerPresent: serverPresent, ServerParseable: serverParseable, ServerError: serverErr,
		NodePresent: nodePresent, NodeParseable: nodeParseable, NodeError: nodeErr,
		ControlConfigured: configured,
	}
}

// CompressionSide is one side's effective zstd settings, read from its
// config file. When the file is missing or unparseable, Available is
// false and Note explains why; no values are invented.
type CompressionSide struct {
	Available   bool   `json:"available"`
	Note        string `json:"note,omitempty"`
	DictEnabled bool   `json:"dict_enabled"`
	Level       int    `json:"level"`
	LongEnabled bool   `json:"long_enabled"`
}

// CompressionStatus is the two-sided compression view plus the shared
// dictionary identity. Symmetric is false when dictionary enablement
// differs between the sides; Warning (fail-closed) is set in exactly
// that case, when both sides are observable.
type CompressionStatus struct {
	Server               CompressionSide `json:"server"`
	Node                 CompressionSide `json:"node"`
	DictionaryVersion    string          `json:"dictionary_version"`
	UploadDictionaryID   uint32          `json:"upload_dictionary_id"`
	DownloadDictionaryID uint32          `json:"download_dictionary_id"`
	Comparable           bool            `json:"comparable"`
	Symmetric            bool            `json:"symmetric"`
	SettingsMatch        bool            `json:"settings_match"`
	Warning              string          `json:"warning,omitempty"`
}

// symmetricEnablementWarning is shown on both the UI form and the API
// response whenever dictionary compression is enabled on one side only.
const symmetricEnablementWarning = "Dictionary compression is enabled on one side only. Dictionary frames cannot be decoded by a peer without dictionaries enabled, so those packets will be dropped. Enable ZSTD_DICT_ENABLED on both sides (and restart both processes) or disable it on both sides."

// loadCompressionStatus reads both sides' ZSTD_* keys through the config
// loaders. It is the one reader used by the dashboard and the API.
func loadCompressionStatus(serverConfigPath, nodeConfigPath string) CompressionStatus {
	status := CompressionStatus{
		DictionaryVersion:    compression.DictionaryVersion,
		UploadDictionaryID:   compression.UploadDictionaryID,
		DownloadDictionaryID: compression.DownloadDictionaryID,
	}
	if sc, err := config.LoadServerConfig(serverConfigPath); err != nil {
		status.Server = CompressionSide{Note: "server config unavailable"}
	} else {
		status.Server = CompressionSide{Available: true, DictEnabled: sc.ZSTDDictEnabled, Level: sc.ZSTDLevel, LongEnabled: sc.ZSTDLongEnabled}
	}
	if nc, err := config.LoadClientConfig(nodeConfigPath); err != nil {
		status.Node = CompressionSide{Note: "node config unavailable"}
	} else {
		status.Node = CompressionSide{Available: true, DictEnabled: nc.ZSTDDictEnabled, Level: nc.ZSTDLevel, LongEnabled: nc.ZSTDLongEnabled}
	}
	status.Comparable = status.Server.Available && status.Node.Available
	if status.Comparable {
		status.Symmetric = status.Server.DictEnabled == status.Node.DictEnabled
		status.SettingsMatch = status.Symmetric &&
			status.Server.Level == status.Node.Level &&
			status.Server.LongEnabled == status.Node.LongEnabled
		if !status.Symmetric {
			status.Warning = symmetricEnablementWarning
		}
	}
	return status
}

// loadDashboard gathers every dashboard section from the shared service
// functions. It never fails: every unobservable section degrades to an
// explicit unavailable state in its own field.
func (s *Server) loadDashboard(ctx context.Context) statusContent {
	health := FetchServerHealth(ctx, s.cfg.MetricsAddr, s.httpClient)
	nodes, regErr := ListRegistryNodes(s.cfg.RegistryFile)
	resolver := LoadNodeResolverHealth(s.cfg.NodeConfig)
	sessions, ctrl := s.liveSessions(ctx)
	content := statusContent{
		Health: health, Nodes: nodes, Resolver: resolver,
		Control: ctrl, Sessions: sessions,
		Compression: loadCompressionStatus(s.cfg.ServerConfig, s.cfg.NodeConfig),
		ConfigFiles: s.configFileState(),
	}
	if regErr != nil {
		content.RegistryError = regErr.Error()
	}
	if !ctrl.Configured {
		content.SessionsNote = controlSocketNotConfiguredNote
	} else if !ctrl.Available {
		content.SessionsNote = ctrl.Error
	}
	s.restartMu.Lock()
	content.RestartNeeded = s.restartNeeded
	s.restartMu.Unlock()
	return content
}

// RegistryApplyResult reports a registry operation that follows the
// ordering contract: the registry file is written FIRST, then the
// control-socket command. FileWritten/LiveApplied are independent:
// the file can be durable while the live server has not caught up
// (socket absent or down), in which case a restart applies the change.
type RegistryApplyResult struct {
	FileWritten   bool               `json:"file_written"`
	LiveApplied   bool               `json:"live_applied"`
	Control       ControlSocketState `json:"control"`
	RestartNeeded bool               `json:"restart_needed"`
	Error         string             `json:"error,omitempty"`
	NodeID        string             `json:"node_id,omitempty"`
}

// controlApply issues one socket command after the caller has already
// written the registry file. A dead or absent socket is not an error
// that aborts the operation: the file is the durable truth, the
// restart flow applies it, and the result says so honestly.
func (s *Server) controlApply(ctx context.Context, run func(context.Context, controlClient) error) RegistryApplyResult {
	path, configured := s.resolveControlSocketPath()
	result := RegistryApplyResult{Control: ControlSocketState{Configured: configured}}
	if !configured {
		result.Control.Error = controlSocketNotConfiguredNote
		s.markRestartNeeded()
		result.RestartNeeded = true
		return result
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := run(cmdCtx, s.newControlClient(path)); err != nil {
		result.Control.Error = err.Error()
		result.Error = err.Error()
		s.markRestartNeeded()
		result.RestartNeeded = true
		return result
	}
	result.Control.Reachable = true
	result.Control.Available = true
	result.LiveApplied = true
	return result
}

// registryReload asks the running server to re-read the registry file.
// It writes no file itself.
func (s *Server) registryReload(ctx context.Context) RegistryApplyResult {
	return s.controlApply(ctx, func(cmdCtx context.Context, c controlClient) error { return c.ReloadRegistry(cmdCtx) })
}

// registryAdd writes the node to the registry file first, then tells
// the running server. An empty key generates a fresh one (shown once
// by the caller); the generated key is returned for that purpose and
// must never be logged.
func (s *Server) registryAdd(ctx context.Context, nodeID, key string) (RegistryApplyResult, string, error) {
	generated := ""
	if strings.TrimSpace(key) == "" {
		var err error
		key, err = GenerateNodeKey()
		if err != nil {
			return RegistryApplyResult{}, "", err
		}
		generated = key
	}
	if err := AddNodeToRegistry(s.cfg.RegistryFile, nodeID, key); err != nil {
		return RegistryApplyResult{}, "", err
	}
	result := s.controlApply(ctx, func(cmdCtx context.Context, c controlClient) error { return c.AddNode(cmdCtx, nodeID, key) })
	result.FileWritten = true
	result.NodeID = strings.TrimSpace(nodeID)
	return result, generated, nil
}

// registryRemove removes the node from the registry file first, then
// tells the running server. It never touches the remote node service;
// the existing Nodes SSH removal flow is untouched.
func (s *Server) registryRemove(ctx context.Context, nodeID string) (RegistryApplyResult, error) {
	if err := RemoveNodeFromRegistry(s.cfg.RegistryFile, nodeID); err != nil {
		return RegistryApplyResult{}, err
	}
	result := s.controlApply(ctx, func(cmdCtx context.Context, c controlClient) error { return c.RemoveNode(cmdCtx, nodeID) })
	result.FileWritten = true
	result.NodeID = strings.TrimSpace(nodeID)
	return result, nil
}

// registryRotate re-issues a node's key in the registry file first,
// then tells the running server. The new key is returned shown-once
// by the caller; it must never be logged, and delivery to the node
// remains the existing SSH flow (Nodes rotate/deliver), which this
// operation deliberately does not perform.
func (s *Server) registryRotate(ctx context.Context, nodeID string) (RegistryApplyResult, string, error) {
	newKey, err := GenerateNodeKey()
	if err != nil {
		return RegistryApplyResult{}, "", err
	}
	if err := RotateNodeKey(s.cfg.RegistryFile, nodeID, newKey); err != nil {
		return RegistryApplyResult{}, "", err
	}
	result := s.controlApply(ctx, func(cmdCtx context.Context, c controlClient) error { return c.RotateKey(cmdCtx, nodeID, newKey) })
	result.FileWritten = true
	result.NodeID = strings.TrimSpace(nodeID)
	return result, newKey, nil
}
