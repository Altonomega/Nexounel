package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	"github.com/MNSH-Nexo/Nexounel/core/internal/mesh"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
)

func TestHeartbeatCapacityAggregates(t *testing.T) {
	results := []multisession.ProbeResult{
		{Resolver: "8.8.8.8", Port: 53, DownloadMTU: 1000, Loss: 0.1, Valid: true},
		{Resolver: "1.1.1.1", Port: 53, DownloadMTU: 2000, Loss: 0.0, Valid: true},
		{Resolver: "9.9.9.9", Port: 53, DownloadMTU: 5000, Loss: 0.5, Valid: false},
		{Resolver: "4.4.4.4", Port: 53, DownloadMTU: 0, Loss: 0, Valid: true},
	}
	capacity, loss := heartbeatCapacity(results)
	if capacity != 3000 {
		t.Errorf("capacity = %v, want 3000 (raw ceiling over valid rows)", capacity)
	}
	// MTU-weighted mean loss: (1000*0.1 + 2000*0)/3000.
	if loss < 0.033 || loss > 0.034 {
		t.Errorf("loss = %v, want ~0.0333", loss)
	}
	if c, l := heartbeatCapacity(nil); c != 0 || l != 0 {
		t.Errorf("empty = %v/%v, want 0/0", c, l)
	}
}

func TestHeartbeatResolversStates(t *testing.T) {
	results := []multisession.ProbeResult{
		{Resolver: "8.8.8.8", Port: 53, UploadMTU: 110, DownloadMTU: 1000, Valid: true},
		{Resolver: "1.1.1.1", Port: 53, Valid: false},
	}
	out := heartbeatResolvers(results)
	if len(out) != 2 || out[0].State != "usable" || out[1].State != "rejected" {
		t.Fatalf("resolvers = %+v", out)
	}
	if out[0].Address != "8.8.8.8:53" || out[0].UploadMTU != 110 {
		t.Errorf("resolver[0] = %+v", out[0])
	}
}

func meshTestAgent(t *testing.T, dir string) (*meshAgent, config.ClientConfig, config.ClientConfigOverrides, string, string) {
	t.Helper()
	configPath, resolversPath, keyPath := writeEnrollTestBootstrapConfig(t, dir)
	overrides := config.ClientConfigOverrides{ResolversFilePath: &resolversPath}
	cfg, err := config.LoadClientConfigWithOverrides(configPath, overrides)
	if err != nil {
		t.Fatal(err)
	}
	agent := newMeshAgent(cfg, configPath, overrides, nil, func() heartbeatSnapshot { return heartbeatSnapshot{} }, nil)
	if agent == nil {
		t.Fatal("newMeshAgent must succeed with default timeouts")
	}
	return agent, cfg, overrides, configPath, keyPath
}

func meshTestPushTOML(keyPath, logDir string, minUpload int) string {
	return `
PROTOCOL_TYPE = "TCP"
DOMAINS = ["a.example.com"]
DATA_ENCRYPTION_METHOD = 5
LOG_DIR = "` + logDir + `"
MIN_UPLOAD_MTU = ` + strconv.Itoa(minUpload) + `
MAX_UPLOAD_MTU = 200
MIN_DOWNLOAD_MTU = 100
MAX_DOWNLOAD_MTU = 4000
NODE_ID = "node-1"
NODE_KEY_FILE = "` + keyPath + `"
`
}

func TestAgentConfigPushAppliesAndPersists(t *testing.T) {
	dir := t.TempDir()
	agent, cfg, overrides, configPath, keyPath := meshTestAgent(t, dir)
	logDir := filepath.Join(dir, "logs")
	push := mesh.ConfigPush{Version: 1, TOML: meshTestPushTOML(keyPath, logDir, 50)}
	ack := agent.applyConfigPush(push)
	if ack.Error != "" {
		t.Fatalf("applyConfigPush: %s", ack.Error)
	}
	if !ack.RestartRequired || ack.AppliedVersion != 1 {
		t.Errorf("ack = %+v, want restart-required v1", ack)
	}
	installed, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installed), "MIN_UPLOAD_MTU = 50") {
		t.Fatalf("installed config missing the push: %s", installed)
	}
	versionRaw, err := os.ReadFile(appliedVersionPath(configPath))
	if err != nil || strings.TrimSpace(string(versionRaw)) != "1" {
		t.Fatalf("version file = %q, err %v", versionRaw, err)
	}
	// A fresh agent loads the applied version from disk (the
	// version file is separate from the config file).
	agent2 := newMeshAgent(cfg, configPath, overrides, nil, func() heartbeatSnapshot { return heartbeatSnapshot{} }, nil)
	if agent2 == nil || agent2.appliedVersion != 1 {
		t.Fatalf("reloaded applied version = %v, want 1", agent2)
	}
	// Redelivery at the applied version is a no-op success.
	ack = agent.applyConfigPush(push)
	if ack.Error != "" || ack.AppliedVersion != 1 {
		t.Errorf("redelivery ack = %+v", ack)
	}
	// Stale versions are refused.
	ack = agent.applyConfigPush(mesh.ConfigPush{Version: 0, TOML: push.TOML})
	if ack.Error == "" {
		t.Error("stale version 0 must be refused")
	}
}

func TestAgentConfigPushRefusesIdentityChange(t *testing.T) {
	dir := t.TempDir()
	agent, _, _, configPath, keyPath := meshTestAgent(t, dir)
	original, _ := os.ReadFile(configPath)
	logDir := filepath.Join(dir, "logs")
	bad := meshTestPushTOML(keyPath, logDir, 50)
	bad = strings.Replace(bad, `NODE_ID = "node-1"`, `NODE_ID = "node-2"`, 1)
	ack := agent.applyConfigPush(mesh.ConfigPush{Version: 1, TOML: bad})
	if ack.Error == "" || !strings.Contains(ack.Error, "node id") {
		t.Fatalf("ack = %+v, want an identity-change refusal", ack)
	}
	after, _ := os.ReadFile(configPath)
	if string(after) != string(original) {
		t.Error("refused push must leave the config untouched")
	}
}

func TestAgentConfigPushRefusesInvalidTOML(t *testing.T) {
	dir := t.TempDir()
	agent, _, _, configPath, _ := meshTestAgent(t, dir)
	original, _ := os.ReadFile(configPath)
	for _, toml := range []string{"", "this is not toml [[["} {
		ack := agent.applyConfigPush(mesh.ConfigPush{Version: 1, TOML: toml})
		if ack.Error == "" {
			t.Errorf("TOML %q must be refused", toml)
		}
	}
	after, _ := os.ReadFile(configPath)
	if string(after) != string(original) {
		t.Error("refused pushes must leave the config untouched")
	}
	if agent.appliedVersion != 0 {
		t.Errorf("applied version = %d, want 0 after refusals", agent.appliedVersion)
	}
}

func TestAgentRotation(t *testing.T) {
	dir := t.TempDir()
	agent, cfg, _, _, _ := meshTestAgent(t, dir)
	newKey := strings.Repeat("cd", 32)
	// Wrong node: refused, nothing written.
	ack := agent.applyRotation(mesh.RotationOrder{NodeID: "node-2", NewKeyHex: newKey})
	if ack.Error == "" {
		t.Fatal("rotation for another node must be refused")
	}
	// Malformed key: refused.
	ack = agent.applyRotation(mesh.RotationOrder{NodeID: "node-1", NewKeyHex: "zz"})
	if ack.Error == "" {
		t.Fatal("malformed rotation key must be refused")
	}
	// Valid: written atomically, 0600, hex + newline.
	ack = agent.applyRotation(mesh.RotationOrder{NodeID: "node-1", NewKeyHex: newKey, Reason: "scheduled"})
	if ack.Error != "" {
		t.Fatalf("applyRotation: %s", ack.Error)
	}
	if !ack.RestartRequired {
		t.Errorf("ack = %+v, want restart-required", ack)
	}
	data, err := os.ReadFile(cfg.NodeKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != newKey {
		t.Fatalf("key file = %q, want the rotated key", data)
	}
	if st, err := os.Stat(cfg.NodeKeyFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, err %v", st.Mode(), err)
	}
}

func TestAgentTableTermRuleAndStepDown(t *testing.T) {
	dir := t.TempDir()
	agent, _, _, _, _ := meshTestAgent(t, dir)
	agent.applyTable(mesh.TablePush{Table: mesh.Table{Term: mesh.Term{Number: 1}, Version: 1, ChiefID: "node-1", Members: []mesh.Member{{ID: "node-1", State: mesh.StateActive}}}})
	table, ok := agent.CurrentTable()
	if !ok || table.ChiefID != "node-1" {
		t.Fatalf("table = %+v ok=%v", table, ok)
	}
	// Stale republication (same term, lower version) is ignored.
	agent.applyTable(mesh.TablePush{Table: mesh.Table{Term: mesh.Term{Number: 1}, Version: 1, ChiefID: "node-2"}})
	if table, _ := agent.CurrentTable(); table.ChiefID != "node-1" {
		t.Errorf("stale table changed the chief to %q", table.ChiefID)
	}
	// Higher term wins.
	agent.applyTable(mesh.TablePush{Table: mesh.Table{Term: mesh.Term{Number: 2}, Version: 1, ChiefID: "node-2", Members: []mesh.Member{{ID: "node-1", State: mesh.StateActive}, {ID: "node-2", State: mesh.StateActive}}}})
	if table, _ := agent.CurrentTable(); table.ChiefID != "node-2" {
		t.Errorf("table chief = %q, want node-2", table.ChiefID)
	}
	// Step-down order: this node is not chief, so the flag is
	// recorded but no local claim is relinquished.
	ack := agent.applyTermAnnouncement(mesh.TermAnnouncement{Term: mesh.Term{Number: 2}, StepDown: true, Reason: "operator"})
	if ack.Error != "" {
		t.Fatalf("term ack: %s", ack.Error)
	}
	req, term := agent.StepDownRequested()
	if !req || term.Number != 2 {
		t.Errorf("step-down requested = %v term %v", req, term)
	}
	// A table naming this node chief, then a step-down, clears
	// the local claim.
	agent.applyTable(mesh.TablePush{Table: mesh.Table{Term: mesh.Term{Number: 3}, Version: 1, ChiefID: "node-1", Members: []mesh.Member{{ID: "node-1", State: mesh.StateActive}}}})
	agent.mu.Lock()
	isChief := agent.coord.IsChief()
	agent.mu.Unlock()
	if !isChief {
		t.Fatal("agent must be chief after a table names it")
	}
	agent.applyTermAnnouncement(mesh.TermAnnouncement{Term: mesh.Term{Number: 3}, StepDown: true})
	agent.mu.Lock()
	isChief = agent.coord.IsChief()
	agent.mu.Unlock()
	if isChief {
		t.Error("step-down must clear the local chief claim")
	}
}

// TestAgentStreamExchange drives the agent over a net.Pipe with a
// fake mother: heartbeats flow up, table/config/rotation/term
// frames flow down, acks flow back. It proves the framing, the
// dispatch, and the ack path end to end without a tunnel.
func TestAgentStreamExchange(t *testing.T) {
	dir := t.TempDir()
	agent, _, _, _, keyPath := meshTestAgent(t, dir)
	agent.snapshot = func() heartbeatSnapshot {
		return heartbeatSnapshot{CapacityBps: 500, LegOK: true, ActiveStreams: 2, ForwardPortsBound: 3}
	}
	motherEnd, agentEnd := net.Pipe()
	defer motherEnd.Close()
	defer agentEnd.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		agent.serve(ctx, agentEnd)
	}()
	_ = motherEnd.SetDeadline(time.Now().Add(10 * time.Second))

	readAck := func(want mesh.FrameKind) mesh.Ack {
		t.Helper()
		for {
			frame, err := mesh.ReadFrame(motherEnd)
			if err != nil {
				t.Fatalf("read frame: %v", err)
			}
			switch frame.Kind {
			case mesh.KindHeartbeat:
				continue
			case mesh.KindAck:
				var ack mesh.Ack
				if err := frame.Decode(&ack); err != nil {
					t.Fatalf("decode ack: %v", err)
				}
				if ack.For != want {
					t.Fatalf("ack for %q, want %q: %+v", ack.For, want, ack)
				}
				return ack
			default:
				t.Fatalf("unexpected frame kind %q", frame.Kind)
			}
		}
	}

	// Table push: applied, no ack (the next heartbeat is the ack).
	if err := mesh.WriteFrame(motherEnd, mesh.KindTable, mesh.TablePush{Table: mesh.Table{Term: mesh.Term{Number: 1}, Version: 1, ChiefID: "node-1", Members: []mesh.Member{{ID: "node-1", State: mesh.StateActive}}}}); err != nil {
		t.Fatalf("write table: %v", err)
	}
	// Wait for the heartbeat that proves the stream is live and
	// the table landed (the heartbeat carries the term).
	termSeen := false
	deadline := time.Now().Add(5 * time.Second)
	for !termSeen && time.Now().Before(deadline) {
		frame, err := mesh.ReadFrame(motherEnd)
		if err != nil {
			t.Fatalf("read heartbeat: %v", err)
		}
		if frame.Kind == mesh.KindHeartbeat {
			var hb mesh.Heartbeat
			if err := frame.Decode(&hb); err != nil {
				t.Fatal(err)
			}
			if hb.Term.Number == 1 && hb.NodeID == "node-1" && hb.CapacityBps == 500 && hb.ForwardPortsBound == 3 {
				termSeen = true
			}
		}
	}
	if !termSeen {
		t.Fatal("no heartbeat carried the applied term")
	}
	// Config push: acked with restart-required.
	logDir := filepath.Join(dir, "logs")
	push := mesh.ConfigPush{Version: 7, TOML: meshTestPushTOML(keyPath, logDir, 60)}
	if err := mesh.WriteFrame(motherEnd, mesh.KindConfig, push); err != nil {
		t.Fatalf("write config: %v", err)
	}
	ack := readAck(mesh.KindConfig)
	if ack.Error != "" || ack.AppliedVersion != 7 || !ack.RestartRequired {
		t.Errorf("config ack = %+v", ack)
	}
	// Rotation: acked, key installed.
	newKey := strings.Repeat("ab", 32)
	if err := mesh.WriteFrame(motherEnd, mesh.KindRotation, mesh.RotationOrder{NodeID: "node-1", NewKeyHex: newKey}); err != nil {
		t.Fatalf("write rotation: %v", err)
	}
	ack = readAck(mesh.KindRotation)
	if ack.Error != "" || !ack.RestartRequired {
		t.Errorf("rotation ack = %+v", ack)
	}
	// Term + step-down: acked, flag recorded.
	if err := mesh.WriteFrame(motherEnd, mesh.KindTerm, mesh.TermAnnouncement{Term: mesh.Term{Number: 1}, StepDown: true}); err != nil {
		t.Fatalf("write term: %v", err)
	}
	ack = readAck(mesh.KindTerm)
	if ack.Error != "" {
		t.Errorf("term ack = %+v", ack)
	}
	if req, _ := agent.StepDownRequested(); !req {
		t.Error("step-down must be recorded")
	}
	// Closing the mother end must end serve.
	_ = motherEnd.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("agent serve did not exit after the stream closed")
	}
}

func TestAgentRunRetriesAndStops(t *testing.T) {
	dir := t.TempDir()
	agent, _, _, _, _ := meshTestAgent(t, dir)
	attempts := 0
	agent.openStream = func(ctx context.Context) (net.Conn, error) {
		attempts++
		return nil, errors.New("no ready session")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		agent.Run(ctx)
	}()
	// Let the backoff loop spin twice, then stop: Run must exit
	// promptly on ctx cancel and never return an error.
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("agent Run did not stop on ctx cancel")
	}
	if attempts == 0 {
		t.Error("Run must attempt to open a stream")
	}
}
