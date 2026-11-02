package panel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type mockFile struct {
	data []byte
	path string
	mode os.FileMode
}

type mockTransport struct {
	fingerprint   string
	dialErr       error
	dialCalls     []ProvisionAuth
	commands      []string
	files         []mockFile
	outputs       map[string]string // substring -> stdout
	failSubstr    string
	closed        bool
	ephemeralSeen bool // authorized_keys currently holds the ephemeral key
	pubBase64     string
}

func (m *mockTransport) Dial(ctx context.Context) error {
	if m.dialErr != nil {
		return m.dialErr
	}
	return nil
}

func (m *mockTransport) Fingerprint() string { return m.fingerprint }

func (m *mockTransport) Run(ctx context.Context, cmd string) (string, string, error) {
	m.commands = append(m.commands, cmd)
	if m.failSubstr != "" && strings.Contains(cmd, m.failSubstr) {
		return "", "mock failure", fmt.Errorf("mock command failure for %q", cmd)
	}
	// Explicit output overrides win over the canned defaults below.
	for substr, out := range m.outputs {
		if strings.Contains(cmd, substr) {
			return out, "", nil
		}
	}
	switch {
	case strings.Contains(cmd, "grep -v"):
		m.ephemeralSeen = false
		return "", "", nil
	case strings.Contains(cmd, "cat ~/.ssh/authorized_keys"):
		if m.ephemeralSeen {
			return "ssh-ed25519 " + m.pubBase64 + " ephemeral\n", "", nil
		}
		return "", "", nil
	case strings.Contains(cmd, ">> ~/.ssh/authorized_keys"):
		m.ephemeralSeen = true
		// Learn the public key from the printf argument for verification.
		fields := strings.Fields(cmd)
		for _, f := range fields {
			if strings.HasPrefix(f, "ssh-ed25519") {
				parts := strings.Fields(f)
				if len(parts) >= 2 {
					m.pubBase64 = parts[1]
				}
			}
		}
		return "", "", nil
	case strings.Contains(cmd, "cat /etc/os-release"):
		return "ID=debian\nVERSION_ID=\"12\"\n", "", nil
	case strings.Contains(cmd, "command -v systemctl"):
		return "/usr/bin/systemctl\n", "", nil
	case strings.Contains(cmd, "systemctl is-active"):
		return "active\n", "", nil
	case strings.Contains(cmd, "ss -tlnH"):
		return "LISTEN 0 4096 0.0.0.0:20000 0.0.0.0:*\n", "", nil
	case strings.Contains(cmd, "-version"):
		return "test-version-1\n", "", nil
	}
	return "", "", nil
}

func (m *mockTransport) SendFile(ctx context.Context, data []byte, remotePath string, mode os.FileMode) error {
	m.files = append(m.files, mockFile{data: append([]byte(nil), data...), path: remotePath, mode: mode})
	return nil
}

func (m *mockTransport) Close() error { m.closed = true; return nil }

type mockFactory struct {
	transports []*mockTransport
	auths      []ProvisionAuth
}

func (f *mockFactory) factory(ctx context.Context, auth ProvisionAuth) (SSHTransport, error) {
	f.auths = append(f.auths, auth)
	if len(f.transports) == 0 {
		return nil, fmt.Errorf("no mock transport left")
	}
	t := f.transports[0]
	f.transports = f.transports[1:]
	t.dialCalls = append(t.dialCalls, auth)
	return t, nil
}

func testProvisionRequest(t *testing.T, dir string) ProvisionRequest {
	t.Helper()
	binaryPath := filepath.Join(dir, "nexounel-node")
	if err := os.WriteFile(binaryPath, []byte("fake-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	return ProvisionRequest{
		Mode: ProvisionInstall, Host: "203.0.113.50", Port: 22, Username: "root",
		Password: "example-password-12345",
		NodeID:   "node-1", NodeKey: validTestKey(1), ConnectAddr: "v.example.invalid",
		ListenPort: 18000, ForwardRange: "20000-20010",
		LocalBinaryPath:    binaryPath,
		LocalResolversPath: filepath.Join(dir, "missing-resolvers.txt"),
		KeyFilePath:        "/opt/nexounel/node.key",
		NodeConfigPath:     "/opt/nexounel/nexounel-node.toml",
		ResolversFilePath:  "/opt/nexounel/client_resolvers.txt",
		BinaryPath:         "/opt/nexounel/nexounel-node",
		LocalVersion:       func(ctx context.Context) (string, error) { return "test-version-1", nil },
	}
}

func TestProvisionInstallOrderingAndRedaction(t *testing.T) {
	dir := t.TempDir()
	req := testProvisionRequest(t, dir)
	first := &mockTransport{fingerprint: "SHA256:testfingerprint"}
	second := &mockTransport{fingerprint: "SHA256:testfingerprint"}
	factory := &mockFactory{transports: []*mockTransport{first, second}}
	store := NewJobStore()
	job, err := RunProvision(context.Background(), req, factory.factory, store)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "succeeded" {
		t.Fatalf("job status = %q error = %q\nsteps: %+v\nlog: %v", job.Status, job.Error, job.Steps, job.Log)
	}
	// Step ordering: target check before ephemeral install, install
	// before enable, verify last (besides ephemeral removal).
	var stepNames []string
	for _, s := range job.Steps {
		stepNames = append(stepNames, s.Name)
	}
	ordered := []string{"connect to target", "check target system", "generate ephemeral key", "install ephemeral key", "reconnect with ephemeral key", "record local binary version", "transfer files", "install files", "enable and start node service", "verify node service", "remove ephemeral key"}
	if len(stepNames) != len(ordered) {
		t.Fatalf("steps = %v, want %v", stepNames, ordered)
	}
	for i, name := range ordered {
		if stepNames[i] != name {
			t.Fatalf("step %d = %q, want %q (all: %v)", i, stepNames[i], name, stepNames)
		}
	}
	// The second (ephemeral) transport performed the installs.
	joined := strings.Join(second.commands, "\n")
	for _, want := range []string{"mkdir -p /opt/nexounel", "install -m 755", "install -m 600", "systemctl daemon-reload", "systemctl enable --now nexounel-node", "systemctl is-active nexounel-node", "ss -tlnH"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("ephemeral transport commands missing %q:\n%s", want, joined)
		}
	}
	// Files transferred: binary, config, key, resolvers, unit.
	if len(second.files) != 5 {
		t.Fatalf("expected 5 transferred files, got %d", len(second.files))
	}
	var sawConfig, sawKey, sawResolvers, sawUnit, sawBinary bool
	for _, f := range second.files {
		switch filepath.Base(f.path) {
		case "nexounel-node":
			sawBinary = true
			if f.mode != 0o755 {
				t.Fatalf("binary mode %o", f.mode)
			}
		case "nexounel-node.toml":
			sawConfig = true
			if !strings.Contains(string(f.data), `DOMAINS = ["v.example.invalid"]`) {
				t.Fatalf("config content wrong:\n%s", f.data)
			}
			if strings.Contains(string(f.data), req.NodeKey) {
				t.Fatal("config embeds the node key")
			}
		case "node.key":
			sawKey = true
			if strings.TrimSpace(string(f.data)) != req.NodeKey || f.mode != 0o600 {
				t.Fatalf("key file wrong: %q mode %o", f.data, f.mode)
			}
		case "client_resolvers.txt":
			sawResolvers = true
			if !strings.Contains(string(f.data), "8.8.8.8") {
				t.Fatal("default resolvers not used when local file absent")
			}
		case "nexounel-node.service":
			sawUnit = true
			if !strings.Contains(string(f.data), "ExecStart=/opt/nexounel/nexounel-node -config /opt/nexounel/nexounel-node.toml") || !strings.Contains(string(f.data), "RestartSec=5") {
				t.Fatalf("unit content wrong:\n%s", f.data)
			}
		}
	}
	if !sawConfig || !sawKey || !sawResolvers || !sawUnit || !sawBinary {
		t.Fatalf("missing transfers: config=%v key=%v resolvers=%v unit=%v binary=%v", sawConfig, sawKey, sawResolvers, sawUnit, sawBinary)
	}
	// Ephemeral key removal verified on the ephemeral transport.
	if second.ephemeralSeen {
		t.Fatal("ephemeral key still present after run")
	}
	removalSeen := false
	for _, cmd := range second.commands {
		if strings.Contains(cmd, "grep -v") {
			removalSeen = true
		}
	}
	if !removalSeen {
		t.Fatal("ephemeral key removal command never ran")
	}
	// Redaction: no secret anywhere in the job log or steps.
	for _, line := range job.Log {
		if strings.Contains(line, req.Password) || strings.Contains(line, req.NodeKey) {
			t.Fatalf("secret leaked into job log: %q", line)
		}
	}
	for _, s := range job.Steps {
		if strings.Contains(s.Detail, req.Password) || strings.Contains(s.Detail, req.NodeKey) {
			t.Fatalf("secret leaked into step detail: %+v", s)
		}
	}
	// Password auth was used for the first dial, key auth for the second.
	if len(factory.auths) != 2 || factory.auths[0].Password == "" || len(factory.auths[1].PrivateKeyPEM) == 0 || factory.auths[1].Password != "" {
		t.Fatalf("auth sequence wrong: %+v", factory.auths)
	}
}

func TestProvisionFailureRemovesKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	req := testProvisionRequest(t, dir)
	first := &mockTransport{}
	second := &mockTransport{failSubstr: "systemctl enable --now"}
	factory := &mockFactory{transports: []*mockTransport{first, second}}
	job, err := RunProvision(context.Background(), req, factory.factory, NewJobStore())
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "failed" {
		t.Fatalf("job status = %q, want failed", job.Status)
	}
	joined := strings.Join(second.commands, "\n")
	if !strings.Contains(joined, "rm -f '/opt/nexounel/node.key'") {
		t.Fatalf("key material removal missing after failure:\n%s", joined)
	}
	if second.ephemeralSeen {
		t.Fatal("ephemeral key not removed after failure")
	}
	if !strings.Contains(joined, "grep -v") {
		t.Fatal("ephemeral removal missing after failure")
	}
	// Pre-existing services were left untouched: no stop/disable.
	if strings.Contains(joined, "disable --now") || strings.Contains(joined, "systemctl stop") {
		t.Fatalf("failure path touched pre-existing services:\n%s", joined)
	}
}

func TestProvisionTOFUConfirmation(t *testing.T) {
	dir := t.TempDir()
	req := testProvisionRequest(t, dir)
	unconfirmed := &UnconfirmedHostKeyError{Fingerprint: "SHA256:unconfirmedfp"}
	first := &mockTransport{dialErr: unconfirmed}
	factory := &mockFactory{transports: []*mockTransport{first}}
	job, err := RunProvision(context.Background(), req, factory.factory, NewJobStore())
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "needs-confirmation" || job.HostKeyFingerprint != "SHA256:unconfirmedfp" {
		t.Fatalf("TOFU outcome wrong: status=%q fp=%q err=%q", job.Status, job.HostKeyFingerprint, job.Error)
	}
	if len(first.commands) != 0 {
		t.Fatalf("commands ran before host-key confirmation: %v", first.commands)
	}
	// With confirmation, the run proceeds and the fingerprint is
	// persisted via the callback.
	confirmed := false
	req.ConfirmUnknown = true
	req.KnownFingerprint = ""
	req.OnFingerprintConfirmed = func(hostPort, fp string) { confirmed = true }
	second := &mockTransport{fingerprint: "SHA256:unconfirmedfp"}
	third := &mockTransport{fingerprint: "SHA256:unconfirmedfp"}
	factory2 := &mockFactory{transports: []*mockTransport{second, third}}
	job2, err := RunProvision(context.Background(), req, factory2.factory, NewJobStore())
	if err != nil {
		t.Fatal(err)
	}
	if job2.Status != "succeeded" || !confirmed {
		t.Fatalf("confirmed run wrong: status=%q confirmed=%v err=%q", job2.Status, confirmed, job2.Error)
	}
}

func TestProvisionRefusesNonDebianTarget(t *testing.T) {
	dir := t.TempDir()
	req := testProvisionRequest(t, dir)
	first := &mockTransport{outputs: map[string]string{"cat /etc/os-release": "ID=arch\n"}}
	factory := &mockFactory{transports: []*mockTransport{first}}
	job, err := RunProvision(context.Background(), req, factory.factory, NewJobStore())
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "failed" || !strings.Contains(job.Error, "unsupported target system") {
		t.Fatalf("non-Debian target not refused: status=%q err=%q", job.Status, job.Error)
	}
	if len(first.commands) > 2 {
		t.Fatalf("run continued after target refusal: %v", first.commands)
	}
}

func TestProvisionRotateOnlyTransfersKey(t *testing.T) {
	dir := t.TempDir()
	req := testProvisionRequest(t, dir)
	req.Mode = ProvisionRotate
	first := &mockTransport{}
	second := &mockTransport{}
	factory := &mockFactory{transports: []*mockTransport{first, second}}
	job, err := RunProvision(context.Background(), req, factory.factory, NewJobStore())
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "succeeded" {
		t.Fatalf("rotate job failed: %q steps=%+v", job.Error, job.Steps)
	}
	if len(second.files) != 1 || filepath.Base(second.files[0].path) != "node.key" {
		t.Fatalf("rotate transferred %d files, want only the key file", len(second.files))
	}
	joined := strings.Join(second.commands, "\n")
	if !strings.Contains(joined, "systemctl restart nexounel-node") {
		t.Fatalf("rotate did not restart the node:\n%s", joined)
	}
	if strings.Contains(joined, "nexounel-node.toml") || strings.Contains(joined, "daemon-reload") {
		t.Fatalf("rotate touched config/unit:\n%s", joined)
	}
}

func TestEphemeralKeyGeneration(t *testing.T) {
	pemBytes, line, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		t.Fatalf("authorized line wrong: %q", line)
	}
	if len(pemBytes) == 0 || !strings.Contains(string(pemBytes), "PRIVATE KEY") {
		t.Fatal("private key PEM malformed")
	}
	// The private key must parse as an SSH key.
	if _, err := ssh.ParsePrivateKey(pemBytes); err != nil {
		t.Fatalf("ephemeral private key does not parse: %v", err)
	}
	_, line2, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	if line == line2 {
		t.Fatal("ephemeral keys are not unique")
	}
}

func TestParseOSReleaseID(t *testing.T) {
	if got := ParseOSReleaseID("NAME=\"Debian GNU/Linux\"\nID=debian\n"); got != "debian" {
		t.Fatalf("got %q", got)
	}
	if got := ParseOSReleaseID("ID=\"ubuntu\"\n"); got != "ubuntu" {
		t.Fatalf("got %q", got)
	}
	if got := ParseOSReleaseID("ID=arch\n"); got != "arch" {
		t.Fatalf("got %q", got)
	}
}
