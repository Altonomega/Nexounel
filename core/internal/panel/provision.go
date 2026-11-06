package panel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/config"
	"golang.org/x/crypto/ssh"
)

// SSHTransport is the provisioning transport seam. Tests use a mock;
// production uses x/crypto/ssh. SendFile transfers bytes without ever
// embedding them in a command string.
type SSHTransport interface {
	Dial(ctx context.Context) error
	Fingerprint() string
	Run(ctx context.Context, cmd string) (stdout string, stderr string, err error)
	SendFile(ctx context.Context, data []byte, remotePath string, mode os.FileMode) error
	Close() error
}

// ProvisionAuth carries one provisioning run's authorization. Values live
// only in job memory and are scrubbed from every log line.
type ProvisionAuth struct {
	Username         string
	Password         string
	PrivateKeyPEM    []byte
	KnownFingerprint string
	ConfirmUnknown   bool
}

// UnconfirmedHostKeyError is returned by Dial when the target's host key
// is unknown and the admin has not confirmed it yet.
type UnconfirmedHostKeyError struct {
	Fingerprint string
}

func (e *UnconfirmedHostKeyError) Error() string {
	return fmt.Sprintf("unknown SSH host key %s: explicit admin confirmation is required", e.Fingerprint)
}

// ProvisionMode selects which provisioning flow runs.
type ProvisionMode string

const (
	// ProvisionInstall transfers binary, config, key and resolvers, then
	// enables and starts the node service.
	ProvisionInstall ProvisionMode = "install"
	// ProvisionRotate transfers only a new key file and restarts the node.
	ProvisionRotate ProvisionMode = "rotate"
	// ProvisionRemoveRemote stops and removes the remote service and key
	// file (with admin confirmation), leaving the binary in place.
	ProvisionRemoveRemote ProvisionMode = "remove-remote"
)

// ProvisionRequest is one provisioning run's input. All secret fields
// live only in the job's memory.
type ProvisionRequest struct {
	Mode             ProvisionMode
	Host             string
	Port             int
	Username         string
	Password         string
	PrivateKeyPEM    []byte
	KnownFingerprint string
	ConfirmUnknown   bool

	NodeID       string
	NodeKey      string
	ConnectAddr  string
	ListenPort   int
	ForwardRange string

	LocalBinaryPath    string
	LocalResolversPath string
	KeyFilePath        string // absolute path on the node, default /opt/nexounel/node.key
	NodeConfigPath     string // absolute path on the node
	ResolversFilePath  string // absolute path on the node
	BinaryPath         string // absolute path on the node
	RemoveService      bool   // ProvisionRemoveRemote only, admin-confirmed

	OnFingerprintConfirmed func(hostPort, fingerprint string)
	LocalVersion           func(ctx context.Context) (string, error)
}

// TransportFactory builds a transport for one dial attempt.
type TransportFactory func(ctx context.Context, auth ProvisionAuth) (SSHTransport, error)

// JobStep is one recorded provisioning step.
type JobStep struct {
	Name     string
	Status   string // pending, running, succeeded, failed, skipped
	Detail   string
	Started  time.Time
	Finished time.Time
}

// Job is one provisioning run's recorded outcome. Log lines are scrubbed
// of secrets before storage.
type Job struct {
	ID                 string
	Kind               string
	NodeID             string
	HostPort           string // SSH target, for host-key confirmation
	Status             string // running, succeeded, failed, needs-confirmation
	Error              string
	HostKeyFingerprint string
	CleanupWarning     string
	Steps              []JobStep
	Log                []string
	CreatedAt          time.Time
	FinishedAt         time.Time
	mu                 sync.Mutex
	secrets            []string
}

// JobStore holds provisioning jobs in memory.
type JobStore struct {
	mu   sync.Mutex
	jobs map[string]*Job
}

// NewJobStore creates an empty job store.
func NewJobStore() *JobStore { return &JobStore{jobs: map[string]*Job{}} }

func newJobID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// New creates and registers a job.
func (s *JobStore) New(kind, nodeID string, secrets []string) *Job {
	job := &Job{
		ID: newJobID(), Kind: kind, NodeID: nodeID, Status: "running",
		CreatedAt: time.Now(), secrets: secrets,
	}
	s.mu.Lock()
	s.jobs[job.ID] = job
	s.mu.Unlock()
	return job
}

// Get returns a job by id.
func (s *JobStore) Get(id string) (*Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	return job, ok
}

// List returns jobs newest first.
func (s *JobStore) List() []*Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Job, 0, len(s.jobs))
	for _, job := range s.jobs {
		out = append(out, job)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Logf appends a scrubbed line to the job log.
func (j *Job) Logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	line = ScrubSecrets(line, j.secrets)
	j.mu.Lock()
	j.Log = append(j.Log, line)
	j.mu.Unlock()
}

func (j *Job) beginStep(name string) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Steps = append(j.Steps, JobStep{Name: name, Status: "running", Started: time.Now()})
	return len(j.Steps) - 1
}

func (j *Job) finishStep(idx int, err error, detail string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if idx < 0 || idx >= len(j.Steps) {
		return
	}
	j.Steps[idx].Finished = time.Now()
	j.Steps[idx].Detail = detail
	if err != nil {
		j.Steps[idx].Status = "failed"
	} else {
		j.Steps[idx].Status = "succeeded"
	}
}

func (j *Job) finish(status, errText string) {
	j.mu.Lock()
	j.Status = status
	j.Error = errText
	j.FinishedAt = time.Now()
	j.mu.Unlock()
}

// GenerateEphemeralKey creates an in-memory ed25519 keypair: the PEM
// private key for the reconnect and the authorized_keys line for the
// password session. Nothing is written to disk.
func GenerateEphemeralKey() (privatePEM []byte, authorizedLine string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate ephemeral key: %w", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, "", fmt.Errorf("marshal ephemeral key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, "", fmt.Errorf("derive ephemeral public key: %w", err)
	}
	return pemBytes, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
}

// BuildNodeUnit renders the nexounel-node.service unit file.
func BuildNodeUnit(binaryPath, configPath string) string {
	return "[Unit]\n" +
		"Description=Nexounel node\n" +
		"After=network-online.target\n" +
		"Wants=network-online.target\n\n" +
		"[Service]\n" +
		"User=root\n" +
		"WorkingDirectory=/opt/nexounel\n" +
		"ExecStart=" + binaryPath + " -config " + configPath + "\n" +
		"Restart=on-failure\n" +
		"RestartSec=5\n\n" +
		"[Install]\n" +
		"WantedBy=multi-user.target\n"
}

// ParseOSReleaseID extracts the ID field from /etc/os-release content.
func ParseOSReleaseID(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ID=") {
			continue
		}
		id := strings.TrimSpace(strings.TrimPrefix(line, "ID="))
		return strings.Trim(id, `"'`)
	}
	return ""
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func defaultLocalVersion(binaryPath string) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		cmd := exec.CommandContext(ctx, binaryPath, "-version")
		out, err := cmd.Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	}
}

// RunProvision executes a provisioning run against a transport factory.
// It returns the recorded job; a failed run still returns a job (with
// Status "failed") except for setup errors, which return a nil job.
func RunProvision(ctx context.Context, req ProvisionRequest, factory TransportFactory, store *JobStore) (*Job, error) {
	if store == nil {
		store = NewJobStore()
	}
	if factory == nil {
		return nil, fmt.Errorf("transport factory is required")
	}
	if strings.TrimSpace(req.Host) == "" || req.Port < 1 || req.Port > 65535 || strings.TrimSpace(req.Username) == "" {
		return nil, fmt.Errorf("provisioning target host, port and username are required")
	}
	if req.Mode != ProvisionInstall && req.Mode != ProvisionRotate && req.Mode != ProvisionRemoveRemote {
		return nil, fmt.Errorf("unknown provisioning mode %q", req.Mode)
	}
	if err := validateNodeID(req.NodeID); err != nil {
		return nil, err
	}
	if req.Mode != ProvisionRemoveRemote {
		if err := validateNodeKey(req.NodeKey); err != nil {
			return nil, fmt.Errorf("invalid node key: %w", err)
		}
	}
	secrets := []string{req.Password, req.NodeKey, string(req.PrivateKeyPEM)}
	job := store.New(string(req.Mode), req.NodeID, secrets)
	job.HostPort = net.JoinHostPort(req.Host, fmt.Sprint(req.Port))
	runner := &provisionRunner{req: req, factory: factory, job: job, secrets: secrets}
	runner.run(ctx)
	return job, nil
}

type provisionRunner struct {
	req     ProvisionRequest
	factory TransportFactory
	job     *Job
	secrets []string

	active               SSHTransport
	ephemeralInstalled   bool
	ephemeralPubLine     string
	ephemeralPubBase64   string
	keyMaterialInstalled bool
	stagingDir           string
}

func (r *provisionRunner) run(ctx context.Context) {
	defer func() {
		// Always attempt ephemeral-key removal, then verify it.
		if r.ephemeralInstalled {
			r.removeEphemeralKey(ctx)
		}
		if r.active != nil {
			_ = r.active.Close()
		}
	}()
	if err := r.execute(ctx); err != nil {
		var unconfirmed *UnconfirmedHostKeyError
		if errors.As(err, &unconfirmed) {
			r.job.mu.Lock()
			r.job.HostKeyFingerprint = unconfirmed.Fingerprint
			r.job.mu.Unlock()
			r.job.finish("needs-confirmation", err.Error())
			return
		}
		r.job.finish("failed", err.Error())
		return
	}
	if r.job.CleanupWarning != "" {
		r.job.finish("succeeded", "")
		// Keep the warning visible via the log; status stays succeeded
		// because the provisioning itself completed.
		r.job.Logf("warning: %s", r.job.CleanupWarning)
		return
	}
	r.job.finish("succeeded", "")
}

func (r *provisionRunner) step(ctx context.Context, name string, timeout time.Duration, fn func(ctx context.Context) error) error {
	idx := r.job.beginStep(name)
	r.job.Logf("step: %s", name)
	stepCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := fn(stepCtx)
	detail := ""
	if err != nil {
		detail = ScrubSecrets(err.Error(), r.secrets)
		r.job.Logf("step failed: %s: %s", name, detail)
	} else {
		r.job.Logf("step ok: %s", name)
	}
	r.job.finishStep(idx, err, detail)
	return err
}

func (r *provisionRunner) execute(ctx context.Context) error {
	// (a) Connect with the admin-supplied authorization.
	var first *UnconfirmedHostKeyError
	err := r.step(ctx, "connect to target", 20*time.Second, func(stepCtx context.Context) error {
		transport, err := r.factory(stepCtx, ProvisionAuth{
			Username: r.req.Username, Password: r.req.Password, PrivateKeyPEM: r.req.PrivateKeyPEM,
			KnownFingerprint: r.req.KnownFingerprint, ConfirmUnknown: r.req.ConfirmUnknown,
		})
		if err != nil {
			return err
		}
		if err := transport.Dial(stepCtx); err != nil {
			_ = transport.Close()
			return err
		}
		r.active = transport
		if r.req.ConfirmUnknown && transport.Fingerprint() != "" && r.req.OnFingerprintConfirmed != nil {
			r.req.OnFingerprintConfirmed(net.JoinHostPort(r.req.Host, fmt.Sprint(r.req.Port)), transport.Fingerprint())
		}
		return nil
	})
	if err != nil {
		if errors.As(err, &first) {
			return first
		}
		return fmt.Errorf("connect to target: %w", err)
	}

	// Target check: Debian/Ubuntu with systemd.
	err = r.step(ctx, "check target system", 60*time.Second, func(stepCtx context.Context) error {
		out, _, err := r.active.Run(stepCtx, "cat /etc/os-release")
		if err != nil {
			return fmt.Errorf("read /etc/os-release: %w", err)
		}
		id := ParseOSReleaseID(out)
		if id != "debian" && id != "ubuntu" {
			return fmt.Errorf("unsupported target system %q: only Debian and Ubuntu targets are supported", id)
		}
		sysctl, _, err := r.active.Run(stepCtx, "command -v systemctl")
		if err != nil || strings.TrimSpace(sysctl) == "" {
			return fmt.Errorf("target has no systemctl: systemd is required")
		}
		r.job.Logf("target system: %s with systemd", id)
		return nil
	})
	if err != nil {
		return err
	}

	// (b) Ephemeral keypair, in memory only.
	var ephemeralPEM []byte
	err = r.step(ctx, "generate ephemeral key", 10*time.Second, func(stepCtx context.Context) error {
		pemBytes, line, err := GenerateEphemeralKey()
		if err != nil {
			return err
		}
		ephemeralPEM = pemBytes
		r.ephemeralPubLine = line
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			r.ephemeralPubBase64 = fields[1]
		}
		r.secrets = append(r.secrets, string(ephemeralPEM))
		r.job.secrets = r.secrets
		return nil
	})
	if err != nil {
		return err
	}

	// (c) Append the ephemeral public key via the first session.
	err = r.step(ctx, "install ephemeral key", 60*time.Second, func(stepCtx context.Context) error {
		cmd := "mkdir -p ~/.ssh && chmod 700 ~/.ssh && printf '%s\\n' " + shellQuote(r.ephemeralPubLine) + " >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
		if _, _, err := r.active.Run(stepCtx, cmd); err != nil {
			return fmt.Errorf("append ephemeral key: %w", err)
		}
		r.ephemeralInstalled = true
		return nil
	})
	if err != nil {
		return err
	}

	// Reconnect with the ephemeral key.
	err = r.step(ctx, "reconnect with ephemeral key", 20*time.Second, func(stepCtx context.Context) error {
		old := r.active
		transport, err := r.factory(stepCtx, ProvisionAuth{
			Username: r.req.Username, PrivateKeyPEM: ephemeralPEM,
			KnownFingerprint: r.req.KnownFingerprint, ConfirmUnknown: true,
		})
		if err != nil {
			return err
		}
		if err := transport.Dial(stepCtx); err != nil {
			_ = transport.Close()
			return err
		}
		_ = old.Close()
		r.active = transport
		return nil
	})
	if err != nil {
		return fmt.Errorf("reconnect with ephemeral key: %w", err)
	}

	// (d)+(e) Mode-specific transfer and service steps. Any failure
	// triggers key-material cleanup below.
	runErr := r.runModeSteps(ctx)
	if runErr != nil {
		if r.keyMaterialInstalled {
			_ = r.step(ctx, "remove transferred key material", 60*time.Second, func(stepCtx context.Context) error {
				_, _, err := r.active.Run(stepCtx, "rm -f "+shellQuote(r.req.KeyFilePath))
				return err
			})
			r.keyMaterialInstalled = false
		}
		return runErr
	}
	return nil
}

func (r *provisionRunner) runModeSteps(ctx context.Context) error {
	switch r.req.Mode {
	case ProvisionInstall:
		return r.installSteps(ctx)
	case ProvisionRotate:
		return r.rotateSteps(ctx)
	case ProvisionRemoveRemote:
		return r.removeSteps(ctx)
	default:
		return fmt.Errorf("unknown provisioning mode %q", r.req.Mode)
	}
}

func (r *provisionRunner) installSteps(ctx context.Context) error {
	localVersion := ""
	err := r.step(ctx, "record local binary version", 60*time.Second, func(stepCtx context.Context) error {
		versionFn := r.req.LocalVersion
		if versionFn == nil {
			versionFn = defaultLocalVersion(r.req.LocalBinaryPath)
		}
		version, err := versionFn(stepCtx)
		if err != nil {
			r.job.Logf("warning: could not record local binary version: %s", ScrubSecrets(err.Error(), r.secrets))
			return nil // best-effort
		}
		localVersion = version
		r.job.Logf("local binary version: %s", version)
		return nil
	})
	if err != nil {
		return err
	}

	// Build transfer payloads (never embedded in command strings).
	pending := PendingNode{
		ID: r.req.NodeID, Key: r.req.NodeKey, ConnectAddress: r.req.ConnectAddr,
		ListenPort: r.req.ListenPort, ForwardRange: r.req.ForwardRange,
	}
	nodeConfig := BuildNodeConfig(pending, r.req.KeyFilePath, r.req.ResolversFilePath)
	resolvers, err := r.resolversContent()
	if err != nil {
		return err
	}
	binaryData, err := os.ReadFile(r.req.LocalBinaryPath)
	if err != nil {
		return fmt.Errorf("read local node binary: %w", err)
	}
	unit := BuildNodeUnit(r.req.BinaryPath, r.req.NodeConfigPath)
	stageSuffix, err := randomHex(8)
	if err != nil {
		return err
	}
	r.stagingDir = "/tmp/nexounel-provision-" + stageSuffix

	type transfer struct {
		name string
		data []byte
		mode os.FileMode
	}
	transfers := []transfer{
		{"nexounel-node", binaryData, 0o755},
		{"nexounel-node.toml", []byte(nodeConfig), 0o600},
		{"node.key", []byte(r.req.NodeKey + "\n"), 0o600},
		{"client_resolvers.txt", []byte(resolvers), 0o600},
		{"nexounel-node.service", []byte(unit), 0o644},
	}
	err = r.step(ctx, "transfer files", 120*time.Second, func(stepCtx context.Context) error {
		for _, t := range transfers {
			remote := r.stagingDir + "/" + t.name
			if err := r.active.SendFile(stepCtx, t.data, remote, t.mode); err != nil {
				return fmt.Errorf("transfer %s: %w", t.name, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	err = r.step(ctx, "install files", 60*time.Second, func(stepCtx context.Context) error {
		commands := []string{
			"mkdir -p /opt/nexounel",
			"install -m 755 " + shellQuote(r.stagingDir+"/nexounel-node") + " " + shellQuote(r.req.BinaryPath),
			"install -m 600 " + shellQuote(r.stagingDir+"/nexounel-node.toml") + " " + shellQuote(r.req.NodeConfigPath),
			"install -m 600 " + shellQuote(r.stagingDir+"/node.key") + " " + shellQuote(r.req.KeyFilePath),
			"install -m 644 " + shellQuote(r.stagingDir+"/client_resolvers.txt") + " " + shellQuote(r.req.ResolversFilePath),
			"install -m 644 " + shellQuote(r.stagingDir+"/nexounel-node.service") + " /etc/systemd/system/nexounel-node.service",
		}
		for _, cmd := range commands {
			if _, _, err := r.active.Run(stepCtx, cmd); err != nil {
				return err
			}
		}
		r.keyMaterialInstalled = true
		return nil
	})
	if err != nil {
		return err
	}

	err = r.step(ctx, "enable and start node service", 60*time.Second, func(stepCtx context.Context) error {
		if _, _, err := r.active.Run(stepCtx, "systemctl daemon-reload"); err != nil {
			return err
		}
		if _, _, err := r.active.Run(stepCtx, "systemctl enable --now nexounel-node"); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	return r.verifyNode(ctx, localVersion)
}

func (r *provisionRunner) rotateSteps(ctx context.Context) error {
	err := r.step(ctx, "transfer new key file", 120*time.Second, func(stepCtx context.Context) error {
		stage, err := randomHex(8)
		if err != nil {
			return err
		}
		r.stagingDir = "/tmp/nexounel-provision-" + stage
		if err := r.active.SendFile(stepCtx, []byte(r.req.NodeKey+"\n"), r.stagingDir+"/node.key", 0o600); err != nil {
			return err
		}
		if _, _, err := r.active.Run(stepCtx, "install -m 600 "+shellQuote(r.stagingDir+"/node.key")+" "+shellQuote(r.req.KeyFilePath)); err != nil {
			return err
		}
		r.keyMaterialInstalled = true
		return nil
	})
	if err != nil {
		return err
	}
	err = r.step(ctx, "restart node service", 60*time.Second, func(stepCtx context.Context) error {
		if _, _, err := r.active.Run(stepCtx, "systemctl restart nexounel-node"); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return r.verifyNode(ctx, "")
}

func (r *provisionRunner) removeSteps(ctx context.Context) error {
	if !r.req.RemoveService {
		return fmt.Errorf("remote removal requires explicit admin confirmation")
	}
	return r.step(ctx, "stop and remove remote node service", 60*time.Second, func(stepCtx context.Context) error {
		commands := []string{
			"systemctl disable --now nexounel-node",
			"rm -f /etc/systemd/system/nexounel-node.service " + shellQuote(r.req.KeyFilePath),
			"systemctl daemon-reload",
		}
		for _, cmd := range commands {
			if _, _, err := r.active.Run(stepCtx, cmd); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *provisionRunner) verifyNode(ctx context.Context, localVersion string) error {
	return r.step(ctx, "verify node service", 60*time.Second, func(stepCtx context.Context) error {
		out, _, err := r.active.Run(stepCtx, "systemctl is-active nexounel-node")
		if err != nil {
			return fmt.Errorf("node service is not active: %w", err)
		}
		if strings.TrimSpace(out) != "active" {
			return fmt.Errorf("node service is not active: is-active reported %q", strings.TrimSpace(out))
		}
		// Remote version check is best-effort: warn on mismatch only.
		if localVersion != "" {
			remoteOut, _, err := r.active.Run(stepCtx, shellQuote(r.req.BinaryPath)+" -version")
			if err == nil {
				remoteVersion := strings.TrimSpace(remoteOut)
				if remoteVersion != localVersion {
					r.job.Logf("warning: remote binary version %q differs from local %q", remoteVersion, localVersion)
				}
			}
		}
		// Forward-port listen check on the first port of the range.
		if r.req.ForwardRange != "" {
			lo, _, err := config.ParsePortRange(r.req.ForwardRange)
			if err == nil {
				ssOut, _, err := r.active.Run(stepCtx, "ss -tlnH")
				if err != nil {
					r.job.Logf("warning: ss listen check unavailable: %s", ScrubSecrets(err.Error(), r.secrets))
				} else if !strings.Contains(ssOut, ":"+fmt.Sprint(lo)) {
					return fmt.Errorf("forward port %d is not listening", lo)
				}
			}
		}
		return nil
	})
}

func (r *provisionRunner) resolversContent() (string, error) {
	if strings.TrimSpace(r.req.LocalResolversPath) == "" {
		return DefaultResolversContent(), nil
	}
	data, err := os.ReadFile(r.req.LocalResolversPath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultResolversContent(), nil
		}
		return "", fmt.Errorf("read local resolvers file: %w", err)
	}
	// Strip comment lines? No: copy verbatim; the node parses the file.
	return string(data), nil
}

// removeEphemeralKey removes the ephemeral public key from
// authorized_keys and verifies the removal by re-listing the file.
// It runs even when earlier steps failed.
func (r *provisionRunner) removeEphemeralKey(ctx context.Context) {
	if r.active == nil || r.ephemeralPubLine == "" {
		return
	}
	idx := r.job.beginStep("remove ephemeral key")
	removeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	quoted := shellQuote(r.ephemeralPubLine)
	// grep exits 1 when every line is filtered out (single-key file),
	// which is success here: ignore its status and always move the
	// filtered file into place.
	cmd := "grep -v -F " + quoted + " ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp || true; mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
	_, _, runErr := r.active.Run(removeCtx, cmd)
	verified := false
	if runErr == nil {
		out, _, catErr := r.active.Run(removeCtx, "cat ~/.ssh/authorized_keys 2>/dev/null || true")
		if catErr == nil && !strings.Contains(out, r.ephemeralPubBase64) {
			verified = true
		}
	}
	if runErr != nil {
		r.job.CleanupWarning = fmt.Sprintf("ephemeral key removal failed: %s", ScrubSecrets(runErr.Error(), r.secrets))
		r.job.Logf("warning: ephemeral key removal failed: %s", ScrubSecrets(runErr.Error(), r.secrets))
		r.job.finishStep(idx, runErr, "removal failed")
		return
	}
	if !verified {
		r.job.CleanupWarning = "ephemeral key removal could not be verified: the public key may still be present in authorized_keys"
		r.job.Logf("warning: ephemeral key removal could not be verified")
		r.job.finishStep(idx, fmt.Errorf("removal not verified"), "not verified")
		return
	}
	r.job.Logf("step ok: remove ephemeral key (verified)")
	r.job.finishStep(idx, nil, "verified")
}

func randomHex(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ---------------------------------------------------------------------------
// Real SSH transport (x/crypto/ssh)
// ---------------------------------------------------------------------------

type sshTransport struct {
	addr             string
	username         string
	password         string
	privateKeyPEM    []byte
	knownFingerprint string
	confirmUnknown   bool
	client           *ssh.Client
	fingerprint      string
}

// NewRealTransportFactory builds transports that dial the given SSH
// target address (host:port).
func NewRealTransportFactory(addr string) TransportFactory {
	return func(ctx context.Context, auth ProvisionAuth) (SSHTransport, error) {
		return &sshTransport{
			addr:     addr,
			username: auth.Username, password: auth.Password,
			privateKeyPEM: auth.PrivateKeyPEM, knownFingerprint: auth.KnownFingerprint,
			confirmUnknown: auth.ConfirmUnknown,
		}, nil
	}
}

// Fingerprint returns the host-key fingerprint seen on the last dial.
func (t *sshTransport) Fingerprint() string { return t.fingerprint }

// Dial connects with a 20s timeout and TOFU host-key checking.
func (t *sshTransport) Dial(ctx context.Context) error {
	if t.addr == "" {
		return fmt.Errorf("ssh transport has no target address")
	}
	cfg := &ssh.ClientConfig{
		User:            t.username,
		Timeout:         20 * time.Second,
		HostKeyCallback: t.hostKeyCallback,
	}
	if t.password != "" {
		cfg.Auth = append(cfg.Auth, ssh.Password(t.password))
	}
	if len(t.privateKeyPEM) > 0 {
		signer, err := ssh.ParsePrivateKey(t.privateKeyPEM)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}
		cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signer))
	}
	if len(cfg.Auth) == 0 {
		return fmt.Errorf("no SSH authorization method configured")
	}
	dialer := net.Dialer{Timeout: 20 * time.Second}
	netConn, err := dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", t.addr, err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(netConn, t.addr, cfg)
	if err != nil {
		_ = netConn.Close()
		return err
	}
	t.client = ssh.NewClient(conn, chans, reqs)
	return nil
}

func (t *sshTransport) hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	fp := ssh.FingerprintSHA256(key)
	t.fingerprint = fp
	if t.knownFingerprint != "" {
		if fp != t.knownFingerprint {
			return fmt.Errorf("SSH host key mismatch for %s: got %s, expected %s", hostname, fp, t.knownFingerprint)
		}
		return nil
	}
	if !t.confirmUnknown {
		return &UnconfirmedHostKeyError{Fingerprint: fp}
	}
	return nil
}

// Run executes one command with the caller's context as its timeout.
func (t *sshTransport) Run(ctx context.Context, cmd string) (string, string, error) {
	if t.client == nil {
		return "", "", fmt.Errorf("not connected")
	}
	session, err := t.client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer func() { _ = session.Close() }()
	var stdout, stderr strings.Builder
	session.Stdout = &stdout
	session.Stderr = &stderr
	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()
	select {
	case err := <-done:
		return stdout.String(), stderr.String(), err
	case <-ctx.Done():
		_ = session.Close()
		return stdout.String(), stderr.String(), ctx.Err()
	}
}

// SendFile transfers bytes via a remote "cat" (no scp binary needed),
// then sets the requested mode.
func (t *sshTransport) SendFile(ctx context.Context, data []byte, remotePath string, mode os.FileMode) error {
	if t.client == nil {
		return fmt.Errorf("not connected")
	}
	session, err := t.client.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	session.Stderr = &stderr
	if err := session.Start("cat > " + shellQuote(remotePath)); err != nil {
		return err
	}
	if _, err := io.Copy(stdin, strings.NewReader(string(data))); err != nil {
		_ = stdin.Close()
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("transfer to %s failed: %w: %s", remotePath, err, strings.TrimSpace(stderr.String()))
		}
	case <-ctx.Done():
		_ = session.Close()
		return ctx.Err()
	}
	_, _, err = t.Run(ctx, fmt.Sprintf("chmod %04o %s", mode.Perm(), shellQuote(remotePath)))
	return err
}

// Close disconnects the transport.
func (t *sshTransport) Close() error {
	if t.client == nil {
		return nil
	}
	err := t.client.Close()
	t.client = nil
	return err
}
