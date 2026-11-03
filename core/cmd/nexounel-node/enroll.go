// Enroll mode: outbound-only manual node join (§3.3).
//
// A brand-new node has no key, so it cannot open a normal session.
// In enroll mode the node builds a bootstrap client keyed by the
// token-derived key, probes resolvers, opens a bootstrap session,
// and presents its join token inside an enrollment request over a
// reserved stream. On success it receives its node identity,
// per-node key, node configuration, and mesh control secret,
// writes them to disk, and restarts itself as a normal node.
//
// Fail-closed throughout:
//   - the token is never logged (only its fingerprint, and only
//     inside the enrollment exchange);
//   - forward ports are never opened in enroll mode: the enroll
//     client never calls Run and never binds a listener;
//   - a bad/used/expired/revoked token is a permanent failure:
//     exit, ask the operator for a fresh token, never retry;
//   - transient failures (no working resolver, mother or panel
//     unreachable) retry with backoff until the token expires or
//     the process is stopped;
//   - post-enrollment local failures (unwritable key/config) are
//     fatal, never retried: the token is already burned, and
//     retrying enrollment with it would fail permanently anyway.
//     The operator fixes the files and re-enrolls with a fresh
//     token.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/client"
	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
)

// errEnrolled is returned by runEnrollMode when enrollment
// succeeded and the node must restart as a normal node. It is a
// control-flow signal, not an error.
var errEnrolled = errors.New("enrollment complete: restart as a normal node")

// permanentEnrollmentError marks a permanent token failure: the
// operator must issue a fresh token. It wraps the wire error code.
type permanentEnrollmentError struct {
	code string
}

func (e *permanentEnrollmentError) Error() string {
	return fmt.Sprintf("enrollment permanently failed (%s): issue a fresh join token", e.code)
}

// loadJoinToken resolves the join token from the flag, the file,
// or stdin, in that order. The value is never logged. An empty
// result is an error: enroll mode without a token cannot proceed.
func loadJoinToken(flagValue, filePath string, stdin io.Reader) (string, error) {
	if strings.TrimSpace(flagValue) != "" {
		return strings.TrimSpace(flagValue), nil
	}
	if strings.TrimSpace(filePath) != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read join token file: %w", err)
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("join token file %s is empty", filePath)
		}
		return token, nil
	}
	if stdin == nil {
		return "", errors.New("a join token is required: --join-token, --join-token-file, or stdin")
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		return "", fmt.Errorf("read join token from stdin: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("a join token is required: --join-token, --join-token-file, or stdin")
	}
	return token, nil
}

// exchangeEnrollment performs one enrollment exchange over an
// open reserved stream: one request, one response. Transport
// errors and transient error codes are plain errors (retry); a
// permanent token error code is a *permanentEnrollmentError
// (stop). The token is never logged.
func exchangeEnrollment(ctx context.Context, conn net.Conn, nodeID, token string) (enroll.EnrollmentResponse, error) {
	reqBytes, err := enroll.MarshalRequest(enroll.EnrollmentRequest{NodeID: nodeID, Token: token})
	if err != nil {
		return enroll.EnrollmentResponse{}, err
	}
	deadline := time.Now().Add(30 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(reqBytes); err != nil {
		return enroll.EnrollmentResponse{}, fmt.Errorf("send enrollment request: %w", err)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(conn).Decode(&raw); err != nil {
		return enroll.EnrollmentResponse{}, fmt.Errorf("read enrollment response: %w", err)
	}
	resp, err := enroll.ParseResponse(raw)
	if err != nil {
		return enroll.EnrollmentResponse{}, fmt.Errorf("decode enrollment response: %w", err)
	}
	if resp.ErrorCode != "" {
		if enroll.PermanentErrorCode(resp.ErrorCode) {
			return enroll.EnrollmentResponse{}, &permanentEnrollmentError{code: resp.ErrorCode}
		}
		return enroll.EnrollmentResponse{}, fmt.Errorf("enrollment refused (%s): %s", resp.ErrorCode, resp.Error)
	}
	if strings.TrimSpace(resp.NodeKey) == "" || strings.TrimSpace(resp.NodeConfig) == "" {
		return enroll.EnrollmentResponse{}, errors.New("enrollment response is missing the node key or config")
	}
	return resp, nil
}

// writeFileAtomic writes data to path with perm via a temp file in
// the same directory and a rename, so a crash mid-write never
// leaves a partial key or config behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".nexounel-write-*")
	if err != nil {
		return fmt.Errorf("create staging file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write staging file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("restrict staging file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close staging file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// meshControlSecretPath resolves where the mesh control secret is
// stored: MESH_CONTROL_SECRET_FILE when set, else a sibling of
// the node key file. The secret is useless without the key file
// next to it, so keeping them together is the sane default.
func meshControlSecretPath(cfg config.ClientConfig) string {
	if strings.TrimSpace(cfg.MeshControlSecretFile) != "" {
		return cfg.MeshControlSecretFile
	}
	return filepath.Join(filepath.Dir(cfg.NodeKeyFile), "mesh-control-secret.key")
}

// writeEnrolledFiles installs the enrollment results: the node key
// (0600), the mesh control secret (0600, when issued), and the node
// config (validated before it replaces the bootstrap config). The
// config is installed last: it is the commit point. A failure here
// is fatal to the process (see the package doc): the token is
// already burned. overrides carries the invocation's resolvers
// path: the issued config names no resolvers file (that path is
// not a TOML key), so validation must reuse the same overrides
// the node started with.
func writeEnrolledFiles(cfg config.ClientConfig, overrides config.ClientConfigOverrides, resp enroll.EnrollmentResponse) error {
	keyData := strings.TrimSpace(resp.NodeKey) + "\n"
	if err := writeFileAtomic(cfg.NodeKeyFile, []byte(keyData), 0o600); err != nil {
		return fmt.Errorf("write node key file: %w", err)
	}
	secretPath := meshControlSecretPath(cfg)
	if strings.TrimSpace(resp.MeshControlSecret) != "" {
		secretData := strings.TrimSpace(resp.MeshControlSecret) + "\n"
		if err := writeFileAtomic(secretPath, []byte(secretData), 0o600); err != nil {
			return fmt.Errorf("write mesh control secret file: %w", err)
		}
	}
	// Validate the issued config before it replaces the bootstrap
	// config: stage it, load it, then rename. A config that does
	// not load must never become the node's config.
	staging := cfg.ConfigPath + ".enrolled"
	if err := os.WriteFile(staging, []byte(resp.NodeConfig), 0o600); err != nil {
		return fmt.Errorf("stage issued node config: %w", err)
	}
	defer os.Remove(staging)
	if _, err := config.LoadClientConfigWithOverrides(staging, overrides); err != nil {
		return fmt.Errorf("issued node config does not validate: %w", err)
	}
	if err := os.Rename(staging, cfg.ConfigPath); err != nil {
		return fmt.Errorf("install issued node config: %w", err)
	}
	return nil
}

// enrollClientOverrides builds the Bootstrap overrides for the
// enroll client: the token-derived bootstrap key replaces the
// (not yet written) node key file, and the key-file override is
// cleared so the bootstrap key is actually used.
func enrollClientOverrides(base config.ClientConfigOverrides, bootstrapKeyHex string) config.ClientConfigOverrides {
	out := config.ClientConfigOverrides{
		ResolversFilePath: base.ResolversFilePath,
		Resolvers:         base.Resolvers,
		Values:            make(map[string]any, len(base.Values)+2),
	}
	for k, v := range base.Values {
		out.Values[k] = v
	}
	out.Values["EncryptionKey"] = bootstrapKeyHex
	out.Values["NodeKeyFile"] = ""
	return out
}

// runEnrollAttempt performs one enrollment attempt: probe, session,
// reserved stream, exchange. The client is closed on every exit so
// a retry loop cannot leak descriptors.
func runEnrollAttempt(ctx context.Context, configPath string, overrides config.ClientConfigOverrides, cfg config.ClientConfig, token string) (enroll.EnrollmentResponse, error) {
	bootstrapKeyHex, err := enroll.BootstrapKeyString(token)
	if err != nil {
		// A malformed token can never enroll: permanent.
		return enroll.EnrollmentResponse{}, &permanentEnrollmentError{code: enroll.ErrCodeUnknownToken}
	}
	app, err := client.Bootstrap(configPath, enrollClientOverrides(overrides, bootstrapKeyHex))
	if err != nil {
		return enroll.EnrollmentResponse{}, fmt.Errorf("bootstrap enroll client: %w", err)
	}
	defer app.Close()
	if err := app.RunInitialMTUTests(ctx); err != nil {
		return enroll.EnrollmentResponse{}, fmt.Errorf("probe resolvers: %w", err)
	}
	if err := app.InitializeSessionContext(ctx, 3); err != nil {
		return enroll.EnrollmentResponse{}, fmt.Errorf("open bootstrap session: %w", err)
	}
	conn, err := app.OpenReservedStream(ctx, enroll.EnrollmentTarget)
	if err != nil {
		return enroll.EnrollmentResponse{}, fmt.Errorf("open enrollment stream: %w", err)
	}
	defer conn.Close()
	return exchangeEnrollment(ctx, conn, cfg.NodeID, token)
}

// runEnrollMode retries enrollment until success, a permanent
// failure, or ctx cancellation. Backoff starts at 5s and caps at
// 60s. It returns errEnrolled on success.
func runEnrollMode(ctx context.Context, configPath string, overrides config.ClientConfigOverrides, cfg config.ClientConfig, token string) error {
	if cfg.ProtocolType != "TCP" {
		return fmt.Errorf("enroll mode requires PROTOCOL_TYPE=TCP (reserved streams use STREAM_SYN), have %q", cfg.ProtocolType)
	}
	if err := multisession.ValidateNodeID(cfg.NodeID); err != nil {
		return fmt.Errorf("enroll mode: %w", err)
	}
	backoff := 5 * time.Second
	const maxBackoff = 60 * time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
		resp, err := runEnrollAttempt(attemptCtx, configPath, overrides, cfg, token)
		cancel()
		if err == nil {
			if werr := writeEnrolledFiles(cfg, overrides, resp); werr != nil {
				return werr
			}
			return errEnrolled
		}
		var permanent *permanentEnrollmentError
		if errors.As(err, &permanent) {
			return err
		}
		fmt.Fprintf(os.Stderr, "Enrollment attempt failed (will retry): %v\n", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// restartAsNormalNode replaces this process with a normal node
// invocation on the same config (the issued config is already in
// place). It never returns on success. The caller treats any
// return as a failure and exits 0: enrollment already succeeded,
// and the operator restarts the node normally.
func restartAsNormalNode(configPath, resolversPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	argv := []string{exe, "-config", configPath}
	if strings.TrimSpace(resolversPath) != "" {
		argv = append(argv, "-resolvers", resolversPath)
	}
	return syscall.Exec(exe, argv, os.Environ())
}
