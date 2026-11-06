package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/config"
	"github.com/Altonomega/Nexounel/core/internal/enroll"
)

func TestLoadJoinTokenPrecedence(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token.txt")
	if err := os.WriteFile(tokenFile, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Flag wins over file and stdin.
	got, err := loadJoinToken("flag-token", tokenFile, strings.NewReader("stdin-token"))
	if err != nil || got != "flag-token" {
		t.Fatalf("flag: got %q, err %v", got, err)
	}
	// File wins over stdin, whitespace trimmed.
	got, err = loadJoinToken("", tokenFile, strings.NewReader("stdin-token"))
	if err != nil || got != "file-token" {
		t.Fatalf("file: got %q, err %v", got, err)
	}
	// Stdin is the last resort.
	got, err = loadJoinToken("", "", strings.NewReader("  stdin-token\n"))
	if err != nil || got != "stdin-token" {
		t.Fatalf("stdin: got %q, err %v", got, err)
	}
	// Nothing anywhere is an error.
	if _, err := loadJoinToken("", "", strings.NewReader("  \n")); err == nil {
		t.Fatal("empty token must be refused")
	}
	if _, err := loadJoinToken("", "", nil); err == nil {
		t.Fatal("no token source must be refused")
	}
	// Missing file is an error, not a fallthrough to stdin.
	if _, err := loadJoinToken("", filepath.Join(dir, "missing.txt"), strings.NewReader("stdin-token")); err == nil {
		t.Fatal("missing token file must be refused")
	}
}

func TestExchangeEnrollmentSuccess(t *testing.T) {
	clientEnd, handlerEnd := net.Pipe()
	defer clientEnd.Close()
	defer handlerEnd.Close()
	go func() {
		dec := json.NewDecoder(handlerEnd)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return
		}
		req, err := enroll.ParseRequest(raw)
		if err != nil {
			return
		}
		if req.NodeID != "node-1" || req.Token != "tok" {
			return
		}
		resp, _ := enroll.MarshalResponse(enroll.EnrollmentResponse{
			NodeID: "node-1", NodeKey: "k", NodeConfig: "c", MeshControlSecret: "s",
		})
		_ = handlerEnd.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = handlerEnd.Write(resp)
	}()
	resp, err := exchangeEnrollment(context.Background(), clientEnd, "node-1", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if resp.NodeKey != "k" || resp.NodeConfig != "c" || resp.MeshControlSecret != "s" {
		t.Fatalf("response = %+v", resp)
	}
}

func TestExchangeEnrollmentClassifiesErrors(t *testing.T) {
	cases := []struct {
		name      string
		resp      enroll.EnrollmentResponse
		raw       []byte
		permanent bool
	}{
		{"burned", enroll.EnrollmentResponse{ErrorCode: enroll.ErrCodeBurnedToken}, nil, true},
		{"expired", enroll.EnrollmentResponse{ErrorCode: enroll.ErrCodeExpiredToken}, nil, true},
		{"unknown", enroll.EnrollmentResponse{ErrorCode: enroll.ErrCodeUnknownToken}, nil, true},
		{"used", enroll.EnrollmentResponse{ErrorCode: enroll.ErrCodeUsedToken}, nil, true},
		{"revoked", enroll.EnrollmentResponse{ErrorCode: enroll.ErrCodeRevokedToken}, nil, true},
		{"failed", enroll.EnrollmentResponse{ErrorCode: enroll.ErrCodeFailed}, nil, false},
		{"malformed", enroll.EnrollmentResponse{}, []byte("{nope"), false},
		{"missing key", enroll.EnrollmentResponse{NodeID: "node-1", NodeConfig: "c"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientEnd, handlerEnd := net.Pipe()
			defer clientEnd.Close()
			defer handlerEnd.Close()
			go func() {
				var skip json.RawMessage
				_ = json.NewDecoder(handlerEnd).Decode(&skip)
				data := tc.raw
				if data == nil {
					data, _ = enroll.MarshalResponse(tc.resp)
				}
				_ = handlerEnd.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, _ = handlerEnd.Write(data)
			}()
			_, err := exchangeEnrollment(context.Background(), clientEnd, "node-1", "tok")
			if err == nil {
				t.Fatal("must fail")
			}
			var permanent *permanentEnrollmentError
			if tc.permanent && !errors.As(err, &permanent) {
				t.Fatalf("err = %v, want a permanent error", err)
			}
			if !tc.permanent && errors.As(err, &permanent) {
				t.Fatalf("err = %v, must not be permanent", err)
			}
		})
	}
}

func writeEnrollTestBootstrapConfig(t *testing.T, dir string) (configPath, resolversPath, keyPath string) {
	t.Helper()
	logDir := filepath.Join(dir, "logs")
	configPath = filepath.Join(dir, "node.toml")
	keyPath = filepath.Join(dir, "node.key")
	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "TCP"
DOMAINS = ["a.example.com"]
DATA_ENCRYPTION_METHOD = 5
ENCRYPTION_KEY = "bootstrap-placeholder"
LOG_DIR = "`+logDir+`"
MIN_UPLOAD_MTU = 40
MAX_UPLOAD_MTU = 200
MIN_DOWNLOAD_MTU = 100
MAX_DOWNLOAD_MTU = 4000
NODE_ID = "node-1"
NODE_KEY_FILE = "`+keyPath+`"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	resolversPath = filepath.Join(dir, "resolvers.txt")
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return configPath, resolversPath, keyPath
}

func TestWriteEnrolledFiles(t *testing.T) {
	dir := t.TempDir()
	configPath, resolversPath, keyPath := writeEnrollTestBootstrapConfig(t, dir)
	overrides := config.ClientConfigOverrides{ResolversFilePath: &resolversPath}
	cfg, err := config.LoadClientConfigWithOverrides(configPath, overrides)
	if err != nil {
		t.Fatal(err)
	}
	issued := `
PROTOCOL_TYPE = "TCP"
DOMAINS = ["a.example.com"]
DATA_ENCRYPTION_METHOD = 5
LOG_DIR = "` + filepath.Join(dir, "logs") + `"
MIN_UPLOAD_MTU = 40
MAX_UPLOAD_MTU = 200
MIN_DOWNLOAD_MTU = 100
MAX_DOWNLOAD_MTU = 4000
NODE_ID = "node-1"
NODE_KEY_FILE = "` + keyPath + `"
`
	resp := enroll.EnrollmentResponse{NodeID: "node-1", NodeKey: "issued-node-key", NodeConfig: issued, MeshControlSecret: "issued-mesh-secret"}
	if err := writeEnrolledFiles(cfg, overrides, resp); err != nil {
		t.Fatal(err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(keyData)) != "issued-node-key" {
		t.Fatalf("key file = %q", keyData)
	}
	if st, err := os.Stat(keyPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, err %v", st.Mode(), err)
	}
	secretPath := meshControlSecretPath(cfg)
	secretData, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(secretData)) != "issued-mesh-secret" {
		t.Fatalf("secret file = %q", secretData)
	}
	if st, err := os.Stat(secretPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode = %v, err %v", st.Mode(), err)
	}
	installed, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installed), "NODE_ID") || strings.Contains(string(installed), "bootstrap-placeholder") {
		t.Fatalf("config was not replaced with the issued config: %s", installed)
	}
	// The issued config must load: the node restarts on it.
	if _, err := config.LoadClientConfigWithOverrides(configPath, overrides); err != nil {
		t.Fatalf("installed config does not load: %v", err)
	}
}

func TestWriteEnrolledFilesRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	configPath, resolversPath, _ := writeEnrollTestBootstrapConfig(t, dir)
	overrides := config.ClientConfigOverrides{ResolversFilePath: &resolversPath}
	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadClientConfigWithOverrides(configPath, overrides)
	if err != nil {
		t.Fatal(err)
	}
	resp := enroll.EnrollmentResponse{NodeID: "node-1", NodeKey: "k", NodeConfig: "this is not toml [[["}
	if err := writeEnrolledFiles(cfg, overrides, resp); err == nil {
		t.Fatal("an issued config that does not validate must be refused")
	}
	// The bootstrap config is untouched: the commit point held.
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("failed install must leave the bootstrap config untouched")
	}
}

func TestMeshControlSecretPath(t *testing.T) {
	cfg := config.ClientConfig{NodeKeyFile: "/etc/nexounel/node.key", MeshControlSecretFile: "/etc/nexounel/custom.key"}
	if got := meshControlSecretPath(cfg); got != "/etc/nexounel/custom.key" {
		t.Fatalf("explicit: %q", got)
	}
	cfg.MeshControlSecretFile = ""
	if got := meshControlSecretPath(cfg); got != "/etc/nexounel/mesh-control-secret.key" {
		t.Fatalf("default sibling: %q", got)
	}
}

func TestEnrollClientOverrides(t *testing.T) {
	resolversPath := "/tmp/resolvers.txt"
	base := config.ClientConfigOverrides{
		ResolversFilePath: &resolversPath,
		Values:            map[string]any{"CapacityMargin": 0.9},
	}
	out := enrollClientOverrides(base, "deadbeef")
	if out.Values["EncryptionKey"] != "deadbeef" || out.Values["NodeKeyFile"] != "" {
		t.Fatalf("overrides = %+v", out.Values)
	}
	if out.Values["CapacityMargin"] != 0.9 || out.ResolversFilePath != base.ResolversFilePath {
		t.Fatal("base overrides must be preserved")
	}
	if base.Values["EncryptionKey"] != nil {
		t.Fatal("base overrides must not be mutated")
	}
}
