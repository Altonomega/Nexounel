// Package panel implements the Nexounel web panel: a small, local-only
// administration UI served under one secret path. It never touches tunnel
// behaviour; it reads server health, the node registry and logs, runs the
// setup wizard, writes the registry, and provisions nodes over SSH.
//
// Security posture: the panel config (0600) holds an argon2id password
// hash, never a plaintext password. Cloudflare credentials used by the
// wizard are transient only and are never written to disk, logs or config.
// Node keys are shown once, stored only in the registry, and never logged
// (only fingerprints, via security.KeyFingerprint).
package panel

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the panel configuration file (TOML, mode 0600).
type Config struct {
	ListenAddr   string `toml:"listen_addr"`
	WebPath      string `toml:"web_path"`
	Username     string `toml:"username"`
	PasswordHash string `toml:"password_hash"`
	SessionKey   string `toml:"session_key"`
	TLSSecure    bool   `toml:"tls_secure"`

	ServerConfig  string `toml:"server_config"`
	RegistryFile  string `toml:"registry_file"`
	MetricsAddr   string `toml:"metrics_addr"`
	LogTailLines  int    `toml:"log_tail_lines"`
	LogFile       string `toml:"log_file"`
	NodeConfig    string `toml:"node_config"`
	NodeBinary    string `toml:"node_binary"`
	ResolversFile string `toml:"resolvers_file"`

	// MeshSecretFile holds the mesh-wide control secret (§8.3):
	// one secret shared by every enrolled node, used only for
	// peer-control HMACs. The panel generates it on first use
	// (0600) when the file is absent; the enrollment API issues
	// the same value to every node. It is never a data-plane key.
	MeshSecretFile string `toml:"mesh_secret_file"`

	// EnrollmentAddr is the loopback listen address of the
	// enrollment API (§3.4): the endpoint the tunnel server's
	// enrollment handler relays bootstrap requests to (see
	// ENROLLMENT_ISSUER_URL in the server config). Empty
	// (default) = disabled: the panel serves no enrollment API
	// and bootstrap enrollment is unavailable. A non-empty
	// value must be a loopback address (127.0.0.0/8, ::1, or
	// localhost); anything else is refused, because loopback
	// binding is the API's only authentication boundary.
	EnrollmentAddr string `toml:"enrollment_addr"`

	// KnownHosts maps "host:port" to the accepted SSH host-key fingerprint
	// (SHA256:...). Fingerprints are public identifiers, not secrets.
	KnownHosts map[string]string `toml:"known_hosts"`
}

// DefaultConfig returns the panel defaults from the Phase 2 contract.
func DefaultConfig() Config {
	return Config{
		ListenAddr:     "0.0.0.0:18081",
		ServerConfig:   "/opt/nexounel/nexounel-server.toml",
		RegistryFile:   "/opt/nexounel/nodes.toml",
		MetricsAddr:    "127.0.0.1:9090",
		LogTailLines:   100,
		NodeConfig:     "/opt/nexounel/nexounel-node.toml",
		NodeBinary:     "/opt/nexounel/nexounel-node",
		ResolversFile:  "/opt/nexounel/client_resolvers.txt",
		MeshSecretFile: "/opt/nexounel/mesh-control-secret.key",
		KnownHosts:     map[string]string{},
	}
}

func (c *Config) applyDefaults() {
	def := DefaultConfig()
	if strings.TrimSpace(c.ListenAddr) == "" {
		c.ListenAddr = def.ListenAddr
	}
	if strings.TrimSpace(c.ServerConfig) == "" {
		c.ServerConfig = def.ServerConfig
	}
	if strings.TrimSpace(c.RegistryFile) == "" {
		c.RegistryFile = def.RegistryFile
	}
	if strings.TrimSpace(c.MetricsAddr) == "" {
		c.MetricsAddr = def.MetricsAddr
	}
	if c.LogTailLines <= 0 {
		c.LogTailLines = def.LogTailLines
	}
	if strings.TrimSpace(c.NodeConfig) == "" {
		c.NodeConfig = def.NodeConfig
	}
	if strings.TrimSpace(c.NodeBinary) == "" {
		c.NodeBinary = def.NodeBinary
	}
	if strings.TrimSpace(c.ResolversFile) == "" {
		c.ResolversFile = def.ResolversFile
	}
	if strings.TrimSpace(c.MeshSecretFile) == "" {
		c.MeshSecretFile = def.MeshSecretFile
	}
	if c.KnownHosts == nil {
		c.KnownHosts = map[string]string{}
	}
}

// LoadConfig reads a panel config file, filling unset keys with defaults.
// A missing file is an error: the caller decides whether to run -init.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read panel config %s: %w", path, err)
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse panel config %s: %w", path, err)
	}
	cfg.applyDefaults()
	return cfg, nil
}

// SaveConfig writes cfg atomically (temp file + rename) with mode 0600.
func SaveConfig(path string, cfg Config) error {
	cfg.applyDefaults()
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create config directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".nexounel-panel-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary panel config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temporary panel config mode: %w", err)
	}
	if err := toml.NewEncoder(tmp).Encode(cfg); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode panel config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary panel config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install panel config %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set panel config mode: %w", err)
	}
	return nil
}

// ValidateConfig checks a config without touching the filesystem.
func ValidateConfig(cfg Config) error {
	if _, err := net.ResolveTCPAddr("tcp", cfg.ListenAddr); err != nil {
		return fmt.Errorf("invalid listen_addr %q: %w", cfg.ListenAddr, err)
	}
	if err := ValidateWebPath(cfg.WebPath); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.Username) == "" {
		return errors.New("username is empty: run nexounel-panel -init to set up admin credentials")
	}
	if strings.TrimSpace(cfg.PasswordHash) == "" {
		return errors.New("password_hash is empty: run nexounel-panel -init to set up admin credentials")
	}
	if _, err := parseArgon2idPHC(cfg.PasswordHash); err != nil {
		return fmt.Errorf("invalid password_hash: %w", err)
	}
	if len(cfg.SessionKey) != 64 {
		return fmt.Errorf("invalid session_key: must be 64 hex characters, got %d", len(cfg.SessionKey))
	}
	if _, err := hex.DecodeString(cfg.SessionKey); err != nil {
		return fmt.Errorf("invalid session_key: must be hex: %w", err)
	}
	if cfg.LogTailLines < 0 || cfg.LogTailLines > 10000 {
		return fmt.Errorf("invalid log_tail_lines %d: must be between 0 and 10000", cfg.LogTailLines)
	}
	if _, err := net.ResolveTCPAddr("tcp", cfg.MetricsAddr); err != nil {
		return fmt.Errorf("invalid metrics_addr %q: %w", cfg.MetricsAddr, err)
	}
	if err := ValidateEnrollmentAddr(cfg.EnrollmentAddr); err != nil {
		return err
	}
	for host, fp := range cfg.KnownHosts {
		if strings.TrimSpace(host) == "" || !strings.HasPrefix(fp, "SHA256:") {
			return fmt.Errorf("invalid known_hosts entry %q: fingerprint must start with SHA256:", host)
		}
	}
	return nil
}

// ValidateWebPath checks the secret path: "/" followed by URL-safe chars,
// no embedded slash, and not the bare root.
func ValidateWebPath(path string) error {
	if !strings.HasPrefix(path, "/") || path == "/" {
		return fmt.Errorf("invalid web_path %q: must start with / and not be the root", path)
	}
	rest := strings.TrimPrefix(path, "/")
	if strings.Contains(rest, "/") {
		return fmt.Errorf("invalid web_path %q: must contain no further slashes", path)
	}
	for _, r := range rest {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '~') {
			return fmt.Errorf("invalid web_path %q: characters must be URL-safe", path)
		}
	}
	return nil
}

// ValidateEnrollmentAddr checks the enrollment API listen address:
// empty means disabled (valid); a non-empty value must resolve as a
// TCP address whose host is loopback (an IP in 127.0.0.0/8 or ::1,
// or the name "localhost"). The panel refuses to bind the
// enrollment API anywhere else: loopback binding is its only
// authentication boundary.
func ValidateEnrollmentAddr(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid enrollment_addr %q: %w", addr, err)
	}
	if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
		return fmt.Errorf("invalid enrollment_addr %q: %w", addr, err)
	}
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("invalid enrollment_addr %q: must be a loopback address (127.0.0.0/8, ::1, or localhost)", addr)
}

const webPathAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// GenerateWebPath returns "/" plus 32 URL-safe random characters.
func GenerateWebPath() (string, error) {
	var b strings.Builder
	b.Grow(33)
	b.WriteByte('/')
	for i := 0; i < 32; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(webPathAlphabet))))
		if err != nil {
			return "", fmt.Errorf("generate web path: %w", err)
		}
		b.WriteByte(webPathAlphabet[n.Int64()])
	}
	return b.String(), nil
}

// GenerateSessionKey returns 64 hex characters (32 random bytes).
func GenerateSessionKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session key: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// CreateInitialConfig generates a fresh config with the given admin
// credentials and writes it 0600. It refuses to overwrite an existing
// config unless force is true.
func CreateInitialConfig(path string, force bool, username, password string) (Config, error) {
	if strings.TrimSpace(username) == "" {
		return Config{}, errors.New("username must not be empty")
	}
	if password == "" {
		return Config{}, errors.New("password must not be empty")
	}
	if _, err := os.Stat(path); err == nil && !force {
		return Config{}, fmt.Errorf("panel config %s already exists: refuse to overwrite (use -force to replace it)", path)
	} else if err != nil && !os.IsNotExist(err) {
		return Config{}, fmt.Errorf("check panel config %s: %w", path, err)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return Config{}, err
	}
	webPath, err := GenerateWebPath()
	if err != nil {
		return Config{}, err
	}
	sessionKey, err := GenerateSessionKey()
	if err != nil {
		return Config{}, err
	}
	cfg := DefaultConfig()
	cfg.WebPath = webPath
	cfg.Username = username
	cfg.PasswordHash = hash
	cfg.SessionKey = sessionKey
	if err := SaveConfig(path, cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// HasCredentials reports whether the config can authenticate an admin.
func (c Config) HasCredentials() bool {
	return strings.TrimSpace(c.Username) != "" && strings.TrimSpace(c.PasswordHash) != ""
}
