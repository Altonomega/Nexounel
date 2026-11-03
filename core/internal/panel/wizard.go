package panel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
)

// WizardInput is the validated input shared by both wizard paths.
type WizardInput struct {
	Domain       string
	Subdomain    string // tunnel subdomain label, default "v"
	MotherIP     string
	NodeID       string
	ListenPort   int
	ForwardRange string
}

var domainLabelPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// NormalizeWizardInput validates and normalizes raw wizard form values.
// Domain and subdomain are lowercased; empty subdomain defaults to "v";
// empty listen port defaults to 18000.
func NormalizeWizardInput(domain, subdomain, motherIP, nodeID string, listenPort int, forwardRange string) (WizardInput, error) {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	if domain == "" || len(domain) > 253 {
		return WizardInput{}, fmt.Errorf("domain is required")
	}
	for _, label := range strings.Split(domain, ".") {
		if !domainLabelPattern.MatchString(label) {
			return WizardInput{}, fmt.Errorf("invalid domain %q: each label must start and end with a letter or digit", domain)
		}
	}
	if !strings.Contains(domain, ".") {
		return WizardInput{}, fmt.Errorf("invalid domain %q: a domain must contain at least one dot", domain)
	}
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	if subdomain == "" {
		subdomain = "v"
	}
	if !domainLabelPattern.MatchString(subdomain) || strings.Contains(subdomain, ".") {
		return WizardInput{}, fmt.Errorf("invalid subdomain %q: must be a single DNS label", subdomain)
	}
	ip := net.ParseIP(strings.TrimSpace(motherIP))
	if ip == nil || ip.To4() == nil {
		return WizardInput{}, fmt.Errorf("invalid mother IP %q: must be an IPv4 address", motherIP)
	}
	if listenPort == 0 {
		listenPort = 18000
	}
	if listenPort < 1 || listenPort > 65535 {
		return WizardInput{}, fmt.Errorf("invalid listen port %d", listenPort)
	}
	forwardRange = strings.TrimSpace(forwardRange)
	if forwardRange == "" {
		return WizardInput{}, fmt.Errorf("forward range is required (for example 20000-20010)")
	}
	if _, _, err := config.ParsePortRange(forwardRange); err != nil {
		return WizardInput{}, fmt.Errorf("invalid forward range %q: %w", forwardRange, err)
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID != "" {
		if err := multisession.ValidateNodeID(nodeID); err != nil {
			return WizardInput{}, err
		}
	}
	return WizardInput{
		Domain: domain, Subdomain: subdomain, MotherIP: ip.String(),
		NodeID: nodeID, ListenPort: listenPort, ForwardRange: forwardRange,
	}, nil
}

// TunnelName returns the tunnel subdomain FQDN, e.g. v.example.invalid.
func (w WizardInput) TunnelName() string { return w.Subdomain + "." + w.Domain }

// NSHost returns ns1.<domain>.
func (w WizardInput) NSHost() string { return "ns1." + w.Domain }

// BuildDNSRecords renders the exact records the wizard creates or asks
// the admin to create: an A record for ns1 (DNS-only) and an NS record
// delegating the tunnel subdomain to it.
func BuildDNSRecords(input WizardInput) []DNSRecord {
	return []DNSRecord{
		{Type: "A", Name: input.NSHost(), Content: input.MotherIP, TTL: 300, Proxied: false},
		{Type: "NS", Name: input.TunnelName(), Content: input.NSHost(), TTL: 300, Proxied: false},
	}
}

// GenerateNodeKey returns a fresh 32-hex-character node key (16 random bytes).
func GenerateNodeKey() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate node key: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// GenerateNodeID returns a fresh node id of the form node-<8 hex chars>.
func GenerateNodeID() (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate node id: %w", err)
	}
	return "node-" + hex.EncodeToString(buf), nil
}

// PendingNode is a wizard issuance awaiting admin confirmation. It lives
// only in panel memory; the key is shown once and the registry is written
// only after the confirm step.
type PendingNode struct {
	ID             string
	Key            string
	ConnectAddress string
	Domain         string
	Subdomain      string
	MotherIP       string
	ListenPort     int
	ForwardRange   string
	CreatedAt      time.Time
}

// NewPendingNode builds a pending issuance from validated wizard input,
// generating an id and key when the admin did not supply an id.
func NewPendingNode(input WizardInput) (PendingNode, error) {
	nodeID := input.NodeID
	if nodeID == "" {
		generated, err := GenerateNodeID()
		if err != nil {
			return PendingNode{}, err
		}
		nodeID = generated
	}
	key, err := GenerateNodeKey()
	if err != nil {
		return PendingNode{}, err
	}
	return PendingNode{
		ID: nodeID, Key: key, ConnectAddress: input.TunnelName(),
		Domain: input.Domain, Subdomain: input.Subdomain, MotherIP: input.MotherIP,
		ListenPort: input.ListenPort, ForwardRange: input.ForwardRange,
		CreatedAt: time.Now(),
	}, nil
}

// DefaultQueryTypes are the record types a provisioned node rotates over.
var DefaultQueryTypes = []string{"TXT", "NULL", "HTTPS", "SVCB", "A", "AAAA"}

// DefaultResolversContent is the fallback resolver list written when the
// local resolvers file is absent. It lists public resolvers only.
func DefaultResolversContent() string {
	return strings.Join([]string{
		"8.8.8.8",
		"8.8.4.4",
		"1.1.1.1",
		"1.0.0.1",
		"9.9.9.9",
		"149.112.112.112",
		"208.67.222.222",
		"208.67.220.220",
		"", // trailing newline
	}, "\n")
}

// BuildNodeConfig renders a nexounel-node.toml for a provisioned node.
// keyFilePath and resolversFilePath are absolute paths on the node.
func BuildNodeConfig(pending PendingNode, keyFilePath, resolversFilePath string) string {
	return BuildNodeConfigWithMeshSecret(pending, keyFilePath, resolversFilePath, "")
}

// BuildNodeConfigWithMeshSecret renders the same config, plus a
// MESH_CONTROL_SECRET_FILE line when meshSecretPath is non-empty
// (the enrollment issuance path, §8.3). With an empty path the
// output is byte-identical to BuildNodeConfig: provisioned nodes,
// which receive no mesh secret over SSH, keep exactly the config
// they have always had.
func BuildNodeConfigWithMeshSecret(pending PendingNode, keyFilePath, resolversFilePath, meshSecretPath string) string {
	var b strings.Builder
	b.WriteString("# Nexounel node configuration generated by the panel.\n")
	fmt.Fprintf(&b, "DOMAINS = [%s]\n", strconv.Quote(pending.ConnectAddress))
	b.WriteString("PROTOCOL_TYPE = \"TCP\"\n")
	b.WriteString("LISTEN_IP = \"0.0.0.0\"\n")
	fmt.Fprintf(&b, "LISTEN_PORT = %d\n", pending.ListenPort)
	fmt.Fprintf(&b, "FORWARD_RANGE = %s\n", strconv.Quote(pending.ForwardRange))
	fmt.Fprintf(&b, "NODE_ID = %s\n", strconv.Quote(pending.ID))
	fmt.Fprintf(&b, "NODE_KEY_FILE = %s\n", strconv.Quote(keyFilePath))
	if strings.TrimSpace(meshSecretPath) != "" {
		fmt.Fprintf(&b, "MESH_CONTROL_SECRET_FILE = %s\n", strconv.Quote(strings.TrimSpace(meshSecretPath)))
	}
	b.WriteString("DATA_ENCRYPTION_METHOD = 5\n")
	b.WriteString("MULTISESSION_ENABLED = true\n")
	b.WriteString("CAPACITY_MARGIN = 0.95\n")
	fmt.Fprintf(&b, "RESOLVERS_FILE = %s\n", strconv.Quote(resolversFilePath))
	b.WriteString("QUERY_TYPES = [")
	for i, qt := range DefaultQueryTypes {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Quote(qt))
	}
	b.WriteString("]\n")
	b.WriteString("LOG_LEVEL = \"INFO\"\n")
	return b.String()
}
