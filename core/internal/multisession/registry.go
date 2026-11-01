// Node registry: the file-based Phase 1 seam for per-node identity.
//
// The mother server validates each node by the key that decrypts its
// SESSION_INIT: one codec per registry entry, all sharing the
// configured AES-GCM method. A node is therefore identified by
// possession of its own key, and the registry maps that key to a node
// ID for logging and session attribution. One shared key for all nodes
// is forbidden by design: the registry must list every node explicitly,
// and a key that matches no entry is rejected at ingress (AEAD
// authentication failure) before any session state is created.
//
// Registry file format (TOML):
//
//	[[nodes]]
//	id = "iran-1"
//	key = "0123456789abcdef..."          # inline key, or:
//	key_file = "/etc/nexounel/nodes/iran-1.key"  # file wins if both set
//
// Key files contain the bare key string (whitespace-trimmed). The
// registry file itself must be readable only by the operator; keys are
// never logged (only fingerprints, via security.KeyFingerprint).
package multisession

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/MNSH-Nexo/Nexounel/core/internal/security"
)

// Node is one registry entry: an ID bound to exactly one key.
type Node struct {
	ID  string
	Key string
}

// Registry is the loaded node registry.
type Registry struct {
	Nodes []Node
	byID  map[string]Node
}

// registryFile is the on-disk TOML shape.
type registryFile struct {
	Nodes []registryNode `toml:"nodes"`
}

type registryNode struct {
	ID      string `toml:"id"`
	Key     string `toml:"key"`
	KeyFile string `toml:"key_file"`
}

var nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// LoadRegistry reads and validates the node registry at path. An empty
// path is an error: registry mode must be explicit, never a silent
// fallback to a shared key.
func LoadRegistry(path string) (*Registry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("node registry path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read node registry %s: %w", path, err)
	}
	var file registryFile
	if err := toml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse node registry %s: %w", path, err)
	}
	if len(file.Nodes) == 0 {
		return nil, fmt.Errorf("node registry %s lists no nodes", path)
	}
	reg := &Registry{byID: make(map[string]Node, len(file.Nodes))}
	for i, n := range file.Nodes {
		node, err := resolveRegistryNode(n)
		if err != nil {
			return nil, fmt.Errorf("node registry %s entry %d: %w", path, i, err)
		}
		if _, dup := reg.byID[node.ID]; dup {
			return nil, fmt.Errorf("node registry %s: duplicate node id %q", path, node.ID)
		}
		reg.Nodes = append(reg.Nodes, node)
		reg.byID[node.ID] = node
	}
	return reg, nil
}

func resolveRegistryNode(n registryNode) (Node, error) {
	id := strings.TrimSpace(n.ID)
	if !nodeIDPattern.MatchString(id) {
		return Node{}, fmt.Errorf("invalid node id %q: must match [A-Za-z0-9][A-Za-z0-9_-]{0,63}", n.ID)
	}
	key := strings.TrimSpace(n.Key)
	if strings.TrimSpace(n.KeyFile) != "" {
		data, err := os.ReadFile(strings.TrimSpace(n.KeyFile))
		if err != nil {
			return Node{}, fmt.Errorf("node %q: read key file: %w", id, err)
		}
		key = strings.TrimSpace(string(data))
	}
	if key == "" {
		return Node{}, fmt.Errorf("node %q: no key (set key or key_file)", id)
	}
	return Node{ID: id, Key: key}, nil
}

// Lookup returns the node with the given ID, if registered.
func (r *Registry) Lookup(id string) (Node, bool) {
	if r == nil {
		return Node{}, false
	}
	n, ok := r.byID[id]
	return n, ok
}

// Codecs builds one codec per registered node, all for the given
// AES-GCM method, in registry order. The caller pairs the returned
// slice with Registry.Nodes by index to attribute a decrypting codec
// to its node.
func (r *Registry) Codecs(method int) ([]*security.Codec, error) {
	if r == nil || len(r.Nodes) == 0 {
		return nil, errors.New("node registry is empty")
	}
	codecs := make([]*security.Codec, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		codec, err := security.NewCodec(method, n.Key)
		if err != nil {
			return nil, fmt.Errorf("node %q: %w", n.ID, err)
		}
		codecs = append(codecs, codec)
	}
	return codecs, nil
}

// ValidateNodeID checks a client-supplied node ID against the registry
// ID rules (same charset/length as registry entries).
func ValidateNodeID(id string) error {
	if !nodeIDPattern.MatchString(strings.TrimSpace(id)) {
		return fmt.Errorf("invalid NODE_ID %q: must match [A-Za-z0-9][A-Za-z0-9_-]{0,63}", id)
	}
	return nil
}
