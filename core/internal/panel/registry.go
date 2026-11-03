package panel

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
	"github.com/MNSH-Nexo/Nexounel/core/internal/security"
)

// nodeIDPattern mirrors multisession.nodeIDPattern, which is unexported:
// ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ — the same rule the server enforces.
var nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// RegistryEntry is one parsed registry entry, preserving both key forms.
type RegistryEntry struct {
	ID      string
	Key     string // inline key, if set
	KeyFile string // key file path, if set
}

// registryDoc is the parsed registry file: a generic TOML document whose
// "nodes" value is a list of per-node maps. Keeping nodes as maps (rather
// than decoding through multisession.LoadRegistry, which drops key_file)
// preserves key_file entries and unknown per-node fields on round-trip.
// Unknown top-level fields are preserved as other document keys, as far
// as TOML encoding allows (key order is not preserved).
type registryDoc struct {
	fields map[string]any
	nodes  []map[string]any
}

func parseRegistryDoc(data []byte) (registryDoc, error) {
	doc := registryDoc{fields: map[string]any{}}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return doc, nil
	}
	if err := toml.Unmarshal(data, &doc.fields); err != nil {
		return doc, fmt.Errorf("parse node registry: %w", err)
	}
	rawNodes, ok := doc.fields["nodes"]
	if !ok || rawNodes == nil {
		return doc, nil
	}
	list, ok := rawNodes.([]map[string]any)
	if !ok {
		return doc, fmt.Errorf("node registry: \"nodes\" must be a list of tables")
	}
	doc.nodes = list
	return doc, nil
}

func readRegistryDoc(path string) (registryDoc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return registryDoc{fields: map[string]any{}}, nil
		}
		return registryDoc{}, fmt.Errorf("read node registry %s: %w", path, err)
	}
	return parseRegistryDoc(data)
}

func registryEntryFromMap(m map[string]any) (RegistryEntry, error) {
	entry := RegistryEntry{}
	id, ok := m["id"].(string)
	if !ok {
		return entry, fmt.Errorf("node registry entry without a string id")
	}
	entry.ID = strings.TrimSpace(id)
	if key, ok := m["key"]; ok {
		keyStr, ok := key.(string)
		if !ok {
			return entry, fmt.Errorf("node %q: key must be a string", entry.ID)
		}
		entry.Key = strings.TrimSpace(keyStr)
	}
	if keyFile, ok := m["key_file"]; ok {
		keyFileStr, ok := keyFile.(string)
		if !ok {
			return entry, fmt.Errorf("node %q: key_file must be a string", entry.ID)
		}
		entry.KeyFile = strings.TrimSpace(keyFileStr)
	}
	return entry, nil
}

// ReadRegistryEntries parses the registry file preserving both key forms.
// A missing file yields no entries and no error.
func ReadRegistryEntries(path string) ([]RegistryEntry, error) {
	doc, err := readRegistryDoc(path)
	if err != nil {
		return nil, err
	}
	entries := make([]RegistryEntry, 0, len(doc.nodes))
	for _, m := range doc.nodes {
		entry, err := registryEntryFromMap(m)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// RegistryNodeKey reads one node's inline key from the registry
// file. It exists for idempotent enrollment: a node whose first
// enrollment wrote the registry but lost the response retries with
// the same token and must receive the SAME key, not a second one.
// It returns exists=false when the node is absent, keyFile=true
// when the node is registered via a key file (the panel cannot
// re-issue a key it does not hold), and an error for an unreadable
// registry.
func RegistryNodeKey(path, id string) (key string, exists bool, keyFile bool, err error) {
	entries, err := ReadRegistryEntries(path)
	if err != nil {
		return "", false, false, err
	}
	for _, e := range entries {
		if e.ID == strings.TrimSpace(id) {
			if e.Key != "" {
				return e.Key, true, false, nil
			}
			return "", true, e.KeyFile != "", nil
		}
	}
	return "", false, false, nil
}

func validateNodeID(id string) error {
	if !nodeIDPattern.MatchString(strings.TrimSpace(id)) {
		return fmt.Errorf("invalid node id %q: must match [A-Za-z0-9][A-Za-z0-9_-]{0,63}", id)
	}
	return nil
}

func validateNodeKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("node key must not be empty")
	}
	raw, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("node key must be hex: %w", err)
	}
	// Key string lengths for AES-GCM methods 3/4/5 are 16/24/32 chars.
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return fmt.Errorf("node key must be 16, 24 or 32 hex characters, got %d", len(key))
	}
	_ = raw
	return nil
}

// writeRegistryDoc writes the document atomically (0600), validating the
// result with multisession.LoadRegistry before the rename so a bad write
// never replaces a working registry. Keys are never logged; only the
// caller-visible error text mentions ids.
func writeRegistryDoc(path string, doc registryDoc) error {
	fields := make(map[string]any, len(doc.fields)+1)
	for k, v := range doc.fields {
		fields[k] = v
	}
	nodes := make([]map[string]any, 0, len(doc.nodes))
	for _, m := range doc.nodes {
		copied := make(map[string]any, len(m))
		for k, v := range m {
			copied[k] = v
		}
		// Drop empty key/key_file spellings: the server treats them as
		// unset, and emitting them would imply a key is present.
		if s, ok := copied["key"].(string); ok && strings.TrimSpace(s) == "" {
			delete(copied, "key")
		}
		if s, ok := copied["key_file"].(string); ok && strings.TrimSpace(s) == "" {
			delete(copied, "key_file")
		}
		nodes = append(nodes, copied)
	}
	fields["nodes"] = nodes

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create registry directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".nodes-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary registry: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temporary registry mode: %w", err)
	}
	if err := toml.NewEncoder(tmp).Encode(fields); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode node registry: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary registry: %w", err)
	}
	// Validate before installing: the server must be able to load it.
	if _, err := multisession.LoadRegistry(tmpName); err != nil {
		return fmt.Errorf("registry validation failed: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install node registry %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set node registry mode: %w", err)
	}
	return nil
}

// AddNodeToRegistry appends a node with an inline key. Duplicate ids and
// invalid ids or keys are refused.
func AddNodeToRegistry(path, id, key string) error {
	if err := validateNodeID(id); err != nil {
		return err
	}
	if err := validateNodeKey(key); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	doc, err := readRegistryDoc(path)
	if err != nil {
		return err
	}
	for _, m := range doc.nodes {
		entry, err := registryEntryFromMap(m)
		if err != nil {
			return err
		}
		if entry.ID == id {
			return fmt.Errorf("node id %q already exists in the registry", id)
		}
	}
	doc.nodes = append(doc.nodes, map[string]any{"id": id, "key": strings.TrimSpace(key)})
	return writeRegistryDoc(path, doc)
}

// RemoveNodeFromRegistry deletes a registry entry. Removing the last
// node is refused: the server requires a non-empty registry.
func RemoveNodeFromRegistry(path, id string) error {
	if err := validateNodeID(id); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	doc, err := readRegistryDoc(path)
	if err != nil {
		return err
	}
	if len(doc.nodes) == 0 {
		return fmt.Errorf("node %q not found in the registry", id)
	}
	if len(doc.nodes) == 1 {
		only, err := registryEntryFromMap(doc.nodes[0])
		if err != nil {
			return err
		}
		if only.ID == id {
			return fmt.Errorf("refusing to remove the last node %q: the registry must list at least one node", id)
		}
		return fmt.Errorf("node %q not found in the registry", id)
	}
	kept := make([]map[string]any, 0, len(doc.nodes)-1)
	found := false
	for _, m := range doc.nodes {
		entry, err := registryEntryFromMap(m)
		if err != nil {
			return err
		}
		if entry.ID == id {
			found = true
			continue
		}
		kept = append(kept, m)
	}
	if !found {
		return fmt.Errorf("node %q not found in the registry", id)
	}
	doc.nodes = kept
	return writeRegistryDoc(path, doc)
}

// RotateNodeKey re-issues one node's key. Entries with a key_file keep
// that form: the new key is written to the key file (atomically, 0600)
// and the registry entry is left untouched. Inline-key entries get the
// new key written into the registry. Either way the result is validated
// with multisession.LoadRegistry before it takes effect.
func RotateNodeKey(path, id, newKey string) error {
	if err := validateNodeID(id); err != nil {
		return err
	}
	if err := validateNodeKey(newKey); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	newKey = strings.TrimSpace(newKey)
	doc, err := readRegistryDoc(path)
	if err != nil {
		return err
	}
	found := false
	for _, m := range doc.nodes {
		entry, err := registryEntryFromMap(m)
		if err != nil {
			return err
		}
		if entry.ID != id {
			continue
		}
		found = true
		if entry.KeyFile != "" {
			if err := writeKeyFileAtomic(entry.KeyFile, newKey); err != nil {
				return fmt.Errorf("node %q: write key file: %w", id, err)
			}
		} else {
			m["key"] = newKey
		}
	}
	if !found {
		return fmt.Errorf("node %q not found in the registry", id)
	}
	// For key_file entries the registry file itself is unchanged, but
	// re-validating confirms the file content still loads.
	if err := writeRegistryDoc(path, doc); err != nil {
		return err
	}
	return nil
}

func writeKeyFileAtomic(path, key string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".node-key-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(key + "\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// RegistryFingerprint returns the fingerprint of a node's resolved key
// for logging, or "" when the node cannot be resolved.
func RegistryFingerprint(path, id string) string {
	entries, err := ReadRegistryEntries(path)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.ID != id {
			continue
		}
		if entry.Key != "" {
			return security.KeyFingerprint(entry.Key)
		}
		if entry.KeyFile != "" {
			data, err := os.ReadFile(entry.KeyFile)
			if err != nil {
				return ""
			}
			return security.KeyFingerprint(strings.TrimSpace(string(data)))
		}
	}
	return ""
}
