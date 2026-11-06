package panel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Altonomega/Nexounel/core/internal/multisession"
	"github.com/Altonomega/Nexounel/core/internal/security"
)

func validTestKey(seed byte) string {
	// 32 hex chars.
	const hexdigits = "0123456789abcdef"
	b := make([]byte, 32)
	for i := range b {
		b[i] = hexdigits[(int(seed)+i)%16]
	}
	return string(b)
}

func TestRegistryRoundTripPreservesKeyFileAndUnknownFields(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "node-b.key")
	if err := os.WriteFile(keyFile, []byte(validTestKey(3)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	regPath := filepath.Join(dir, "nodes.toml")
	original := "title = \"example\"\n\n[[nodes]]\nid = \"node-a\"\nkey = \"" + validTestKey(1) + "\"\ncustom = \"keep-me\"\n\n[[nodes]]\nid = \"node-b\"\nkey_file = \"" + keyFile + "\"\n"
	if err := os.WriteFile(regPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	// Add a third node; the existing entries must survive verbatim in
	// meaning (key_file preserved, unknown fields preserved).
	if err := AddNodeToRegistry(regPath, "node-c", validTestKey(5)); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadRegistryEntries(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %+v", entries)
	}
	if entries[1].KeyFile != keyFile || entries[1].Key != "" {
		t.Fatalf("key_file entry not preserved: %+v", entries[1])
	}
	if entries[0].Key != validTestKey(1) {
		t.Fatalf("inline key changed: %+v", entries[0])
	}
	after, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "custom = \"keep-me\"") || !strings.Contains(string(after), "title = \"example\"") {
		t.Fatalf("unknown fields lost:\n%s", after)
	}
	// The result must load through the server's own loader.
	reg, err := multisession.LoadRegistry(regPath)
	if err != nil {
		t.Fatalf("written registry failed server loader: %v", err)
	}
	if len(reg.Nodes) != 3 {
		t.Fatalf("loader saw %d nodes", len(reg.Nodes))
	}
	info, err := os.Stat(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("registry mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestRegistryAddRefusals(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	if err := AddNodeToRegistry(regPath, "node-1", validTestKey(1)); err != nil {
		t.Fatal(err)
	}
	if err := AddNodeToRegistry(regPath, "node-1", validTestKey(2)); err == nil {
		t.Fatal("duplicate id accepted")
	}
	if err := AddNodeToRegistry(regPath, "-bad", validTestKey(2)); err == nil {
		t.Fatal("invalid id accepted")
	}
	if err := AddNodeToRegistry(regPath, "node-2", ""); err == nil {
		t.Fatal("empty key accepted")
	}
	if err := AddNodeToRegistry(regPath, "node-2", "not-hex-zzzz"); err == nil {
		t.Fatal("non-hex key accepted")
	}
	if err := AddNodeToRegistry(regPath, "node-2", "abcd"); err == nil {
		t.Fatal("short key accepted")
	}
	entries, err := ReadRegistryEntries(regPath)
	if err != nil || len(entries) != 1 {
		t.Fatalf("refused adds changed the registry: %+v err=%v", entries, err)
	}
}

func TestRegistryRemoveAndRotate(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "nodes.toml")
	if err := AddNodeToRegistry(regPath, "node-1", validTestKey(1)); err != nil {
		t.Fatal(err)
	}
	// Removing the last node is refused.
	if err := RemoveNodeFromRegistry(regPath, "node-1"); err == nil {
		t.Fatal("removing last node allowed")
	}
	if err := AddNodeToRegistry(regPath, "node-2", validTestKey(2)); err != nil {
		t.Fatal(err)
	}
	// Rotate the inline key.
	newKey := validTestKey(9)
	if err := RotateNodeKey(regPath, "node-1", newKey); err != nil {
		t.Fatal(err)
	}
	reg, err := multisession.LoadRegistry(regPath)
	if err != nil {
		t.Fatal(err)
	}
	node, ok := reg.Lookup("node-1")
	if !ok || node.Key != newKey {
		t.Fatalf("rotation did not take effect: %+v", node)
	}
	if got := RegistryFingerprint(regPath, "node-1"); got != security.KeyFingerprint(newKey) {
		t.Fatalf("fingerprint mismatch: %q", got)
	}
	// Rotate an unknown node: refused.
	if err := RotateNodeKey(regPath, "node-x", validTestKey(4)); err == nil {
		t.Fatal("rotating unknown node allowed")
	}
	// Remove one of two: allowed.
	if err := RemoveNodeFromRegistry(regPath, "node-2"); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadRegistryEntries(regPath)
	if err != nil || len(entries) != 1 || entries[0].ID != "node-1" {
		t.Fatalf("remove wrong: %+v err=%v", entries, err)
	}
	if err := RemoveNodeFromRegistry(regPath, "node-x"); err == nil {
		t.Fatal("removing unknown node allowed")
	}
}

func TestRegistryRotateKeyFileEntry(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "node-1.key")
	oldKey := validTestKey(1)
	if err := os.WriteFile(keyFile, []byte(oldKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	regPath := filepath.Join(dir, "nodes.toml")
	content := "[[nodes]]\nid = \"node-1\"\nkey_file = \"" + keyFile + "\"\n\n[[nodes]]\nid = \"node-2\"\nkey = \"" + validTestKey(2) + "\"\n"
	if err := os.WriteFile(regPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	newKey := validTestKey(7)
	if err := RotateNodeKey(regPath, "node-1", newKey); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != newKey {
		t.Fatalf("key file not rotated: %q", data)
	}
	entries, err := ReadRegistryEntries(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].KeyFile != keyFile || entries[0].Key != "" {
		t.Fatalf("key_file form changed by rotation: %+v", entries[0])
	}
	reg, err := multisession.LoadRegistry(regPath)
	if err != nil {
		t.Fatal(err)
	}
	node, _ := reg.Lookup("node-1")
	if node.Key != newKey {
		t.Fatalf("loader sees stale key: %q", node.Key)
	}
}
