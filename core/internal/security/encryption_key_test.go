// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package security

import (
	"os"
	"strings"
	"testing"

	"github.com/Altonomega/Nexounel/core/internal/config"
)

func TestKeyFingerprintIsStableShortAndNonReversible(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"

	fp := KeyFingerprint(key)
	if len(fp) != 8 {
		t.Fatalf("fingerprint should be 8 hex chars, got %q (len %d)", fp, len(fp))
	}
	// Deterministic for the same key.
	if fp != KeyFingerprint(key) {
		t.Fatal("fingerprint must be stable for the same key")
	}
	// The raw key must never appear inside the fingerprint (no accidental leak).
	if strings.Contains(fp, key) || strings.Contains(key, fp) {
		t.Fatalf("fingerprint %q must not expose the raw key", fp)
	}
	// Different key -> different fingerprint (collisions here would be a red flag).
	if KeyFingerprint("fedcba9876543210fedcba9876543210") == fp {
		t.Fatal("distinct keys should not share a fingerprint")
	}
	// Empty key -> empty fingerprint.
	if KeyFingerprint("") != "" {
		t.Fatal("empty key should yield empty fingerprint")
	}
}

func TestEncryptionMethodNameRejectsLegacy(t *testing.T) {
	if got := EncryptionMethodName(3); got != "AES-128-GCM" {
		t.Fatalf("method 3 name = %q, want AES-128-GCM", got)
	}
	if got := EncryptionMethodName(4); got != "AES-192-GCM" {
		t.Fatalf("method 4 name = %q, want AES-192-GCM", got)
	}
	if got := EncryptionMethodName(5); got != "AES-256-GCM" {
		t.Fatalf("method 5 name = %q, want AES-256-GCM", got)
	}
	// Legacy methods and unknown ids are INVALID, never normalized.
	for _, method := range []int{-1, 0, 1, 2, 6, 99} {
		if got := EncryptionMethodName(method); got != "INVALID" {
			t.Fatalf("method %d name = %q, want INVALID", method, got)
		}
	}
}

func TestEnsureServerEncryptionKeyRejectsLegacyMethod(t *testing.T) {
	dir := t.TempDir()
	cfg := config.ServerConfig{ConfigDir: dir, DataEncryptionMethod: 1}
	if _, err := EnsureServerEncryptionKey(cfg); err == nil {
		t.Fatal("legacy method 1 must be rejected, not normalized")
	}
	if _, err := os.Stat(cfg.EncryptionKeyPath()); !os.IsNotExist(err) {
		t.Fatal("rejected method must not generate a key file")
	}
}

func TestEnsureServerEncryptionKeyGeneratesAndLoadsAES256Key(t *testing.T) {
	dir := t.TempDir()
	cfg := config.ServerConfig{ConfigDir: dir, DataEncryptionMethod: 5}
	info, err := EnsureServerEncryptionKey(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Generated || info.Key == "" {
		t.Fatalf("expected a generated key, got %+v", info)
	}
	if len(info.Key) != 32 {
		t.Fatalf("AES-256-GCM key length = %d, want 32", len(info.Key))
	}
	st, err := os.Stat(cfg.EncryptionKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %o, want 600", st.Mode().Perm())
	}
	loaded, err := EnsureServerEncryptionKey(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Loaded || loaded.Key != info.Key {
		t.Fatalf("second load must return the stored key, got %+v", loaded)
	}
}
