// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
)

type EncryptionKeyInfo struct {
	MethodID   int
	MethodName string
	Key        string
	Path       string
	Loaded     bool
	Generated  bool
}

func EnsureServerEncryptionKey(cfg config.ServerConfig) (EncryptionKeyInfo, error) {
	if cfg.DataEncryptionMethod < 3 || cfg.DataEncryptionMethod > 5 {
		return EncryptionKeyInfo{}, fmt.Errorf("unsupported DATA_ENCRYPTION_METHOD: %d (only AES-GCM methods 3, 4, 5 are supported)", cfg.DataEncryptionMethod)
	}
	info := EncryptionKeyInfo{
		MethodID:   cfg.DataEncryptionMethod,
		MethodName: EncryptionMethodName(cfg.DataEncryptionMethod),
		Path:       cfg.EncryptionKeyPath(),
	}

	requiredLength := requiredKeyLength(cfg.DataEncryptionMethod)
	raw, err := os.ReadFile(info.Path)
	if err == nil {
		key := strings.TrimSpace(string(raw))
		if len(key) == requiredLength {
			info.Key = key
			info.Loaded = true
			return info, nil
		}
	}

	key, err := generateHexText(requiredLength)
	if err != nil {
		return info, fmt.Errorf("generate encryption key: %w", err)
	}
	if err := os.WriteFile(info.Path, []byte(key), 0o600); err != nil {
		return info, fmt.Errorf("write encryption key file %s: %w", info.Path, err)
	}

	info.Key = key
	info.Generated = true
	return info, nil
}

// KeyFingerprint returns a short, non-reversible identifier for an encryption
// key so operators can confirm which key is loaded across client and server
// without the key itself ever appearing in logs. It is the first 8 hex chars of
// the SHA-256 of the key. An empty key yields an empty fingerprint.
func KeyFingerprint(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:8]
}

// EncryptionMethodName names an AES-GCM method. Legacy methods 0 (none),
// 1 (XOR) and 2 (ChaCha20) and any unknown id are INVALID: they are never
// normalized to a supported method.
func EncryptionMethodName(methodID int) string {
	switch methodID {
	case 3:
		return "AES-128-GCM"
	case 4:
		return "AES-192-GCM"
	case 5:
		return "AES-256-GCM"
	default:
		return "INVALID"
	}
}

// requiredKeyLength returns the key length for an AES-GCM method. Callers
// must validate the method first; the default (32) applies to AES-256-GCM.
func requiredKeyLength(methodID int) int {
	switch methodID {
	case 3:
		return 16
	case 4:
		return 24
	default:
		return 32
	}
}

func generateHexText(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}
	buf := make([]byte, (length+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf)[:length], nil
}
