// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package security

import (
	"bytes"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	methods := []int{3, 4, 5}
	plaintext := []byte("nexounel-roundtrip-test")
	rawKey := "0123456789abcdef0123456789abcdef"

	for _, method := range methods {
		codec, err := NewCodec(method, rawKey)
		if err != nil {
			t.Fatalf("NewCodec(%d) returned error: %v", method, err)
		}

		ciphertext, err := codec.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed for method %d: %v", method, err)
		}

		decrypted, err := codec.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt failed for method %d: %v", method, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("round-trip mismatch for method %d", method)
		}
	}
}

func TestCodecRejectsLegacyAndUnknownMethods(t *testing.T) {
	// Methods 0 (none), 1 (XOR) and 2 (ChaCha20) are removed: they provide
	// no authentication and must never construct. Unknown ids fail the
	// same way; nothing is silently normalized to a supported method.
	for _, method := range []int{-1, 0, 1, 2, 6, 99} {
		if _, err := NewCodec(method, "0123456789abcdef0123456789abcdef"); err == nil {
			t.Fatalf("NewCodec(%d) must fail, but it constructed a codec", method)
		}
	}
	if got := AllMethods; len(got) != 3 || got[0] != 3 || got[1] != 4 || got[2] != 5 {
		t.Fatalf("AllMethods = %v, want [3 4 5]", got)
	}
}

func TestCodecRejectsInvalidCiphertext(t *testing.T) {
	codec, err := NewCodec(3, "0123456789abcdef")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	if _, err := codec.Decrypt([]byte{1, 2, 3}); err == nil {
		t.Fatal("Decrypt should reject truncated AES-GCM ciphertext")
	}
}

func TestCodecAESGCMChangesDataAndRejectsTampering(t *testing.T) {
	codec, err := NewCodec(5, "key-material-for-aes-gcm-test")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	plaintext := []byte("aes-gcm-data")
	ciphertext, err := codec.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("AES-GCM encryption should change non-empty data")
	}
	ciphertext[len(ciphertext)-1] ^= 1
	if _, err := codec.Decrypt(ciphertext); err == nil {
		t.Fatal("Decrypt should reject tampered AES-GCM ciphertext")
	}
}

func TestCodecEncodeDecodeLowerBase32RoundTrip(t *testing.T) {
	codec, err := NewCodec(5, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	plaintext := []byte("header-and-payload")
	encoded, err := codec.EncryptAndEncode(plaintext)
	if err != nil {
		t.Fatalf("EncryptAndEncode returned error: %v", err)
	}

	decoded, err := codec.DecodeAndDecrypt([]byte(encoded))
	if err != nil {
		t.Fatalf("DecodeAndDecrypt returned error: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatal("encode/decode lower-base32 round-trip mismatch")
	}
}
