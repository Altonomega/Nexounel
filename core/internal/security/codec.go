// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	baseCodec "github.com/MNSH-Nexo/Nexounel/core/internal/basecodec"
	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
)

var (
	ErrInvalidCodecMethod = errors.New("invalid encryption method")
	ErrInvalidCiphertext  = errors.New("invalid ciphertext")
)

const aesNonceSize = 12

var cryptoBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096)
		return &b
	},
}

func getCryptoBuffer(size int) *[]byte {
	bufPtr := cryptoBufferPool.Get().(*[]byte)
	if cap(*bufPtr) < size {
		b := make([]byte, size*2)
		bufPtr = &b
	}
	return bufPtr
}

func putCryptoBuffer(bufPtr *[]byte) {
	if bufPtr != nil {
		cryptoBufferPool.Put(bufPtr)
	}
}

type Codec struct {
	aead           cipher.AEAD
	method         int
	key            []byte
	encrypt        func(dst, src []byte) ([]byte, error)
	decrypt        func(dst, src []byte) ([]byte, error)
	downstreamOnce sync.Once
	downstream     *Codec
	downstreamErr  error
}

// DownstreamEncryptedFlag uses a spare bit in the existing response-mode byte.
// Old clients keep their original response format; upgraded encrypted clients
// require encrypted replies during probing, setup, and established traffic.
const DownstreamEncryptedFlag uint8 = 0x80

func (c *Codec) CiphertextOverhead() int {
	if c == nil {
		return 0
	}
	switch c.method {
	case 3, 4, 5:
		return aesNonceSize + 16
	default:
		return 0
	}
}

func (c *Codec) downstreamCodec() (*Codec, error) {
	if c == nil {
		return nil, ErrInvalidCodecMethod
	}
	c.downstreamOnce.Do(func() {
		// Direction-specific keys prevent reflecting a valid upstream query
		// as a server reply, without adding a handshake or wire bytes.
		h := hmac.New(sha256.New, c.key)
		h.Write([]byte("CottenDNS downstream v1\x00"))
		key := h.Sum(nil)[:requiredDerivedKeyLength(c.method)]
		c.downstream, c.downstreamErr = newCodecWithKey(c.method, key)
	})
	return c.downstream, c.downstreamErr
}

func (c *Codec) EncryptDownstream(data []byte, context ...[]byte) ([]byte, error) {
	codec, err := c.downstreamCodec()
	if err != nil {
		return nil, err
	}
	if codec.aead == nil {
		return codec.Encrypt(data)
	}
	var aad []byte
	if len(context) > 0 {
		aad = context[0]
	}
	out := make([]byte, aesNonceSize, aesNonceSize+len(data)+codec.aead.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return codec.aead.Seal(out, out[:aesNonceSize], data, aad), nil
}

func (c *Codec) DecryptDownstream(data []byte, context ...[]byte) ([]byte, error) {
	codec, err := c.downstreamCodec()
	if err != nil {
		return nil, err
	}
	if codec.aead == nil {
		return codec.Decrypt(data)
	}
	if len(data) < aesNonceSize+codec.aead.Overhead() {
		return nil, ErrInvalidCiphertext
	}
	var aad []byte
	if len(context) > 0 {
		aad = context[0]
	}
	plain, err := codec.aead.Open(nil, data[:aesNonceSize], data[aesNonceSize:], aad)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plain, nil
}

func NewCodecFromConfig(cfg config.ServerConfig, rawKey string) (*Codec, error) {
	return NewCodec(cfg.DataEncryptionMethod, rawKey)
}

// AllMethods lists every supported encryption method id, in ascending
// order. Only AES-GCM methods are supported: methods 0 (none), 1 (XOR)
// and 2 (ChaCha20) were removed and are rejected by NewCodec.
var AllMethods = []int{3, 4, 5}

// IsAuthenticatedMethod reports whether the method provides authenticated
// encryption (AEAD). Every constructible method (AES-GCM 3, 4, 5)
// authenticates: a wrong key or method makes Open fail cleanly instead of
// silently yielding garbage.
func IsAuthenticatedMethod(method int) bool {
	return method >= 3 && method <= 5
}

// NewCodec builds a codec for an AES-GCM method only (3: AES-128-GCM,
// 4: AES-192-GCM, 5: AES-256-GCM). Methods 0 (none), 1 (XOR) and 2
// (ChaCha20) are rejected with ErrInvalidCodecMethod: they provide no
// authentication and must never be negotiated or silently accepted.
func NewCodec(method int, rawKey string) (*Codec, error) {
	if method < 3 || method > 5 {
		return nil, ErrInvalidCodecMethod
	}

	return newCodecWithKey(method, deriveKey(method, rawKey))
}

func newCodecWithKey(method int, derivedKey []byte) (*Codec, error) {
	codec := &Codec{
		method: method,
		key:    derivedKey,
	}

	switch method {
	case 3, 4, 5:
		aead, err := newAESGCM(derivedKey)
		if err != nil {
			return nil, err
		}
		codec.aead = aead
		codec.encrypt = codec.makeAESEncryptor(aead)
		codec.decrypt = codec.makeAESDecryptor(aead)
	default:
		return nil, ErrInvalidCodecMethod
	}

	return codec, nil
}

func (c *Codec) Encrypt(data []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidCodecMethod
	}
	return c.encrypt(nil, data)
}

func (c *Codec) Decrypt(data []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidCodecMethod
	}
	return c.decrypt(nil, data)
}

func (c *Codec) Method() int {
	if c == nil {
		return 0
	}
	return c.method
}

func (c *Codec) EncryptAndEncode(data []byte) (string, error) {
	if c == nil {
		return "", ErrInvalidCodecMethod
	}
	bufPtr := getCryptoBuffer(len(data) + 64)
	defer putCryptoBuffer(bufPtr)

	encrypted, err := c.encrypt((*bufPtr)[:0], data)
	if err != nil {
		return "", err
	}
	return baseCodec.Encode(encrypted), nil
}

func (c *Codec) EncryptAndEncodeBytes(data []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidCodecMethod
	}
	bufPtr := getCryptoBuffer(len(data) + 64)
	defer putCryptoBuffer(bufPtr)

	encrypted, err := c.encrypt((*bufPtr)[:0], data)
	if err != nil {
		return nil, err
	}
	return baseCodec.EncodeToBytes(encrypted), nil
}

func (c *Codec) DecodeAndDecrypt(data []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidCodecMethod
	}

	decoded, err := baseCodec.Decode(data)
	if err != nil {
		return nil, err
	}
	return c.decrypt(nil, decoded)
}

func (c *Codec) DecodeStringAndDecrypt(data string) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidCodecMethod
	}

	decoded, err := baseCodec.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return c.decrypt(nil, decoded)
}

func (c *Codec) makeAESEncryptor(aead cipher.AEAD) func(dst, src []byte) ([]byte, error) {
	return func(dst, src []byte) ([]byte, error) {
		if len(src) == 0 {
			if cap(dst) == 0 {
				dst = make([]byte, 0)
			} else {
				dst = dst[:0]
			}
			return dst, nil
		}

		reqSize := aesNonceSize + len(src) + aead.Overhead()
		if cap(dst) < reqSize {
			dst = make([]byte, aesNonceSize, reqSize)
		} else {
			dst = dst[:aesNonceSize]
		}

		nonce := dst[:aesNonceSize]
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generate aes-gcm nonce: %w", err)
		}

		dst = aead.Seal(dst, nonce, src, nil)
		return dst, nil
	}
}

func (c *Codec) makeAESDecryptor(aead cipher.AEAD) func(dst, src []byte) ([]byte, error) {
	return func(dst, src []byte) ([]byte, error) {
		if len(src) == 0 {
			return nil, nil
		}
		if len(src) <= aesNonceSize {
			return nil, ErrInvalidCiphertext
		}

		nonce := src[:aesNonceSize]
		ciphertext := src[aesNonceSize:]

		if cap(dst) == 0 {
			dst = make([]byte, 0, len(ciphertext))
		} else {
			dst = dst[:0]
		}

		plaintext, err := aead.Open(dst, nonce, ciphertext, nil)
		if err != nil {
			return nil, ErrInvalidCiphertext
		}
		return plaintext, nil
	}
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create aes-gcm: %w", err)
	}
	return aead, nil
}

func deriveKey(method int, rawKey string) []byte {
	bKey := []byte(rawKey)
	targetLen := requiredDerivedKeyLength(method)

	switch method {
	case 5:
		sum := sha256.Sum256(bKey)
		return sum[:]
	case 3:
		sum := md5.Sum(bKey)
		return sum[:]
	default:
		key := make([]byte, targetLen)
		copy(key, bKey)
		return key
	}
}

func requiredDerivedKeyLength(method int) int {
	switch method {
	case 5:
		return 32
	case 3:
		return 16
	case 4:
		return 24
	default:
		return 32
	}
}
