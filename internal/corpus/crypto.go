package corpus

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

const (
	keySize   = 32 // AES-256
	nonceSize = 12 // GCM standard nonce
)

// GenerateKey returns 32 cryptographically random bytes for AES-256.
func GenerateKey() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("corpus: generate key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext with AES-256-GCM.
// Returns nonce (12 bytes) || ciphertext || GCM tag.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("corpus: encrypt: key must be %d bytes, got %d", keySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("corpus: encrypt: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("corpus: encrypt: %w", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("corpus: encrypt: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. Verifies GCM authentication tag.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("corpus: decrypt: key must be %d bytes, got %d", keySize, len(key))
	}
	if len(ciphertext) < nonceSize {
		return nil, errors.New("corpus: decrypt: ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("corpus: decrypt: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("corpus: decrypt: %w", err)
	}
	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("corpus: decrypt: authentication failed: %w", err)
	}
	return plaintext, nil
}

// LoadKey reads the 32-byte key from the restricted-permission key file.
func LoadKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("corpus: load key: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("corpus: load key: expected %d bytes, got %d", keySize, len(key))
	}
	return key, nil
}

// WriteKey writes key to path with mode 0600.
func WriteKey(path string, key []byte) error {
	if len(key) != keySize {
		return fmt.Errorf("corpus: write key: expected %d bytes, got %d", keySize, len(key))
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return fmt.Errorf("corpus: write key: %w", err)
	}
	return nil
}

// SHA256Hex returns the lowercase hex-encoded SHA-256 digest of data.
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
