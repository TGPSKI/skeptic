// Package security provides secret redaction and file hashing for skeptic.
package security

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

var (
	reSecretKeyValue = regexp.MustCompile(`(?i)\b(api[_-]?key|token|secret|password|client_secret|access_token|refresh_token)\b\s*([:=])\s*["']?([A-Za-z0-9._/\-+=]{6,})`)
	reAWSKey         = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reGitHubToken    = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)
	reSlackToken     = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)
	reBasicAuthURL   = regexp.MustCompile(`(?i)\bhttps?://([^/\s:@]+):([^/\s@]+)@`)
	reOpaqueSecret   = regexp.MustCompile(`\b[A-Za-z0-9+/=_-]{40,}\b`)
)

// RedactSensitiveText replaces secret-like substrings in input with fixed placeholders.
func RedactSensitiveText(input string) string {
	out := input
	out = reSecretKeyValue.ReplaceAllString(out, "$1$2REDACTED")
	out = reAWSKey.ReplaceAllString(out, "AKIAREDACTED")
	out = reGitHubToken.ReplaceAllString(out, "ghp_REDACTED")
	out = reSlackToken.ReplaceAllString(out, "xoxb-REDACTED")
	out = reBasicAuthURL.ReplaceAllString(out, "https://REDACTED:REDACTED@")
	out = reOpaqueSecret.ReplaceAllStringFunc(out, func(match string) string {
		if IsLikelyHash(match) {
			return match
		}
		return "REDACTED"
	})
	return out
}

// IsLikelyHash reports whether value is exactly 40 or 64 characters of hexadecimal,
// matching common SHA-1 and SHA-256 digest lengths so they are not redacted as opaque secrets.
func IsLikelyHash(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}

// NormalizeSHA256 trims whitespace, strips an optional "sha256:" prefix, and validates
// that raw is 64 lowercase hexadecimal characters, returning the normalized form.
func NormalizeSHA256(raw string) (string, error) {
	hash := strings.TrimSpace(strings.ToLower(raw))
	hash = strings.TrimPrefix(hash, "sha256:")
	if len(hash) != 64 {
		return "", fmt.Errorf("sha256 must be 64 hex chars, got %d", len(hash))
	}
	for _, ch := range hash {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') {
			continue
		}
		return "", fmt.Errorf("sha256 contains invalid character: %q", ch)
	}
	return hash, nil
}

// SHA256FileHex returns the lowercase hex-encoded SHA-256 digest of the file at path.
func SHA256FileHex(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close %s: %w", path, err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// SanitizeMatch redacts secrets from finding match text when configured.
func SanitizeMatch(value string, redactSecrets bool) string {
	if !redactSecrets {
		return value
	}
	return RedactSensitiveText(value)
}

// ParseEd25519PrivateKeyPEM extracts an Ed25519 private key from PKCS8 PEM data.
func ParseEd25519PrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
		priv, ok := key.(ed25519.PrivateKey)
		if ok {
			return priv, nil
		}
	}
	return nil, errors.New("no Ed25519 PKCS8 private key found in PEM")
}

// ParseEd25519PublicKeyPEM extracts an Ed25519 public key from PKIX PEM data.
func ParseEd25519PublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		pub, ok := key.(ed25519.PublicKey)
		if ok {
			return pub, nil
		}
	}
	return nil, errors.New("no Ed25519 public key found in PEM")
}
