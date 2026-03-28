package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// VerifySelfIntegrity computes the SHA256 of binaryPath and compares to expectedHash.
// Returns nil if they match, an error otherwise.
func VerifySelfIntegrity(binaryPath, expectedHash string) error {
	f, err := os.Open(binaryPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", binaryPath, err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		_ = f.Close()
		return fmt.Errorf("read %s: %w", binaryPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", binaryPath, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	norm, err := NormalizeSHA256(expectedHash)
	if err != nil {
		return fmt.Errorf("expected hash: %w", err)
	}
	if got != norm {
		return fmt.Errorf("integrity mismatch for %s: expected %s, got %s", binaryPath, norm, got)
	}
	return nil
}

// CheckWorldWritableArtifacts scans paths for world-writable sensitive files.
// Returns paths that are world-writable.
func CheckWorldWritableArtifacts(paths []string) []string {
	var out []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0o002 != 0 {
			out = append(out, p)
		}
	}
	return out
}
