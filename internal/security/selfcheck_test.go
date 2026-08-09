package security

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVerifySelfIntegrityMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bin")
	content := []byte("test binary content\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	sum := sha256.Sum256(content)
	expected := hex.EncodeToString(sum[:])
	if err := VerifySelfIntegrity(path, expected); err != nil {
		t.Fatalf("VerifySelfIntegrity: %v", err)
	}
}

func TestVerifySelfIntegrityMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bin")
	if err := os.WriteFile(path, []byte("a"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	wrong := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := VerifySelfIntegrity(path, wrong); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestCheckWorldWritableArtifacts(t *testing.T) {
	dir := t.TempDir()
	ww := filepath.Join(dir, "world-writable")
	if err := os.WriteFile(ww, []byte("x"), 0o600); err != nil {
		t.Fatalf("write ww: %v", err)
	}
	if err := os.Chmod(ww, 0o666); err != nil {
		t.Fatalf("chmod ww: %v", err)
	}
	secure := filepath.Join(dir, "secure")
	if err := os.WriteFile(secure, []byte("y"), 0o600); err != nil {
		t.Fatalf("write secure: %v", err)
	}
	got := CheckWorldWritableArtifacts([]string{ww, secure, filepath.Join(dir, "missing")})

	// Windows has no POSIX mode bits, so isWorldWritable reports nothing rather
	// than flagging every writable file. See selfcheck_perm_windows.go.
	if runtime.GOOS == "windows" {
		if len(got) != 0 {
			t.Fatalf("expected no world-writable paths on Windows, got %v", got)
		}
		return
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 world-writable path, got %v", got)
	}
	if got[0] != ww {
		t.Fatalf("expected %q, got %q", ww, got[0])
	}
}
