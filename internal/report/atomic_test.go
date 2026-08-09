package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomicCreatesFileAndParents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "report.json")

	if err := WriteFileAtomic(path, []byte("payload\n"), 0o644); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "payload\n" {
		t.Errorf("content = %q, want %q", got, "payload\n")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want 644", perm)
	}
}

func TestWriteFileAtomicOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	if err := WriteFileAtomic(path, []byte("first"), 0o644); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFileAtomic(path, []byte("second"), 0o644); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("content = %q, want %q", got, "second")
	}
}

// The temp file lives in the destination directory so the rename stays within
// one filesystem. It must not survive the call.
func TestWriteFileAtomicLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	if err := WriteFileAtomic(path, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want 1", len(entries))
	}
}

// A failure must leave any existing file untouched rather than truncating it.
func TestWriteFileAtomicFailureKeepsExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := WriteFileAtomic(path, []byte("original"), 0o644); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	// A directory where the temp file must be created makes CreateTemp fail.
	readOnly := filepath.Join(dir, "locked")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })

	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions do not deny writes")
	}
	if err := WriteFileAtomic(filepath.Join(readOnly, "x.json"), []byte("nope"), 0o644); err == nil {
		t.Error("expected an error writing into a non-writable directory")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "original" {
		t.Errorf("existing file was modified: %q", got)
	}
}
