package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunAutoLoadsConfigFile(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	root := t.TempDir()
	writeFixture(t, root, "note.txt", "safe content")
	if err := os.WriteFile(
		filepath.Join(root, ".skeptic.json"),
		[]byte(`{"path":".","format":"json","fail_on":"none"}`),
		0o644,
	); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	defer func() { _ = os.Chdir(prevWD) }()
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}

	var out, errBuf bytes.Buffer
	code := run([]string{}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("run failed code=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"findings"`) {
		t.Fatalf("expected json output from auto config, got %q", out.String())
	}
}

func TestRunPresetCIProducesJSONByDefault(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	root := t.TempDir()
	writeFixture(t, root, "note.txt", "safe content")

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--preset", "ci",
		"--path", root,
		"--fail-on", "none",
		"--max-files", "50",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("run failed code=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"findings"`) {
		t.Fatalf("expected preset ci json output, got %q", out.String())
	}
}
