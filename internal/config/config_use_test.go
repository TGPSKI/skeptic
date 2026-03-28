package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunConfigUseSuccess(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	profDir := filepath.Join(root, "skeptic", "profiles")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profDir, "ci.json"), []byte(`{"preset":"ci"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	code := RunConfigUse([]string{"ci"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunConfigUse failed code=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "active profile: ci") {
		t.Fatalf("expected confirmation, got: %s", out.String())
	}

	pointerData, err := os.ReadFile(filepath.Join(root, "skeptic", "active-profile"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(pointerData)) != "ci" {
		t.Fatalf("pointer file contains %q, want ci", string(pointerData))
	}
}

func TestRunConfigUseMissingProfile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	var out, errBuf bytes.Buffer
	code := RunConfigUse([]string{"nonexistent"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected exit=2 for missing profile, got %d", code)
	}
	if !strings.Contains(errBuf.String(), "not found") {
		t.Fatalf("expected 'not found' error, got: %s", errBuf.String())
	}
}

func TestRunConfigUseNoArgs(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := RunConfigUse(nil, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected exit=2 for no args, got %d", code)
	}
}

func TestRunConfigUseEmptyName(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := RunConfigUse([]string{"  "}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected exit=2 for empty name, got %d", code)
	}
	if !strings.Contains(errBuf.String(), "must not be empty") {
		t.Fatalf("expected empty-name error, got: %s", errBuf.String())
	}
}

func TestRunConfigDispatch(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	var out, errBuf bytes.Buffer

	code := RunConfig(nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("bare 'config' should exit 0, got %d", code)
	}

	out.Reset()
	errBuf.Reset()
	code = RunConfig([]string{"show"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("config show failed code=%d stderr=%s", code, errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	code = RunConfig([]string{"bogus"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected exit=2 for unknown subcommand, got %d", code)
	}
}

func TestRunConfigDispatchUse(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	profDir := filepath.Join(root, "skeptic", "profiles")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profDir, "hunt.json"), []byte(`{"preset":"hunt"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	code := RunConfig([]string{"use", "hunt"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("config use via RunConfig failed code=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "active profile: hunt") {
		t.Fatalf("expected confirmation, got: %s", out.String())
	}
}
