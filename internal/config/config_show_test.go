package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunConfigShowText(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	var out, errBuf bytes.Buffer
	code := RunConfigShow(nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunConfigShow failed code=%d stderr=%s", code, errBuf.String())
	}
	output := out.String()
	if !strings.Contains(output, "System config") {
		t.Fatalf("expected 'System config' heading, got: %s", output)
	}
	if !strings.Contains(output, "Scan profile") {
		t.Fatalf("expected 'Scan profile' heading, got: %s", output)
	}
}

func TestRunConfigShowJSON(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	var out, errBuf bytes.Buffer
	code := RunConfigShow([]string{"--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunConfigShow --json failed code=%d stderr=%s", code, errBuf.String())
	}
	output := out.String()
	if !strings.Contains(output, `"system"`) {
		t.Fatalf("expected system key in JSON output: %s", output)
	}
	if !strings.Contains(output, `"profile"`) {
		t.Fatalf("expected profile key in JSON output: %s", output)
	}
}

func TestRunConfigShowSystemOnly(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	var out, errBuf bytes.Buffer
	code := RunConfigShow([]string{"--system"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunConfigShow --system failed code=%d stderr=%s", code, errBuf.String())
	}
	output := out.String()
	if !strings.Contains(output, "System config") {
		t.Fatalf("expected 'System config', got: %s", output)
	}
	if strings.Contains(output, "Scan profile") {
		t.Fatalf("--system should hide scan profile section, got: %s", output)
	}
}

func TestRunConfigShowProfileOnly(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	var out, errBuf bytes.Buffer
	code := RunConfigShow([]string{"--profile"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunConfigShow --profile failed code=%d stderr=%s", code, errBuf.String())
	}
	output := out.String()
	if strings.Contains(output, "System config") {
		t.Fatalf("--profile should hide system config, got: %s", output)
	}
	if !strings.Contains(output, "Scan profile") {
		t.Fatalf("expected 'Scan profile', got: %s", output)
	}
}

func TestRunConfigShowMutuallyExclusive(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := RunConfigShow([]string{"--system", "--profile"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected exit=2 for --system + --profile, got %d", code)
	}
}

func TestRunConfigShowWithActiveProfile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	dataDir := filepath.Join(root, "skeptic")
	profDir := filepath.Join(dataDir, "profiles")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profDir, "ci.json"), []byte(`{"preset":"ci","fail-on":"high"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "active-profile"), []byte("ci\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	code := RunConfigShow(nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunConfigShow failed code=%d stderr=%s", code, errBuf.String())
	}
	output := out.String()
	if !strings.Contains(output, "active profile: ci") {
		t.Fatalf("expected active profile annotation, got: %s", output)
	}
}

func TestRunConfigShowWithLoadedSystemConfig(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	dataDir := filepath.Join(root, "skeptic")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "system.json"), []byte(`{"daemon-bind":"0.0.0.0:9999","default-workers":4}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	code := RunConfigShow(nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunConfigShow failed code=%d stderr=%s", code, errBuf.String())
	}
	output := out.String()
	if !strings.Contains(output, "source:") || !strings.Contains(output, "system.json") {
		t.Fatalf("expected system.json source path in output, got: %s", output)
	}
	if !strings.Contains(output, "0.0.0.0:9999") {
		t.Fatalf("expected custom daemon-bind value, got: %s", output)
	}
}

func TestRunConfigShowJSONWithLoadedSystem(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	dataDir := filepath.Join(root, "skeptic")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "system.json"), []byte(`{"daemon-bind":"127.0.0.1:5555"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	code := RunConfigShow([]string{"--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunConfigShow --json failed code=%d stderr=%s", code, errBuf.String())
	}
	output := out.String()
	if !strings.Contains(output, "system.json") {
		t.Fatalf("expected system.json path in JSON output, got: %s", output)
	}
	if !strings.Contains(output, "127.0.0.1:5555") {
		t.Fatalf("expected custom bind value in JSON, got: %s", output)
	}
}

func TestRunConfigShowListsMultipleProfiles(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	dataDir := filepath.Join(root, "skeptic")
	profDir := filepath.Join(dataDir, "profiles")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dev", "ci", "hunt"} {
		if err := os.WriteFile(filepath.Join(profDir, name+".json"), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dataDir, "active-profile"), []byte("ci\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	code := RunConfigShow(nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunConfigShow failed code=%d stderr=%s", code, errBuf.String())
	}
	output := out.String()
	if !strings.Contains(output, "Available profiles") {
		t.Fatalf("expected 'Available profiles' section, got: %s", output)
	}
	if !strings.Contains(output, "* ci") {
		t.Fatalf("expected active marker '* ci', got: %s", output)
	}
	if !strings.Contains(output, "dev") || !strings.Contains(output, "hunt") {
		t.Fatalf("expected all profiles listed, got: %s", output)
	}
}

func TestRunConfigShowEmptyProfilesDir(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	profDir := filepath.Join(root, "skeptic", "profiles")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	code := RunConfigShow(nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunConfigShow failed code=%d stderr=%s", code, errBuf.String())
	}
	if strings.Contains(out.String(), "Available profiles") {
		t.Fatal("should not show 'Available profiles' for empty dir")
	}
}
