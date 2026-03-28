package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInitWritesJSON(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)
	outPath := filepath.Join(root, "profiles", "test.json")
	var out, errBuf bytes.Buffer
	code := RunInit([]string{
		"--out", outPath,
		"--format", "json",
		"--preset", "dev",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunInit failed code=%d stderr=%s", code, errBuf.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read generated config failed: %v", err)
	}
	if !strings.Contains(string(data), `"preset": "dev"`) {
		t.Fatalf("unexpected config content: %s", string(data))
	}
}

func TestRunInitValidation(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	var out, errBuf bytes.Buffer
	code := RunInit([]string{"--format", "wat"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected invalid format exit=2, got %d", code)
	}
}

func TestRunInitBootstrapsSystemConfig(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	outPath := filepath.Join(root, "skeptic", "profiles", "dev.json")
	var out, errBuf bytes.Buffer
	code := RunInit([]string{"--out", outPath, "--preset", "dev"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunInit failed code=%d stderr=%s", code, errBuf.String())
	}

	sysPath := filepath.Join(root, "skeptic", "system.json")
	if _, err := os.Stat(sysPath); err != nil {
		t.Fatalf("system.json not created: %v", err)
	}
	data, err := os.ReadFile(sysPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "cache-dir") {
		t.Fatalf("system.json missing expected keys: %s", string(data))
	}
	if !strings.Contains(out.String(), "wrote system config") {
		t.Fatalf("expected system config write message in stdout: %s", out.String())
	}
}

func TestRunInitConfigAliasCallsRunInit(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)
	outPath := filepath.Join(root, "alias-test.json")
	var out, errBuf bytes.Buffer
	code := RunInitConfig([]string{"--out", outPath, "--preset", "dev"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunInitConfig alias failed code=%d stderr=%s", code, errBuf.String())
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected output file from alias: %v", err)
	}
}

func TestRunInitNoOverwriteWithoutForce(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)
	outPath := filepath.Join(root, "existing.json")
	if err := os.WriteFile(outPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := RunInit([]string{"--out", outPath}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected exit=2 for existing file, got %d", code)
	}
}

func TestRunInitDefaultPathUsesXDG(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	var out, errBuf bytes.Buffer
	code := RunInit([]string{"--preset", "ci"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunInit failed code=%d stderr=%s", code, errBuf.String())
	}
	expected := filepath.Join(root, "skeptic", "profiles", "dev.json")
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("expected profile at XDG path %s: %v", expected, err)
	}
}

func TestRunInitInvalidPreset(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	var out, errBuf bytes.Buffer
	code := RunInit([]string{"--preset", "bogus"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected exit=2 for invalid preset, got %d", code)
	}
	if !strings.Contains(errBuf.String(), "invalid --preset") {
		t.Fatalf("expected preset error, got: %s", errBuf.String())
	}
}

func TestRunInitBootstrapSkipsExistingSystemConfig(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	dataDir := filepath.Join(root, "skeptic")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sysPath := filepath.Join(dataDir, "system.json")
	if err := os.WriteFile(sysPath, []byte(`{"daemon-bind":"0.0.0.0:1234"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(root, "test-profile.json")
	var out, errBuf bytes.Buffer
	code := RunInit([]string{"--out", outPath}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunInit failed code=%d stderr=%s", code, errBuf.String())
	}
	if strings.Contains(out.String(), "wrote system config") {
		t.Fatal("should not have rewritten existing system.json")
	}
	data, _ := os.ReadFile(sysPath)
	if !strings.Contains(string(data), "0.0.0.0:1234") {
		t.Fatal("existing system.json was overwritten")
	}
}

func TestRunInitYAMLFormat(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)
	outPath := filepath.Join(root, "test.yaml")
	var out, errBuf bytes.Buffer
	code := RunInit([]string{"--out", outPath, "--format", "yaml", "--preset", "dev"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunInit yaml failed code=%d stderr=%s", code, errBuf.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "preset: dev") {
		t.Fatalf("expected yaml content, got: %s", string(data))
	}
}

func TestRunInitEnvFormat(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)
	outPath := filepath.Join(root, "test.env")
	var out, errBuf bytes.Buffer
	code := RunInit([]string{"--out", outPath, "--format", "env", "--preset", "ci"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunInit env failed code=%d stderr=%s", code, errBuf.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "SKEPTIC_PRESET=ci") {
		t.Fatalf("expected env content, got: %s", string(data))
	}
}

func TestRunInitWaiversInDataDirForDefaultPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	var out, errBuf bytes.Buffer
	code := RunInit([]string{"--preset", "dev"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunInit failed code=%d stderr=%s", code, errBuf.String())
	}
	dataDir := filepath.Join(root, "skeptic")
	profilesDir := filepath.Join(dataDir, "profiles")
	if _, err := os.Stat(filepath.Join(profilesDir, ".skeptic-waivers.json")); err == nil {
		t.Fatalf("waiver file should not be in profiles dir")
	}
	waiverPath := filepath.Join(dataDir, ".skeptic-waivers.json")
	if _, err := os.Stat(waiverPath); err != nil {
		t.Fatalf("waiver file should be in data dir %s: %v", waiverPath, err)
	}
}

func TestRunInitWaiversWrittenForCustomPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	outPath := filepath.Join(root, "myproject", "skeptic.json")
	var out, errBuf bytes.Buffer
	code := RunInit([]string{"--out", outPath, "--preset", "dev"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("RunInit failed code=%d stderr=%s", code, errBuf.String())
	}
	waiverPath := filepath.Join(root, "myproject", ".skeptic-waivers.json")
	if _, err := os.Stat(waiverPath); err != nil {
		t.Fatalf("waiver file should be written alongside custom config: %v", err)
	}
}

func TestRenderInitConfigUnsupportedFormat(t *testing.T) {
	_, err := RenderInitConfig(map[string]any{"preset": "dev"}, "toml")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}
