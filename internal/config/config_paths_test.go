package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSkepticDataDirDefaultsToHome(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	dir := SkepticDataDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	expected := filepath.Join(home, ".local", "share", "skeptic")
	if dir != expected {
		t.Fatalf("SkepticDataDir() = %q, want %q", dir, expected)
	}
}

// These build their expectations with filepath.Join rather than a literal
// POSIX path. The functions under test join with the OS separator, so a
// hardcoded "/tmp/x/skeptic" only matches on Unix.

func TestSkepticDataDirRespectsXDG(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)
	dir := SkepticDataDir()
	want := filepath.Join(root, "skeptic")
	if dir != want {
		t.Fatalf("SkepticDataDir() = %q, want %q", dir, want)
	}
}

func TestSystemConfigPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)
	p := SystemConfigPath()
	want := filepath.Join(root, "skeptic", "system.json")
	if p != want {
		t.Fatalf("SystemConfigPath() = %q, want %q", p, want)
	}
}

func TestProfilesDir(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)
	p := ProfilesDir()
	want := filepath.Join(root, "skeptic", "profiles")
	if p != want {
		t.Fatalf("ProfilesDir() = %q, want %q", p, want)
	}
}

func TestActiveProfileNameNoFile(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	name, err := ActiveProfileName()
	if err != nil {
		t.Fatal(err)
	}
	if name != "" {
		t.Fatalf("expected empty name, got %q", name)
	}
}

func TestActiveProfileNameReadSuccess(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	dataDir := filepath.Join(root, "skeptic")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "active-profile"), []byte("ci\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	name, err := ActiveProfileName()
	if err != nil {
		t.Fatal(err)
	}
	if name != "ci" {
		t.Fatalf("ActiveProfileName() = %q, want ci", name)
	}
}

func TestActiveProfilePathReturnsEmpty(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	dataDir := filepath.Join(root, "skeptic")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "active-profile"), []byte("missing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, err := ActiveProfilePath()
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Fatalf("expected empty path for missing profile, got %q", path)
	}
}

func TestActiveProfilePathReturnsPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	profDir := filepath.Join(root, "skeptic", "profiles")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profDir, "hunt.json"), []byte(`{"preset":"hunt"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(root, "skeptic")
	if err := os.WriteFile(filepath.Join(dataDir, "active-profile"), []byte("hunt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, err := ActiveProfilePath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, "hunt.json") {
		t.Fatalf("ActiveProfilePath() = %q, want suffix hunt.json", path)
	}
}

func TestIsSystemConfigKey(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"cache-dir", true},
		{"log-dir", true},
		{"daemon-bind", true},
		{"daemon-token-dir", true},
		{"default-workers", true},
		{"SKEPTIC_CACHE_DIR", true},
		{"preset", false},
		{"fail-on", false},
	}
	for _, tc := range cases {
		if got := IsSystemConfigKey(tc.key); got != tc.want {
			t.Errorf("IsSystemConfigKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

func TestActiveProfilePathEmptyPointer(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	dataDir := filepath.Join(root, "skeptic")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "active-profile"), []byte("  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, err := ActiveProfilePath()
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Fatalf("expected empty path for whitespace-only pointer, got %q", path)
	}
}

func TestDefaultSystemConfig(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)
	base := filepath.Join(root, "skeptic")
	sys := DefaultSystemConfig()
	if want := filepath.Join(base, "cache"); sys.CacheDir != want {
		t.Fatalf("CacheDir: got %q, want %q", sys.CacheDir, want)
	}
	if want := filepath.Join(base, "logs"); sys.LogDir != want {
		t.Fatalf("LogDir: got %q, want %q", sys.LogDir, want)
	}
	if sys.DaemonBind != "127.0.0.1:7788" {
		t.Fatalf("DaemonBind: got %q", sys.DaemonBind)
	}
	if sys.DaemonTokenDir != base {
		t.Fatalf("DaemonTokenDir: got %q, want %q", sys.DaemonTokenDir, base)
	}
	if sys.DefaultWorkers != 0 {
		t.Fatalf("DefaultWorkers: got %d", sys.DefaultWorkers)
	}
}

func TestRenderSystemConfig(t *testing.T) {
	sys := SystemConfig{
		CacheDir:       "/test/cache",
		LogDir:         "/test/logs",
		DaemonBind:     "0.0.0.0:8080",
		DaemonTokenDir: "/test/tokens",
		DefaultWorkers: 8,
	}
	data, err := RenderSystemConfig(sys)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"cache-dir"`) {
		t.Fatalf("missing cache-dir in rendered output: %s", s)
	}
	if !strings.Contains(s, `"0.0.0.0:8080"`) {
		t.Fatalf("missing daemon-bind value: %s", s)
	}
	if !strings.Contains(s, `"default-workers": 8`) {
		t.Fatalf("missing default-workers: %s", s)
	}
}
