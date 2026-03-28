package config

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestApplyRunConfigValuesMapsBehaviorBaselineAndProvenanceManifest(t *testing.T) {
	raw := RunRawOptions{}
	visited := map[string]struct{}{}
	vals := map[string]string{
		"behavior-baseline":   filepath.Join("tmp", "behavior.json"),
		"provenance-manifest": filepath.Join("tmp", "prov.json"),
	}
	if err := ApplyRunConfigValues(&raw, vals, visited); err != nil {
		t.Fatal(err)
	}
	if raw.BehaviorBaselinePath != vals["behavior-baseline"] {
		t.Fatalf("BehaviorBaselinePath: got %q want %q", raw.BehaviorBaselinePath, vals["behavior-baseline"])
	}
	if raw.ProvenanceManifestPath != vals["provenance-manifest"] {
		t.Fatalf("ProvenanceManifestPath: got %q want %q", raw.ProvenanceManifestPath, vals["provenance-manifest"])
	}
}

func TestModePresetValues(t *testing.T) {
	t.Parallel()
	dev := ModePresetValues(model.ScanModeDeveloper)
	if dev["fail-on"] != string(model.SeverityCritical) {
		t.Fatalf("developer fail-on: got %q want critical", dev["fail-on"])
	}
	ir := ModePresetValues(model.ScanModeIR)
	if ir["fail-on"] != string(model.SeverityNone) {
		t.Fatalf("ir fail-on: got %q want none", ir["fail-on"])
	}
	if unknown := ModePresetValues(model.ScanMode("")); len(unknown) != 0 {
		t.Fatalf("unknown mode should return empty map, got %v", unknown)
	}
}

func TestApplyRunConfigValuesRespectsVisitedFlagsForBaselinePaths(t *testing.T) {
	raw := RunRawOptions{}
	visited := map[string]struct{}{
		"behavior-baseline":   {},
		"provenance-manifest": {},
	}
	vals := map[string]string{
		"behavior-baseline":   "/from-config/behavior.json",
		"provenance-manifest": "/from-config/prov.json",
	}
	raw.BehaviorBaselinePath = "/from-cli/behavior.json"
	raw.ProvenanceManifestPath = "/from-cli/prov.json"
	if err := ApplyRunConfigValues(&raw, vals, visited); err != nil {
		t.Fatal(err)
	}
	if raw.BehaviorBaselinePath != "/from-cli/behavior.json" {
		t.Fatalf("BehaviorBaselinePath should stay CLI value, got %q", raw.BehaviorBaselinePath)
	}
	if raw.ProvenanceManifestPath != "/from-cli/prov.json" {
		t.Fatalf("ProvenanceManifestPath should stay CLI value, got %q", raw.ProvenanceManifestPath)
	}
}

func TestResolveConfigLayersDefaultMode(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	raw := RunRawOptions{ModeRaw: "developer"}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("mode", "developer", "")
	fs.String("preset", "", "")

	resolved, err := ResolveConfigLayers(fs, &raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.ScanMode != model.ScanModeDeveloper {
		t.Errorf("expected developer mode, got %s", resolved.ScanMode)
	}
}

func TestResolveConfigLayersIRMode(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	raw := RunRawOptions{ModeRaw: "ir"}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("mode", "ir", "")
	fs.String("preset", "", "")

	resolved, err := ResolveConfigLayers(fs, &raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.ScanMode != model.ScanModeIR {
		t.Errorf("expected ir mode, got %s", resolved.ScanMode)
	}
}

func TestResolveConfigLayersInvalidMode(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	raw := RunRawOptions{ModeRaw: "bogus"}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("mode", "bogus", "")
	fs.String("preset", "", "")

	_, err := ResolveConfigLayers(fs, &raw)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestResolveConfigLayersWithPreset(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	raw := RunRawOptions{ModeRaw: "developer", PresetRaw: "ci"}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("mode", "developer", "")
	fs.String("preset", "ci", "")

	resolved, err := ResolveConfigLayers(fs, &raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.Preset != "ci" {
		t.Errorf("expected ci preset, got %s", resolved.Preset)
	}
}

func TestDiscoverConfigPathFallsBackToActiveProfile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	profDir := filepath.Join(root, "skeptic", "profiles")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatal(err)
	}
	profPath := filepath.Join(profDir, "hunt.json")
	if err := os.WriteFile(profPath, []byte(`{"preset":"hunt"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(root, "skeptic")
	if err := os.WriteFile(filepath.Join(dataDir, "active-profile"), []byte("hunt\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run from a temp directory with no local configs
	emptyDir := t.TempDir()
	origDir, _ := os.Getwd()
	if err := os.Chdir(emptyDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	discovered, err := DiscoverConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(discovered, "hunt.json") {
		t.Fatalf("DiscoverConfigPath() = %q, expected to end with hunt.json", discovered)
	}
}

func TestDiscoverConfigPathLocalWinsOverProfile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	// Set up active profile
	profDir := filepath.Join(root, "skeptic", "profiles")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profDir, "ci.json"), []byte(`{"preset":"ci"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(root, "skeptic")
	if err := os.WriteFile(filepath.Join(dataDir, "active-profile"), []byte("ci\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create local config in a different temp dir and chdir there
	localDir := t.TempDir()
	localConfig := filepath.Join(localDir, ".skeptic.json")
	if err := os.WriteFile(localConfig, []byte(`{"preset":"dev"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	origDir, _ := os.Getwd()
	if err := os.Chdir(localDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	discovered, err := DiscoverConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(discovered, ".skeptic.json") {
		t.Fatalf("local config should win, got %q", discovered)
	}
}

func TestLoadSystemConfigDefaults(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	sys, path, err := LoadSystemConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Fatalf("expected empty path when no file exists, got %q", path)
	}
	if sys.DaemonBind != "127.0.0.1:7788" {
		t.Fatalf("default daemon-bind: got %q", sys.DaemonBind)
	}
}

func TestLoadSystemConfigFromFile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	dataDir := filepath.Join(root, "skeptic")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sys := SystemConfig{
		CacheDir:       "/custom/cache",
		LogDir:         "/custom/logs",
		DaemonBind:     "0.0.0.0:9999",
		DaemonTokenDir: "/custom/tokens",
		DefaultWorkers: 4,
	}
	data, _ := json.MarshalIndent(sys, "", "  ")
	sysPath := filepath.Join(dataDir, "system.json")
	if err := os.WriteFile(sysPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, loadedPath, err := LoadSystemConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath == "" {
		t.Fatal("expected non-empty loaded path")
	}
	if loaded.DaemonBind != "0.0.0.0:9999" {
		t.Fatalf("DaemonBind: got %q", loaded.DaemonBind)
	}
	if loaded.DefaultWorkers != 4 {
		t.Fatalf("DefaultWorkers: got %d", loaded.DefaultWorkers)
	}
}

func TestResolveConfigLayersLoadsSystemConfig(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	raw := RunRawOptions{ModeRaw: "developer"}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("mode", "developer", "")
	fs.String("preset", "", "")

	resolved, err := ResolveConfigLayers(fs, &raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.System.DaemonBind != "127.0.0.1:7788" {
		t.Errorf("system config not loaded, DaemonBind = %q", resolved.System.DaemonBind)
	}
}

func TestLoadSystemConfigExplicitPath(t *testing.T) {
	root := t.TempDir()
	customPath := filepath.Join(root, "custom-system.json")
	sys := SystemConfig{
		CacheDir:       "/explicit/cache",
		LogDir:         "/explicit/logs",
		DaemonBind:     "127.0.0.1:9090",
		DaemonTokenDir: "/explicit/tokens",
		DefaultWorkers: 2,
	}
	data, _ := json.MarshalIndent(sys, "", "  ")
	if err := os.WriteFile(customPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, loadedPath, err := LoadSystemConfig(customPath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath == "" {
		t.Fatal("expected non-empty loaded path for explicit path")
	}
	if loaded.DaemonBind != "127.0.0.1:9090" {
		t.Fatalf("DaemonBind: got %q", loaded.DaemonBind)
	}
	if loaded.DefaultWorkers != 2 {
		t.Fatalf("DefaultWorkers: got %d", loaded.DefaultWorkers)
	}
}

func TestLoadSystemConfigCorpusNoRulepacks(t *testing.T) {
	root := t.TempDir()
	sysPath := filepath.Join(root, "system.json")
	if err := os.WriteFile(sysPath, []byte(`{"corpus-no-rulepacks": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := LoadSystemConfig(sysPath)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.CorpusNoRulepacks {
		t.Fatal("expected CorpusNoRulepacks=true")
	}
}

func TestLoadSystemConfigBadJSON(t *testing.T) {
	root := t.TempDir()
	badPath := filepath.Join(root, "bad-system.json")
	if err := os.WriteFile(badPath, []byte(`{invalid json`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadSystemConfig(badPath)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "parse system config") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestResolveConfigLayersAppliesDefaultWorkers(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)

	dataDir := filepath.Join(root, "skeptic")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sys := SystemConfig{
		CacheDir:       filepath.Join(dataDir, "cache"),
		LogDir:         filepath.Join(dataDir, "logs"),
		DaemonBind:     "127.0.0.1:7788",
		DaemonTokenDir: dataDir,
		DefaultWorkers: 6,
	}
	data, _ := json.MarshalIndent(sys, "", "  ")
	if err := os.WriteFile(filepath.Join(dataDir, "system.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	raw := RunRawOptions{ModeRaw: "developer"}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("mode", "developer", "")
	fs.String("preset", "", "")

	resolved, err := ResolveConfigLayers(fs, &raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw.Workers != 6 {
		t.Fatalf("expected Workers=6 from system config, got %d", raw.Workers)
	}
	if resolved.SystemConfigPath == "" {
		t.Fatal("expected non-empty SystemConfigPath")
	}
}

func TestApplyRunConfigValuesShorthandFlagPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		visited       map[string]struct{}
		configValues  map[string]string
		initialFormat string
		initialPath   string
		wantFormat    string
		wantPath      string
	}{
		{
			name:          "shorthand -f blocks config override",
			visited:       map[string]struct{}{"f": {}},
			configValues:  map[string]string{"format": "text"},
			initialFormat: "json",
			wantFormat:    "json",
		},
		{
			name:         "shorthand -p blocks config override",
			visited:      map[string]struct{}{"p": {}},
			configValues: map[string]string{"path": "/from-config"},
			initialPath:  "/from-cli",
			wantPath:     "/from-cli",
		},
		{
			name:          "long --format blocks config override",
			visited:       map[string]struct{}{"format": {}},
			configValues:  map[string]string{"format": "sarif"},
			initialFormat: "json",
			wantFormat:    "json",
		},
		{
			name:         "long --path blocks config override",
			visited:      map[string]struct{}{"path": {}},
			configValues: map[string]string{"path": "/from-config"},
			initialPath:  "/from-cli",
			wantPath:     "/from-cli",
		},
		{
			name:          "unvisited format allows config override",
			visited:       map[string]struct{}{},
			configValues:  map[string]string{"format": "sarif"},
			initialFormat: "text",
			wantFormat:    "sarif",
		},
		{
			name:         "unvisited path allows config override",
			visited:      map[string]struct{}{},
			configValues: map[string]string{"path": "/from-config"},
			initialPath:  ".",
			wantPath:     "/from-config",
		},
		{
			name:          "shorthand -f blocks preset override",
			visited:       map[string]struct{}{"f": {}},
			configValues:  PresetValues(PresetCI),
			initialFormat: "sarif",
			wantFormat:    "sarif",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw := RunRawOptions{
				OutputFormatRaw: tc.initialFormat,
				TargetPath:      tc.initialPath,
			}
			if err := ApplyRunConfigValues(&raw, tc.configValues, tc.visited); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantFormat != "" && raw.OutputFormatRaw != tc.wantFormat {
				t.Errorf("OutputFormatRaw: got %q, want %q", raw.OutputFormatRaw, tc.wantFormat)
			}
			if tc.wantPath != "" && raw.TargetPath != tc.wantPath {
				t.Errorf("TargetPath: got %q, want %q", raw.TargetPath, tc.wantPath)
			}
		})
	}
}
