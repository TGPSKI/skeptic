package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

// RunInit creates starter config files and bootstraps the XDG data directory.
// When --out is not specified, writes to ~/.local/share/skeptic/profiles/dev.json.
func RunInit(args []string, stdout io.Writer, stderr io.Writer) int {
	var (
		outPath  string
		format   string
		force    bool
		presetIn string
	)
	defaultOut := filepath.Join(ProfilesDir(), "dev.json")
	fs := flag.NewFlagSet("skeptic init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		PrintSubcommandHeader(stderr, "init", "Bootstrap skeptic configuration and its XDG data directory.", []string{"skeptic init --preset ci --out .skeptic.json"})
		PrintFormattedFlags(fs, stderr, map[string]string{
			"o": "out", "f": "format",
		}, nil)
	}
	fs.StringVar(&outPath, "out", defaultOut, "output config path")
	fs.StringVar(&outPath, "o", defaultOut, "output config path")
	fs.StringVar(&format, "format", "json", "config format: json|yaml|env")
	fs.StringVar(&format, "f", "json", "config format: json|yaml|env")
	fs.BoolVar(&force, "force", false, "overwrite existing config file")
	fs.StringVar(&presetIn, "preset", string(PresetDev), "starter preset: quick|dev|ci|hunt|machine-identity|ai-workload")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	preset, err := ParseScanPreset(presetIn)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --preset value: %v\n", err)
		return 2
	}
	if preset == "" {
		preset = PresetDev
	}
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "json", "yaml", "env":
	default:
		fmt.Fprintln(stderr, "invalid --format value: expected json|yaml|env")
		return 2
	}

	if code := bootstrapSystemConfig(stdout, stderr); code != 0 {
		return code
	}

	absPath, err := filepath.Abs(model.ExpandHomePath(outPath))
	if err != nil {
		fmt.Fprintf(stderr, "invalid output path: %v\n", err)
		return 2
	}
	if !force {
		if _, err := os.Stat(absPath); err == nil {
			fmt.Fprintf(stderr, "config file already exists: %s (use --force to overwrite)\n", absPath)
			return 2
		}
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "failed to create config directory: %v\n", err)
		return 1
	}

	waiverFilename := ".skeptic-waivers.json"
	values := map[string]any{
		"preset":  string(preset),
		"path":    ".",
		"waivers": waiverFilename,
	}
	rulesDir := filepath.Join(filepath.Dir(absPath), "rulepacks", "campaigns")
	if info, err := os.Stat(rulesDir); err == nil && info.IsDir() {
		values["rules_dir"] = "rulepacks/campaigns"
	}
	rendered, err := RenderInitConfig(values, format)
	if err != nil {
		fmt.Fprintf(stderr, "failed to render config: %v\n", err)
		return 1
	}
	if err := os.WriteFile(absPath, rendered, 0o600); err != nil {
		fmt.Fprintf(stderr, "failed to write config file: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote skeptic config: %s\n", absPath)

	waiverDir := filepath.Dir(absPath)
	profilesAbs, _ := filepath.Abs(ProfilesDir())                          //nolint:errcheck // best-effort comparison
	if configAbs, _ := filepath.Abs(waiverDir); configAbs == profilesAbs { //nolint:errcheck // best-effort comparison
		waiverDir = SkepticDataDir()
	}
	waiverPath := filepath.Join(waiverDir, waiverFilename)
	if _, statErr := os.Stat(waiverPath); statErr != nil {
		emptyWaivers := []byte("{\n  \"version\": 1,\n  \"waivers\": []\n}\n")
		if err := os.WriteFile(waiverPath, emptyWaivers, 0o600); err != nil {
			fmt.Fprintf(stderr, "failed to write waiver file: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote waiver file: %s\n", waiverPath)
	}

	// Activate the profile so `skeptic scan` immediately uses it.
	profileName := strings.TrimSuffix(filepath.Base(absPath), filepath.Ext(absPath))
	if dir, _ := filepath.Abs(filepath.Dir(absPath)); dir == profilesAbs { //nolint:errcheck // best-effort comparison
		pointerPath := filepath.Join(SkepticDataDir(), "active-profile")
		if err := os.WriteFile(pointerPath, []byte(profileName+"\n"), 0o644); err != nil {
			fmt.Fprintf(stderr, "warning: could not activate profile: %v\n", err)
		} else {
			fmt.Fprintf(stdout, "active profile: %s\n", profileName)
		}
	}
	return 0
}

// RunInitConfig is a backward-compatible alias for RunInit.
func RunInitConfig(args []string, stdout io.Writer, stderr io.Writer) int {
	return RunInit(args, stdout, stderr)
}

func bootstrapSystemConfig(stdout io.Writer, stderr io.Writer) int {
	sysPath := SystemConfigPath()
	if _, err := os.Stat(sysPath); err == nil {
		return 0
	}
	if err := os.MkdirAll(filepath.Dir(sysPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "failed to create data directory: %v\n", err)
		return 1
	}
	data, err := RenderSystemConfig(DefaultSystemConfig())
	if err != nil {
		fmt.Fprintf(stderr, "failed to render system config: %v\n", err)
		return 1
	}
	if err := os.WriteFile(sysPath, data, 0o600); err != nil {
		fmt.Fprintf(stderr, "failed to write system config: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote system config: %s\n", sysPath)
	return 0
}

// RenderInitConfig serializes starter config content for supported file formats.
func RenderInitConfig(values map[string]any, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(values, "", "  ")
	case "yaml":
		lines := []string{
			"preset: " + fmt.Sprintf("%v", values["preset"]),
			"path: " + fmt.Sprintf("%v", values["path"]),
		}
		if w, ok := values["waivers"]; ok {
			lines = append(lines, "waivers: "+fmt.Sprintf("%v", w))
		}
		if rd, ok := values["rules_dir"]; ok {
			lines = append(lines, "rules_dir: "+fmt.Sprintf("%v", rd))
		}
		lines = append(lines, "")
		return []byte(strings.Join(lines, "\n")), nil
	case "env":
		lines := []string{
			"SKEPTIC_PRESET=" + fmt.Sprintf("%v", values["preset"]),
			"SKEPTIC_PATH=" + fmt.Sprintf("%v", values["path"]),
		}
		if w, ok := values["waivers"]; ok {
			lines = append(lines, "SKEPTIC_WAIVERS="+fmt.Sprintf("%v", w))
		}
		lines = append(lines, "")
		return []byte(strings.Join(lines, "\n")), nil
	default:
		return nil, errors.New("unsupported format")
	}
}
