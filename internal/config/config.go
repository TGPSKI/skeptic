package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

// RunRawOptions stores raw CLI/config values before typed validation.
type RunRawOptions struct {
	TargetPath                      string
	PathsRaw                        string
	ProfileRaw                      string
	ScanStyleRaw                    string
	ThreatModeRaw                   string
	PolicyChecks                    bool
	AutoDiscoverMCP                 bool
	RulesFileRaw                    string
	RulesDir                        string
	RulesSHA256Raw                  string
	RulesPubKeyRaw                  string
	RequireSignedRules              bool
	NoDefaultRules                  bool
	OutputFormatRaw                 string
	RuleQualityRaw                  string
	FailOnRaw                       string
	MaxBytes                        int64
	IgnorePermissionErrors          bool
	MaxFiles                        int
	Workers                         int
	MaxFindings                     int
	MaxFindingsPerFile              int
	RedactSecrets                   bool
	Incremental                     bool
	StateCachePath                  string
	BaselinePath                    string
	DiffOnly                        bool
	WriteBaselinePath               string
	Verbosity                       int
	Quiet                           bool
	LogFilePath                     string
	ConfigPath                      string
	PresetRaw                       string
	ModeRaw                         string
	BehaviorBaselinePath            string
	BehaviorHistoryPath             string
	DriftSeverityMultiplier         float64
	DriftAllowedChainsRaw           string
	GitCorrelation                  bool
	ProvenanceManifestPath          string
	RequireSignedProvenanceManifest bool
	SBOMPath                        string
	IncludeRulesRaw                 string
	ExcludeRulesRaw                 string
	IgnorePathsRaw                  string
	WaiversRaw                      string
	IdentityGraphHops               int
	AhoCorasick                     bool
	NFKC                            bool
	XORBrute                        bool
	MaxDecodeDepth                  int
	FailOnScore                     int
	ToolName                        string
	NoRulepacks                     bool
}

// SkepticDataDir returns the base directory for skeptic's persistent data.
// It respects $XDG_DATA_HOME (default ~/.local/share) per the XDG Base Directory spec.
func SkepticDataDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "skeptic")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".skeptic")
	}
	return filepath.Join(home, ".local", "share", "skeptic")
}

// SystemConfigPath returns the path to the system-wide infra config.
func SystemConfigPath() string {
	return filepath.Join(SkepticDataDir(), "system.json")
}

// DaemonLogPath returns the default path for daemon log output.
func DaemonLogPath() string {
	return filepath.Join(SkepticDataDir(), "logs", "daemon.log")
}

// DaemonStderrPath returns the default path for capturing daemon child-process stderr.
func DaemonStderrPath() string {
	return filepath.Join(SkepticDataDir(), "logs", "daemon-stderr.log")
}

// DaemonReportPath returns the default path where the daemon writes the latest scan report.
func DaemonReportPath() string {
	return filepath.Join(SkepticDataDir(), "daemon-report.json")
}

// DaemonTokenPath returns the default path for the daemon bearer token file.
func DaemonTokenPath() string {
	return filepath.Join(SkepticDataDir(), "daemon.token")
}

// ProfilesDir returns the directory containing named scan profiles.
func ProfilesDir() string {
	return filepath.Join(SkepticDataDir(), "profiles")
}

// ActiveProfileName reads the active-profile pointer file and returns the profile name.
// Returns empty string if no active profile is set.
func ActiveProfileName() (string, error) {
	data, err := os.ReadFile(filepath.Join(SkepticDataDir(), "active-profile"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	name := strings.TrimSpace(string(data))
	return name, nil
}

// ActiveProfilePath returns the full path to the active named profile, or empty string if none is set.
func ActiveProfilePath() (string, error) {
	name, err := ActiveProfileName()
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", nil
	}
	path := filepath.Join(ProfilesDir(), name+".json")
	if _, statErr := os.Stat(path); statErr != nil {
		if os.IsNotExist(statErr) {
			return "", nil
		}
		return "", statErr
	}
	return path, nil
}

// SystemConfig holds infrastructure-level settings separate from scan behavior.
type SystemConfig struct {
	CacheDir          string `json:"cache-dir"`
	LogDir            string `json:"log-dir"`
	DaemonBind        string `json:"daemon-bind"`
	DaemonTokenDir    string `json:"daemon-token-dir"`
	DefaultWorkers    int    `json:"default-workers"`
	CorpusNoRulepacks bool   `json:"corpus-no-rulepacks,omitempty"`
}

// DefaultSystemConfig returns system config with sensible defaults derived from the data directory.
func DefaultSystemConfig() SystemConfig {
	dataDir := SkepticDataDir()
	return SystemConfig{
		CacheDir:       filepath.Join(dataDir, "cache"),
		LogDir:         filepath.Join(dataDir, "logs"),
		DaemonBind:     "127.0.0.1:7788",
		DaemonTokenDir: dataDir,
		DefaultWorkers: 0,
	}
}

// systemConfigKeys lists keys that belong to system.json and must not appear in scan profiles.
var systemConfigKeys = map[string]struct{}{
	"cache-dir":           {},
	"log-dir":             {},
	"daemon-bind":         {},
	"daemon-token-dir":    {},
	"default-workers":     {},
	"corpus-no-rulepacks": {},
}

// IsSystemConfigKey reports whether a normalized config key belongs to system config.
func IsSystemConfigKey(key string) bool {
	_, ok := systemConfigKeys[NormalizeConfigKey(key)]
	return ok
}

// LoadSystemConfig reads and parses the system config file. If the file does not
// exist, it returns defaults. An explicit path overrides the standard location.
func LoadSystemConfig(path string) (SystemConfig, string, error) {
	selected := strings.TrimSpace(path)
	if selected == "" {
		selected = SystemConfigPath()
	}
	abs, err := filepath.Abs(model.ExpandHomePath(selected))
	if err != nil {
		return DefaultSystemConfig(), "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultSystemConfig(), "", nil
		}
		return SystemConfig{}, "", err
	}
	sys := DefaultSystemConfig()
	if err := json.Unmarshal(data, &sys); err != nil {
		return SystemConfig{}, "", fmt.Errorf("parse system config %s: %w", abs, err)
	}
	if sys.CacheDir != "" {
		sys.CacheDir = model.ExpandHomePath(sys.CacheDir)
	}
	if sys.LogDir != "" {
		sys.LogDir = model.ExpandHomePath(sys.LogDir)
	}
	if sys.DaemonTokenDir != "" {
		sys.DaemonTokenDir = model.ExpandHomePath(sys.DaemonTokenDir)
	}
	return sys, abs, nil
}

// RenderSystemConfig serializes a SystemConfig to indented JSON.
func RenderSystemConfig(sys SystemConfig) ([]byte, error) {
	return json.MarshalIndent(sys, "", "  ")
}

// DefaultConfigCandidates are filenames searched in the working directory for auto-config.
var DefaultConfigCandidates = []string{
	".skeptic.json",
	".skeptic.yaml",
	".skeptic.yml",
	".skeptic.env",
	"skeptic.json",
	"skeptic.yaml",
	"skeptic.yml",
	"skeptic.env",
}

// VisitedFlagNames captures explicitly provided CLI flags for precedence handling.
func VisitedFlagNames(fs *flag.FlagSet) map[string]struct{} {
	out := make(map[string]struct{}, 32)
	fs.Visit(func(f *flag.Flag) {
		out[f.Name] = struct{}{}
	})
	return out
}

// FlagWasSet checks whether a flag was explicitly set by the caller.
func FlagWasSet(visited map[string]struct{}, name string) bool {
	_, ok := visited[name]
	return ok
}

// DiscoverConfigPath finds the first default config candidate in the current working
// directory. If none is found, it falls back to the active named profile under the
// XDG data directory.
func DiscoverConfigPath() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for _, candidate := range DefaultConfigCandidates {
		path := filepath.Join(cwd, candidate)
		info, statErr := os.Stat(path)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				continue
			}
			return "", statErr
		}
		if info.Mode().IsRegular() {
			return path, nil
		}
	}
	return ActiveProfilePath()
}

// LoadConfigValues loads and normalizes config values from JSON/YAML/ENV formats.
func LoadConfigValues(configPath string) (map[string]string, string, error) {
	selected := strings.TrimSpace(configPath)
	if selected == "" {
		discovered, err := DiscoverConfigPath()
		if err != nil {
			return nil, "", err
		}
		if discovered == "" {
			return map[string]string{}, "", nil
		}
		selected = discovered
	}

	abs, err := filepath.Abs(model.ExpandHomePath(selected))
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, "", err
	}
	lower := strings.ToLower(abs)
	switch {
	case strings.HasSuffix(lower, ".json"):
		values, parseErr := ParseJSONConfigValues(data)
		return values, abs, parseErr
	case strings.HasSuffix(lower, ".yaml"), strings.HasSuffix(lower, ".yml"):
		values, parseErr := ParseYAMLConfigValues(data)
		return values, abs, parseErr
	case strings.HasSuffix(lower, ".env"):
		values, parseErr := ParseEnvConfigValues(data)
		return values, abs, parseErr
	default:
		// Fallback for unknown extension: try JSON, then env-like key/value.
		values, parseErr := ParseJSONConfigValues(data)
		if parseErr == nil {
			return values, abs, nil
		}
		values, parseErr = ParseEnvConfigValues(data)
		if parseErr == nil {
			return values, abs, nil
		}
		return nil, "", errors.New("unsupported config format (expected .json, .yaml/.yml, or .env)")
	}
}

// ParseJSONConfigValues converts generic JSON values into string-backed config map entries.
func ParseJSONConfigValues(data []byte) (map[string]string, error) {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(obj))
	for rawKey, value := range obj {
		key := NormalizeConfigKey(rawKey)
		switch typed := value.(type) {
		case string:
			out[key] = strings.TrimSpace(typed)
		case bool:
			out[key] = strconv.FormatBool(typed)
		case float64:
			if float64(int64(typed)) == typed {
				out[key] = strconv.FormatInt(int64(typed), 10)
			} else {
				out[key] = strconv.FormatFloat(typed, 'f', -1, 64)
			}
		case []any:
			parts := make([]string, 0, len(typed))
			for _, item := range typed {
				parts = append(parts, fmt.Sprintf("%v", item))
			}
			out[key] = strings.Join(parts, ",")
		default:
			out[key] = strings.TrimSpace(fmt.Sprintf("%v", typed))
		}
	}
	return out, nil
}

// ParseYAMLConfigValues parses simple YAML key/value and one-level sectioned config files.
func ParseYAMLConfigValues(data []byte) (map[string]string, error) {
	out := make(map[string]string, 32)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	currentSection := ""
	for scanner.Scan() {
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, ": ") {
			section := strings.TrimSuffix(trimmed, ":")
			currentSection = NormalizeConfigKey(section)
			continue
		}
		idx := strings.Index(trimmed, ":")
		if idx <= 0 {
			continue
		}
		rawKey := strings.TrimSpace(trimmed[:idx])
		rawValue := strings.TrimSpace(trimmed[idx+1:])
		if comment := strings.Index(rawValue, " #"); comment >= 0 {
			rawValue = strings.TrimSpace(rawValue[:comment])
		}
		key := NormalizeConfigKey(rawKey)
		if currentSection != "" && strings.HasPrefix(rawLine, " ") {
			key = NormalizeConfigKey(currentSection + "-" + rawKey)
		}
		value := strings.TrimSpace(strings.Trim(rawValue, `"'`))
		if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
			value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
			value = strings.ReplaceAll(value, ", ", ",")
		}
		out[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ParseEnvConfigValues parses dotenv-style config content.
func ParseEnvConfigValues(data []byte) (map[string]string, error) {
	out := make(map[string]string, 32)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		rawKey := strings.TrimSpace(line[:idx])
		rawValue := strings.TrimSpace(line[idx+1:])
		key := NormalizeConfigKey(rawKey)
		value := strings.TrimSpace(strings.Trim(rawValue, `"'`))
		out[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// NormalizeConfigKey aligns aliases (`_`, `.`, prefix) to canonical dash-case keys.
func NormalizeConfigKey(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	key = strings.ReplaceAll(key, ".", "-")
	key = strings.ReplaceAll(key, "_", "-")
	key = strings.TrimPrefix(key, "skeptic-")
	return key
}

// LookupConfigValue resolves key aliases for a config option.
func LookupConfigValue(values map[string]string, key string, aliases ...string) (string, bool) {
	candidates := make([]string, 0, 2+len(aliases))
	candidates = append(candidates, NormalizeConfigKey(key))
	candidates = append(candidates, NormalizeConfigKey("scan-"+key))
	for _, alias := range aliases {
		candidates = append(candidates, NormalizeConfigKey(alias))
	}
	for _, candidate := range candidates {
		if value, ok := values[candidate]; ok {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

// ParseFlexibleBool accepts common human boolean variants for config ergonomics.
func ParseFlexibleBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true, nil
	case "0", "false", "no", "n", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid bool value %q", raw)
	}
}

// ResolvedConfig holds the results of config layer resolution.
type ResolvedConfig struct {
	ScanMode         model.ScanMode
	Preset           ScanPreset
	ConfigPath       string // path of the loaded scan config file, empty if none
	ConfigValues     map[string]string
	VisitedFlags     map[string]struct{}
	System           SystemConfig
	SystemConfigPath string // path of the loaded system config, empty if none
}

// ResolveConfigLayers applies system config, scan profile, mode presets, and scan presets
// to raw options in the correct precedence order: CLI flags > scan config file > preset > mode defaults.
// System config (infra settings) is always loaded underneath.
func ResolveConfigLayers(fs *flag.FlagSet, raw *RunRawOptions) (ResolvedConfig, error) {
	visited := VisitedFlagNames(fs)

	sysConfig, sysPath, sysErr := LoadSystemConfig("")
	if sysErr != nil {
		return ResolvedConfig{}, fmt.Errorf("load system config: %w", sysErr)
	}
	if sysConfig.DefaultWorkers > 0 && !FlagWasSet(visited, "workers") && raw.Workers == 0 {
		raw.Workers = sysConfig.DefaultWorkers
	}

	configValues, loadedPath, err := LoadConfigValues(raw.ConfigPath)
	if err != nil {
		return ResolvedConfig{}, fmt.Errorf("load config: %w", err)
	}
	// NB: if a shorthand is ever added for --mode, check the short name here
	// too — flag.Visit records the Flag.Name that was parsed, not aliases.
	if !FlagWasSet(visited, "mode") {
		if v, ok := LookupConfigValue(configValues, "mode"); ok {
			raw.ModeRaw = v
		}
	}
	scanMode, err := model.ParseScanMode(raw.ModeRaw)
	if err != nil {
		return ResolvedConfig{}, fmt.Errorf("invalid mode: %w", err)
	}
	if err := ApplyRunConfigValues(raw, ModePresetValues(scanMode), visited); err != nil {
		return ResolvedConfig{}, fmt.Errorf("mode preset: %w", err)
	}
	// NB: if a shorthand is ever added for --preset, check the short name here too.
	if !FlagWasSet(visited, "preset") {
		if v, ok := LookupConfigValue(configValues, "preset"); ok {
			raw.PresetRaw = v
		}
	}
	preset, err := ParseScanPreset(raw.PresetRaw)
	if err != nil {
		return ResolvedConfig{}, fmt.Errorf("invalid preset: %w", err)
	}
	if preset != "" {
		if err := ApplyRunConfigValues(raw, PresetValues(preset), visited); err != nil {
			return ResolvedConfig{}, fmt.Errorf("preset values: %w", err)
		}
	}
	if err := ApplyRunConfigValues(raw, configValues, visited); err != nil {
		return ResolvedConfig{}, fmt.Errorf("config values: %w", err)
	}
	scanMode, err = model.ParseScanMode(raw.ModeRaw)
	if err != nil {
		return ResolvedConfig{}, fmt.Errorf("invalid mode after merge: %w", err)
	}
	return ResolvedConfig{
		ScanMode:         scanMode,
		Preset:           preset,
		ConfigPath:       loadedPath,
		ConfigValues:     configValues,
		VisitedFlags:     visited,
		System:           sysConfig,
		SystemConfigPath: sysPath,
	}, nil
}
