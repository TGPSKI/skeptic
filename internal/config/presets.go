package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

// ScanPreset names low-friction scanning workflows.
type ScanPreset string

// Built-in scan preset identifiers, each mapping to a curated flag combination.
const (
	PresetQuick           ScanPreset = "quick"
	PresetDev             ScanPreset = "dev"
	PresetCI              ScanPreset = "ci"
	PresetHunt            ScanPreset = "hunt"
	PresetMachineIdentity ScanPreset = "machine-identity"
	PresetAIWorkload      ScanPreset = "ai-workload"
)

// ParseScanPreset validates named presets used for low-friction scanning workflows.
func ParseScanPreset(raw string) (ScanPreset, error) {
	preset := ScanPreset(strings.ToLower(strings.TrimSpace(raw)))
	if preset == "" {
		return "", nil
	}
	switch preset {
	case PresetQuick, PresetDev, PresetCI, PresetHunt, PresetMachineIdentity, PresetAIWorkload:
		return preset, nil
	default:
		return "", fmt.Errorf("expected one of quick|dev|ci|hunt|machine-identity|ai-workload, got %q", raw)
	}
}

// PresetValues returns opinionated defaults for common operating modes.
func PresetValues(preset ScanPreset) map[string]string {
	switch preset {
	case PresetQuick:
		return map[string]string{
			"scan-style":    string(model.ScanStyleHybrid),
			"policy-checks": "true",
			"fail-on":       string(model.SeverityHigh),
		}
	case PresetDev:
		return map[string]string{
			"profile":                  string(model.ProfileDeveloper),
			"scan-style":               string(model.ScanStyleHybrid),
			"policy-checks":            "true",
			"auto-discover-mcp":        "true",
			"incremental":              "true",
			"ignore-permission-errors": "true",
			"fail-on":                  string(model.SeverityHigh),
		}
	case PresetCI:
		return map[string]string{
			"profile":       string(model.ProfileRepo),
			"scan-style":    string(model.ScanStyleHybrid),
			"policy-checks": "true",
			"format":        string(model.FormatJSON),
			"fail-on":       string(model.SeverityHigh),
		}
	case PresetHunt:
		return map[string]string{
			"scan-style":        string(model.ScanStyleBehavior),
			"policy-checks":     "true",
			"auto-discover-mcp": "true",
			"fail-on":           string(model.SeverityMedium),
			"max-files":         "250000",
		}
	case PresetMachineIdentity:
		return map[string]string{
			"scan-style":    string(model.ScanStyleHybrid),
			"threat-mode":   string(model.ThreatModeMachineIdentity),
			"policy-checks": "true",
			"format":        string(model.FormatJSON),
			"fail-on":       string(model.SeverityMedium),
		}
	case PresetAIWorkload:
		return map[string]string{
			"scan-style":    string(model.ScanStyleHybrid),
			"threat-mode":   string(model.ThreatModeAIWorkload),
			"policy-checks": "true",
			"format":        string(model.FormatJSON),
			"fail-on":       string(model.SeverityMedium),
		}
	default:
		return map[string]string{}
	}
}

// ModePresetValues maps ScanMode to preset-like config values. Modes sit above presets in the resolution chain.
func ModePresetValues(mode model.ScanMode) map[string]string {
	switch mode {
	case model.ScanModeDeveloper:
		return map[string]string{
			"scan-style":    string(model.ScanStyleHybrid),
			"threat-mode":   string(model.ThreatModeAll),
			"policy-checks": "true",
			"fail-on":       string(model.SeverityCritical),
		}
	case model.ScanModeIR:
		return map[string]string{
			"scan-style":    string(model.ScanStyleHybrid),
			"threat-mode":   string(model.ThreatModeAll),
			"policy-checks": "true",
			"fail-on":       string(model.SeverityNone),
		}
	case model.ScanModeDeep:
		return map[string]string{
			"scan-style":    string(model.ScanStyleHybrid),
			"threat-mode":   string(model.ThreatModeAll),
			"policy-checks": "true",
			"fail-on":       string(model.SeverityNone),
		}
	default:
		return map[string]string{}
	}
}

// ApplyRunConfigValues merges string-backed config values into raw run options.
//
//nolint:gocyclo,funlen // flag-by-flag merge requires one branch per option
func ApplyRunConfigValues(raw *RunRawOptions, values map[string]string, visited map[string]struct{}) error {
	if raw == nil || len(values) == 0 {
		return nil
	}

	// flagShorthands maps canonical flag names to their short aliases registered
	// via separate fs.*Var calls (e.g. "format"/"f", "path"/"p"). Go's flag.Visit
	// records the Flag.Name that was actually parsed, so passing -f sets "f" in
	// the visited map, not "format". Without this mapping, config/preset layers
	// silently overwrite values the user explicitly provided via shorthand.
	flagShorthands := map[string]string{
		"format": "f",
		"path":   "p",
	}

	flagExplicit := func(flagName string) bool {
		if FlagWasSet(visited, flagName) {
			return true
		}
		if short, ok := flagShorthands[flagName]; ok {
			return FlagWasSet(visited, short)
		}
		return false
	}

	setString := func(flagName string, target *string, aliases ...string) {
		if flagExplicit(flagName) {
			return
		}
		if value, ok := LookupConfigValue(values, flagName, aliases...); ok {
			*target = value
		}
	}
	setBool := func(flagName string, target *bool, aliases ...string) error {
		if flagExplicit(flagName) {
			return nil
		}
		value, ok := LookupConfigValue(values, flagName, aliases...)
		if !ok {
			return nil
		}
		parsed, err := ParseFlexibleBool(value)
		if err != nil {
			return fmt.Errorf("config %s: %w", flagName, err)
		}
		*target = parsed
		return nil
	}
	setInt := func(flagName string, target *int, aliases ...string) error {
		if flagExplicit(flagName) {
			return nil
		}
		value, ok := LookupConfigValue(values, flagName, aliases...)
		if !ok {
			return nil
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("config %s: invalid int value %q", flagName, value)
		}
		*target = parsed
		return nil
	}
	setInt64 := func(flagName string, target *int64, aliases ...string) error {
		if flagExplicit(flagName) {
			return nil
		}
		value, ok := LookupConfigValue(values, flagName, aliases...)
		if !ok {
			return nil
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("config %s: invalid int64 value %q", flagName, value)
		}
		*target = parsed
		return nil
	}
	setFloat64 := func(flagName string, target *float64, aliases ...string) error {
		if flagExplicit(flagName) {
			return nil
		}
		value, ok := LookupConfigValue(values, flagName, aliases...)
		if !ok {
			return nil
		}
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("config %s: invalid float value %q", flagName, value)
		}
		*target = parsed
		return nil
	}

	setString("path", &raw.TargetPath)
	setString("paths", &raw.PathsRaw)
	setString("profile", &raw.ProfileRaw)
	setString("scan-style", &raw.ScanStyleRaw)
	setString("mode", &raw.ModeRaw)
	setString("threat-mode", &raw.ThreatModeRaw)
	if err := setBool("policy-checks", &raw.PolicyChecks); err != nil {
		return err
	}
	if err := setBool("auto-discover-mcp", &raw.AutoDiscoverMCP); err != nil {
		return err
	}

	setString("rules-file", &raw.RulesFileRaw)
	setString("rules-dir", &raw.RulesDir)
	setString("rules-sha256", &raw.RulesSHA256Raw)
	setString("rules-pubkey", &raw.RulesPubKeyRaw)
	if err := setBool("require-signed-rules", &raw.RequireSignedRules); err != nil {
		return err
	}
	if err := setBool("no-default-rules", &raw.NoDefaultRules); err != nil {
		return err
	}
	if err := setBool("no-rulepacks", &raw.NoRulepacks); err != nil {
		return err
	}
	setString("format", &raw.OutputFormatRaw, "output", "output-format")
	setString("rule-quality", &raw.RuleQualityRaw)
	setString("fail-on", &raw.FailOnRaw)
	if err := setInt64("max-bytes", &raw.MaxBytes); err != nil {
		return err
	}
	if err := setBool("ignore-permission-errors", &raw.IgnorePermissionErrors); err != nil {
		return err
	}
	if err := setInt("max-files", &raw.MaxFiles); err != nil {
		return err
	}
	if err := setInt("workers", &raw.Workers); err != nil {
		return err
	}
	if err := setInt("max-findings", &raw.MaxFindings); err != nil {
		return err
	}
	if err := setInt("max-findings-per-file", &raw.MaxFindingsPerFile); err != nil {
		return err
	}
	if err := setBool("redact-secrets", &raw.RedactSecrets); err != nil {
		return err
	}
	if err := setBool("incremental", &raw.Incremental); err != nil {
		return err
	}
	setString("state-cache", &raw.StateCachePath)
	setString("baseline", &raw.BaselinePath)
	if err := setBool("diff-only", &raw.DiffOnly); err != nil {
		return err
	}
	setString("write-baseline", &raw.WriteBaselinePath)
	if err := setInt("verbose", &raw.Verbosity); err != nil {
		return err
	}
	if err := setBool("quiet", &raw.Quiet); err != nil {
		return err
	}
	setString("log-file", &raw.LogFilePath)
	setString("config", &raw.ConfigPath)
	setString("preset", &raw.PresetRaw)
	setString("behavior-baseline", &raw.BehaviorBaselinePath)
	setString("behavior-history", &raw.BehaviorHistoryPath)
	if err := setFloat64("drift-severity-multiplier", &raw.DriftSeverityMultiplier); err != nil {
		return err
	}
	setString("drift-allowed-chains", &raw.DriftAllowedChainsRaw)
	if err := setBool("git-correlation", &raw.GitCorrelation); err != nil {
		return err
	}
	setString("provenance-manifest", &raw.ProvenanceManifestPath)
	if err := setBool("require-signed-manifest", &raw.RequireSignedProvenanceManifest); err != nil {
		return err
	}
	setString("sbom", &raw.SBOMPath)
	setString("include-rules", &raw.IncludeRulesRaw)
	setString("exclude-rules", &raw.ExcludeRulesRaw)
	setString("ignore-paths", &raw.IgnorePathsRaw)
	setString("waivers", &raw.WaiversRaw)
	if err := setInt("identity-graph-hops", &raw.IdentityGraphHops); err != nil {
		return err
	}
	if err := setBool("aho-corasick", &raw.AhoCorasick); err != nil {
		return err
	}
	if err := setBool("nfkc", &raw.NFKC); err != nil {
		return err
	}
	if err := setBool("xor-brute", &raw.XORBrute); err != nil {
		return err
	}
	if err := setInt("max-decode-depth", &raw.MaxDecodeDepth); err != nil {
		return err
	}

	return nil
}
