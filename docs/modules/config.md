# config

> Config file discovery, loading, preset resolution, XDG profile management, and init bootstrap.

## Responsibility

`internal/config` implements skeptic's config-first UX: auto-discovering `.skeptic.json|yaml|yml|env` and `skeptic.json|yaml|yml|env` files in the working directory (falling back to the active named profile under `$XDG_DATA_HOME/skeptic/profiles/`), parsing them into normalized key-value maps, applying preset defaults, and merging config values with CLI flags using explicit precedence rules. It manages two config layers: a system config (`system.json` for infrastructure settings) and named scan profiles (scan behavior). It also provides the `init`, `config show`, and `config use` subcommands.

## Public API

### Config Loading

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `DiscoverConfigPath` | `() (string, error)` | Finds first default config file in working directory. |
| `LoadConfigValues` | `(configPath string) (map[string]string, string, error)` | Loads and normalizes config from JSON/YAML/ENV. |
| `ApplyRunConfigValues` | `(raw *RunRawOptions, values map[string]string, visited map[string]struct{}) error` | Merges config into raw CLI options respecting flag precedence. |

### Format Parsers

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `ParseJSONConfigValues` | `(data []byte) (map[string]string, error)` | JSON object to config map. |
| `ParseYAMLConfigValues` | `(data []byte) (map[string]string, error)` | Simple/sectioned YAML to config map. |
| `ParseEnvConfigValues` | `(data []byte) (map[string]string, error)` | Dotenv to config map. |

### Presets and Modes

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `ParseScanPreset` | `(raw string) (ScanPreset, error)` | Validates `quick|dev|ci|hunt|machine-identity|ai-workload`. |
| `PresetValues` | `(preset ScanPreset) map[string]string` | Returns opinionated defaults for a preset. |
| `ModePresetValues` | `(mode model.ScanMode) map[string]string` | Returns mode-specific defaults (`--scan-style`, `--threat-mode`, `--fail-on`). Modes sit above presets in precedence. |

### Config Resolution

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `ResolveConfigLayers` | `(fs *flag.FlagSet, raw *RunRawOptions) (ResolvedConfig, error)` | Resolves mode, preset, config file, and system config into a `ResolvedConfig` with all layers applied in precedence order. |
| `DefaultConfigCandidates` | `var []string` | Default config file names tried during auto-discovery (`.skeptic.json`, `.skeptic.yaml`, `.skeptic.yml`, `.skeptic.env`, `skeptic.json`, `skeptic.yaml`, `skeptic.yml`, `skeptic.env`). |

### Helpers

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `NormalizeConfigKey` | `(raw string) string` | Aligns underscores, dots, `SKEPTIC_` prefix to dash-case. |
| `LookupConfigValue` | `(values, key, aliases...) (string, bool)` | Alias-aware config lookup. |
| `ParseFlexibleBool` | `(raw string) (bool, error)` | Accepts `true/false/yes/no/1/0/on/off`. |
| `VisitedFlagNames` | `(fs *flag.FlagSet) map[string]struct{}` | Captures explicitly-set CLI flags. |
| `FlagWasSet` | `(visited, name) bool` | Tests whether a specific flag was set. |
| `PrintFormattedFlags` | `(fs *flag.FlagSet, out io.Writer, shorthands map[string]string, skipNames map[string]bool)` | Renders formatted `--help` output for a `FlagSet` with shorthand aliases. Used by `daemon`, `ingest`, and `mcp` subcommands. |

### XDG Path Helpers

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `SkepticDataDir` | `() string` | Returns `$XDG_DATA_HOME/skeptic` (default `~/.local/share/skeptic`). |
| `SystemConfigPath` | `() string` | Returns path to `system.json`. |
| `ProfilesDir` | `() string` | Returns path to `profiles/` directory. |
| `ActiveProfileName` | `() (string, error)` | Reads the `active-profile` pointer file. |
| `ActiveProfilePath` | `() (string, error)` | Returns full path to the active named profile JSON. |
| `DaemonLogPath` | `() string` | Returns path to daemon log file. |
| `DaemonStderrPath` | `() string` | Returns path to daemon stderr file. |
| `DaemonReportPath` | `() string` | Returns path to daemon report file. |
| `DaemonTokenPath` | `() string` | Returns path to daemon token file. |

### System Config

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `LoadSystemConfig` | `(path string) (SystemConfig, string, error)` | Loads and parses `system.json`; returns defaults if missing. |
| `RenderSystemConfig` | `(sys SystemConfig) ([]byte, error)` | Serializes system config to JSON. |
| `DefaultSystemConfig` | `() SystemConfig` | Returns defaults derived from XDG data dir. |
| `IsSystemConfigKey` | `(key string) bool` | Reports whether a key belongs to system config. |

### Init and Config Subcommands

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `RunInit` | `(args, stdout, stderr) int` | `init` subcommand: bootstraps XDG directory and writes starter profile. |
| `RunInitConfig` | `(args, stdout, stderr) int` | Backward-compatible alias for `RunInit`. |
| `RenderInitConfig` | `(values map[string]any, format string) ([]byte, error)` | Serializes config for JSON/YAML/ENV formats. |
| `RunConfig` | `(args, stdout, stderr) int` | `config` parent subcommand dispatcher (`show`, `use`). |
| `RunConfigShow` | `(args, stdout, stderr) int` | `config show`: prints resolved configuration. |
| `RunConfigUse` | `(args, stdout, stderr) int` | `config use <name>`: sets the active named profile. |

### Types

| Type | Description |
|------|-------------|
| `RunRawOptions` | All raw CLI/config values before typed validation, including `ModeRaw`. Used as the bridge between flag parsing and scan execution. |
| `ScanPreset` | Named preset string type with `quick`, `dev`, `ci`, `hunt`, `machine-identity`, `ai-workload` constants. |
| `SystemConfig` | Infrastructure settings: cache dir, log dir, daemon bind, daemon token dir, default workers. |
| `ResolvedConfig` | Results of config layer resolution, including scan mode, preset, loaded paths, system config, and visited flags. |

## Internal Design

### Configuration Precedence

Resolution order (later wins): system config → mode defaults → preset overrides → scan config file values → explicit CLI flags. System config is loaded first for infrastructure settings. Then `ModePresetValues` is applied when `--mode` is set, then `PresetValues` if `--preset` is also given, then scan config file values, and finally any flags the user set explicitly on the command line.

### Waivers (`waivers`)

| Key | Type | Description |
|-----|------|-------------|
| `waivers` | string | Path to the waiver JSON file. When set in merged config (same key as CLI `--waivers`), the default scan loads and applies that file if present. |

`init` writes `.skeptic-waivers.json` beside the new config when that file does not already exist, and includes `waivers` pointing at it in the starter template.

**Waiver JSON schema (top-level):** `version` (int, ≥ 1); `waivers` (array of objects). Each waiver object may include: `rule_id`, `file_path`, `file_sha256`, `reason`, `expires_at`, `author`, `created_at` (RFC3339 strings for the timestamp fields; optional fields may be omitted).

## Dependencies

| Package | Why |
|---------|-----|
| `internal/model` | `ScanProfile`, `ScanStyle`, `ThreatMode`, `Severity`, `ScanMode` for preset/mode value maps |

## Test Surface

| File | Tests |
|------|-------|
| `config_test.go` | Behavior baseline/provenance mapping, flag precedence, discovery fallback, system config loading |
| `config_paths_test.go` | XDG path helpers, active profile resolution, system config key validation |
| `config_show_test.go` | Text/JSON output, system-only/profile-only filters, active profile annotation |
| `config_use_test.go` | Profile switching, missing profile error, dispatch routing |
| `init_test.go` | JSON output, validation, system.json bootstrap, XDG default path, backward-compatible alias |

```bash
go test ./internal/config -count=1
```

## Related Docs

- [CONFIGURATION.md](../CONFIGURATION.md) — user-facing config guide
- [cli module](cli.md) — `performSkepticRun` uses `ApplyRunConfigValues` for merge
- [ARCHITECTURE.md](../ARCHITECTURE.md) — config in dependency graph
