# completion

> Shell completion generation for bash, zsh, and fish with per-subcommand flag and value completion.

## Responsibility

`internal/completion` generates shell completion scripts for all skeptic subcommands, their flags, and enum values. Each shell gets subcommand-aware completion: bash uses `_init_completion` with subcommand detection, zsh uses `_arguments` with per-subcommand case blocks, and fish uses `__fish_seen_subcommand_from` guards. The package is stdlib-only with no intra-project dependencies.

## Public API

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `RunCompletion` | `(args, stdout, stderr) int` | `completion` subcommand: `skeptic completion <bash\|zsh\|fish>` |
| `GenerateBashCompletion` | `(w io.Writer)` | Writes bash completion script with subcommand detection and flag-value dispatch |
| `GenerateZshCompletion` | `(w io.Writer)` | Writes zsh completion script with per-subcommand `_arguments` blocks |
| `GenerateFishCompletion` | `(w io.Writer)` | Writes fish completion script with subcommand guards and flag annotations |

### Exported Variables

| Variable | Type | Contents |
|----------|------|----------|
| `Subcommands` | `[]string` | All 18 CLI subcommand names (scan, ingest, serve, daemon, mcp, init, init-config, config, corpus, waive, bundle, verify-bundle, export-evidence, sign-rulepack, gen-rule-keypair, verify-rulepack, completion, version) |
| `CorpusSubcommands` | `[]string` | `init`, `fetch`, `info`, `scan`, `purge` |
| `ConfigSubcommands` | `[]string` | `show`, `use` |
| `PresetNames` | `[]string` | `quick`, `dev`, `ci`, `hunt`, `machine-identity`, `ai-workload` |
| `FormatNames` | `[]string` | `text`, `json`, `sarif`, `markdown` |
| `ProfileNames` | `[]string` | `repo`, `developer`, `container`, `fullfs` |
| `ScanStyleNames` | `[]string` | `pattern`, `behavior`, `hybrid` |
| `ThreatModeNames` | `[]string` | `all`, `machine-identity`, `ai-workload` |
| `ModeNames` | `[]string` | `developer`, `ir`, `deep` |
| `SeverityNames` | `[]string` | `none`, `info`, `low`, `medium`, `high`, `critical` |
| `RuleQualityNames` | `[]string` | `off`, `warn`, `strict` |
| `IngestFormatNames` | `[]string` | `auto`, `stix`, `sigma`, `yara` |
| `InitFormatNames` | `[]string` | `json`, `yaml`, `env` |
| `ShellNames` | `[]string` | `bash`, `zsh`, `fish` |
| `CorpusInfoSortKeys` | `[]string` | `name`, `size`, `date`, `source-type` (plus `-` prefixed descending variants) |
| `CorpusSourceTypes` | `[]string` | `url`, `file` |

## Dependencies

None. stdlib-only.

## Test Surface

| File | Tests |
|------|-------|
| `completion_test.go` | Bash, zsh, fish generation (verify subcommands, flags, enum values), invalid shell, no args, `TestSubcommandsMatchesDispatch` |

```bash
go test ./internal/completion -count=1
```

## Related Docs

- [README.md](../../README.md) — install instructions including `make install-completions` and manual placement
- [ARCHITECTURE.md](../ARCHITECTURE.md) — module boundaries
