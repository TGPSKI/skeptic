# ingest

> Threat-intelligence ingestion: URL/file/directory sources to signed rule packs with STIX/Sigma/YARA adapters.

## Responsibility

`internal/ingest` converts threat intelligence content into external rule packs. It loads source material from URLs (with host allowlisting), local files, and directories; extracts indicators across 9 ecosystems (general, pypi, npm, go, cargo, container, mcp, agent-skills, github-actions); applies quality enforcement; and writes versioned `RulePack` JSON. It also includes feed adapters for STIX 2.1 bundles, Sigma rules, and YARA string patterns.

## Public API

### Entry Point

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `RunIngest` | `(ctx context.Context, args []string, stdout, stderr io.Writer) int` | CLI subcommand: converts threat intel into an external rule pack. |

### Source Loading

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `LoadSourceDocuments` | `(ctx context.Context, sources []string, opts SourceLoadOptions) ([]SourceDocument, []string, error)` | Resolves and loads mixed source types with bounds. |
| `ReadURLSource` | `(ctx context.Context, client *http.Client, rawURL string, maxBytes int64, allowHTTP bool, allowed map[string]struct{}) (string, error)` | Fetches URLs with host allowlisting and redirect control. |
| `ReadDirectorySource` | `(dir string, maxBytes int64, maxFiles int) ([]SourceDocument, []string)` | Recursive text-file ingestion from directories. |
| `ReadSourcesFile` | `(path string) ([]string, error)` | Parses newline-delimited source lists. |
| `ReadLocalFileLimited` | `(path string, maxBytes int64) (string, error)` | Bounded local file reads. |

### Rule Generation

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `NewGeneratedRuleCollector` | `(maxRules int, minSeverity model.Severity) *GeneratedRuleCollector` | De-dup-aware rule buffering. |
| `AddGeneralIOCLineRules` | `(c, line, risky, strongRisk, source string, lineNo int)` | Generic IOC extraction. |
| `AddGitHubActionRules` | ... | Workflow-focused indicators. |
| `AddPyPIRules` / `AddNpmRules` / `AddGoRules` / `AddCargoRules` / `AddContainerRules` / `AddMcpRules` / `AddAgentSkillRules` | ... | Ecosystem-specific indicator extraction. |
| `NewLiteralRule` | `(category, title, mitre string, severity model.Severity, value string, caseInsensitive bool) model.Rule` | Wraps literal values into safe regex patterns. |

### Feed Adapters

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `DetectFeedFormat` | `(explicit, content string) string` | Auto-detects `stix`, `sigma`, `yara`, or empty. |
| `ParseSTIXBundle` | `(data []byte) ([]model.Rule, error)` | STIX 2.1 indicator extraction with error handling. |
| `ParseSigmaRule` | `(data []byte) []model.Rule` | Sigma detection pattern extraction. |
| `ParseYARAStrings` | `(data []byte) []model.Rule` | YARA string pattern extraction. |

### Output

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `WriteRulePack` | `(outPath string, pack model.RulePack) error` | Writes rule pack JSON to disk. |
| `SummarizeRuleSpecs` | `(specs []model.RuleSpec) map[string]int` | Severity distribution summary. |

## Dependencies

| Package | Why |
|---------|-----|
| `internal/model` | `Rule`, `RulePack`, `RuleSpec`, `Severity` types; `LooksLikeText` for text file detection |
| `internal/config` | `PrintFormattedFlags` for `--help` output |
| `internal/rules` | `CompileRuleSpecs` for validation |
| `internal/logging` | Logger for verbose output |

## Test Surface

| File | Tests |
|------|-------|
| `ingest_helpers_test.go` | Source loading, rule builders, CSV parsing, write/summarize, validation |
| `feed_adapters_test.go` | STIX/Sigma/YARA format detection and parsing |
| `ingest_fuzz_test.go` | Fuzz: `ParseSTIXBundle`, `ParseSigmaRule`, `DetectFeedFormat` |

```bash
go test ./internal/ingest -count=1
```

## Related Docs

- [rules module](rules.md) — `CompileRuleSpecs` validates generated rules
- [mcp module](mcp.md) — `MCPIngestURLToRulepack` tool wraps `RunIngest`
- [SERVER.md](../SERVER.md) — ingest approval gates and MCP reference
