# AGENTS.md — skeptic

Instructions for AI agents and contributors working on this codebase.

## Identity

**skeptic** is a standalone, stdlib-only Go security scanner that detects supply chain compromise, agentic/LLM ecosystem poisoning, CI/CD weaponization, and machine-identity abuse. It ships as a single static binary with zero runtime dependencies.

## Threat Model Grounding

skeptic exists because the March 2026 TeamPCP campaign proved that **the structural trust boundary violations enabling cascading supply chain compromise are invisible to existing scanner categories**. CVE scanners find known vulnerabilities. SAST tools find code bugs. Secret scanners find leaked credentials. None of them detect that your GitHub Action uses a mutable tag, your workflow grants `pull_request_target` access to untrusted PR code, your CI service account has cross-ecosystem write permissions, or your MCP config passes credentials to an unvetted tool server.

The SANS report on the campaign concluded: *"The attack succeeded not because of exotic zero-day exploits, but because of well-understood misconfigurations and architectural weaknesses that defenders have known about for years."* skeptic targets those misconfigurations and architectural weaknesses.

### What skeptic detects (the gap between existing tools)

1. **CI/CD trust boundary violations** — mutable action refs, `pull_request_target` + unsafe checkout, over-permissioned service accounts, unpinned dependency installation, CI secret hygiene gaps
2. **Agentic ecosystem poisoning** — malicious SKILL.md directives, MCP tool shadowing, memory persistence injection, tool-output instruction injection, scanner suppression attempts
3. **Persistence and stealer artifact patterns** — systemd user services, Python `.pth` auto-exec, `/proc/*/mem` scraping, IMDS credential access, credential file sweep patterns
4. **Machine identity abuse** — over-privileged IAM roles, wildcard OIDC federation, static client secrets, broad token exchange flows
5. **Supply chain structural hygiene** — committed build caches, world-writable security artifacts, unsigned rule packs, dependency confusion indicators

### What skeptic does NOT try to be

- **Not a CVE/vulnerability scanner.** That is Trivy, Grype, osv-scanner. skeptic complements them.
- **Not a SAST tool.** No AST parsing, no dataflow taint tracking, no language-specific analysis.
- **Not a secrets scanner.** Gitleaks and trufflehog do this better. skeptic detects the *structural conditions* that lead to secret exposure, not the secrets themselves.
- **Not an EDR or runtime monitor.** skeptic scans files at rest. It finds persistence artifacts and configuration weaknesses, not active process behavior.
- **Not a malware signature database.** Campaign-specific IOC rules (`TPCP-*` and similar) ship in signed JSON under `rulepacks/campaigns/<campaign>/` for triage, but the primary value is the structural and behavioral detection layer that catches the *next* campaign, not just replaying indicators from the last one.

### Detection philosophy

Rules should detect **attack-enabling conditions**, not just attack artifacts. A rule for `pull_request_target` is more valuable than a rule for a specific malicious commit SHA, because the former catches the class of vulnerability while the latter catches one instance. Campaign IOC rules are useful for incident triage but should never be the majority of the ruleset.

When evaluating whether to add a detection: ask whether a different attacker group using a different C2 domain and different package names would still be caught. If the answer is no, the detection is an IOC, not a structural rule. Both have value, but structural rules are the priority.

## Hard Constraints

These are non-negotiable. Violating any of them is a build-breaking change.

1. **stdlib-only**: No third-party Go modules. Every import must resolve to the Go standard library. The `go.mod` file must never contain a `require` block. If you think you need an external dependency, implement the needed functionality using stdlib packages.
2. **Single binary**: Everything compiles to one `go build` output. No plugins, no shared libraries, no CGO.
3. **RE2 regex only**: Go's `regexp` package uses RE2 syntax. No lookaheads, no backreferences, no PCRE extensions. Every pattern must compile with `regexp.MustCompile`.
4. **No secrets in output**: `--redact-secrets` defaults to `true`. All findings that match secret-like content must pass through `security.SanitizeMatch` before being stored in a `Finding`.

## Module and Package Structure

```
go.mod                       # module skeptic (standalone root, Go 1.24)
CODEOWNERS                   # code ownership hints (optional)
action.yml                   # GitHub Actions composite action (reusable CI integration)
cmd/skeptic/                 # CLI entry point — package main
  main.go                    # CLI entry, subcommand dispatch, global flag extraction
  perform_skeptic_run.go     # default scan path: flag parsing, config/preset merge, enrichment
  profiling.go               # CPU/mem/trace profiling helpers (startProfiling, globalProfileAndStop)
  cli_helpers.go             # shared CLI utilities: format/policy parsing, report emission, path resolution, global-flag merging
  serve_cmd.go               # serve subcommand wiring (runServeGlobal, executeDaemonScanForServe)
  mcp.go                     # mcp subcommand wiring
  bundle_cmd.go              # bundle/verify-bundle subcommands
  export_evidence_cmd.go     # export-evidence subcommand
  corpus_cmd.go              # corpus subcommand dispatch (init/fetch/info/scan/purge)
  waive_cmd.go               # waive subcommand wiring (SHA256-pinned waiver creation)
  *_test.go                  # unit + integration tests (package main)
internal/
  model/                     # shared domain types (Severity, Finding, Rule, RuleSpec, RulePack, RuleTestCase, RuleTestPack, Report, ScanOptions, ConfidenceClass, ScanMode, RuleQualityMode, CompiledPattern, ScanLogger), file-type heuristics (filetypes.go)
  logging/                   # structured logger with verbosity levels (logging.go)
  security/                  # redaction, hashing, integrity helpers (security.go, selfcheck.go)
  rules/                     # built-in rules (229), rulepack loading, quality validation; rule groups: rules_agentic_surfaces.go, rules_attack_tactics.go, rules_behavioral_signals.go, rules_identity_exposure.go, rules_non_code_surfaces.go; core composition: rules_core.go; signing: signatures.go; quality: rule_quality.go; test runner: rulepack_test_runner.go; rulepack loader: rulepacks.go; campaign packs under rulepacks/campaigns/<campaign>/; signing material in rulepacks/signing
  config/                    # config file loading (config.go), presets (presets.go), init (init.go), config show (config_show.go), config use (config_use.go), flag help formatting (flaghelp.go), system config, XDG profile management
  checks/                    # behavior_checks, dep_checks, domain_checks (structural domain typosquat: DOM-TYPO-*), focus_checks, graph (graph.go, graph_azure.go, graph_gcp.go, graph_rbac.go), policy_checks
  scan/                      # scan engine (engine.go, worker.go, walker.go), payload decoders (decoders.go), incremental cache (incremental.go), pre-filter (prefilter.go), NFKC normalization (normalize.go), risk scoring (risk_score.go), tool exemptions (tool_exemptions.go), threat-mode filter (filter.go), entropy anomaly detection (entropy.go), XOR brute-force decoder (xor_decoder.go), polyglot detection (polyglot.go)
  correlation/               # cross-finding correlation (correlation.go), drift detection (drift.go), temporal/git correlation (temporal.go)
  enrich/                    # post-scan enrichment pipeline (enrich.go): dep checks, identity graph, provenance, MCP, drift, git correlation
  ingest/                    # threat-intel ingestion: feed adapters (feed_adapters.go), rule generators (generators.go), source loading (sources.go), orchestration (ingest.go); formats: STIX, Sigma, YARA, URL
  report/                    # SARIF (sarif.go), markdown (markdown.go), text (text.go) output; baseline (baseline.go), evidence export (export_evidence.go), bundles (bundle.go)
  provenance/                # dependency provenance hash verification (provenance.go), SBOM cross-referencing (sbom.go)
  completion/                # shell completion generation (completion.go)
  daemon/                    # HTTP daemon + scheduler (daemon.go), API client (client.go)
  mcp/                       # MCP JSON-RPC server (mcp.go, mcp_tools.go, mcp_ingest.go, mcp_auto_daemon.go), MCP config discovery (discovery.go)
  suppress/                  # waiver-based finding suppression (suppress.go), interactive waiver creation (waive.go)
  corpus/                    # encrypted-at-rest .md corpus for agentic rule validation (crypto.go, safety.go, manifest.go, fetch.go, corpus.go, scan.go)
```

### Dependency Direction

Dependencies flow **downward only**. Never import a higher-level package from a lower-level one.

```
cmd/skeptic          →  internal/* (config, completion, ingest, model, rules, scan, suppress, and transitively others)
internal/scan        →  internal/model, internal/security, internal/logging, internal/checks, internal/correlation
internal/daemon      →  internal/model, internal/config, internal/logging
internal/mcp         →  internal/model, internal/daemon, internal/security, internal/config, internal/logging, internal/suppress
internal/checks      →  internal/model, internal/security
internal/rules       →  internal/model, internal/security, internal/logging
internal/ingest      →  internal/model, internal/config, internal/rules, internal/logging
internal/report      →  internal/model
internal/config      →  internal/model
internal/correlation →  internal/model
internal/enrich      →  internal/model, internal/checks, internal/correlation, internal/mcp, internal/provenance, internal/logging
internal/provenance  →  internal/model, internal/security, internal/checks
internal/suppress    →  internal/model, internal/security
internal/corpus      →  internal/model, internal/security, internal/scan, internal/rules, internal/logging
internal/logging     →  internal/model
internal/completion  →  (stdlib only)
internal/model       →  (stdlib only, zero intra-project imports)
internal/security    →  (stdlib only)
```

**Circular dependencies are forbidden.** When `cmd/skeptic/main.go` needs to pass its scan function to `daemon` or `mcp`, use callback function parameters (e.g., `daemon.ScanFunc`, `mcp.Options.RunScan`), not direct imports of `main`.

### Model: key types, confidence, and operating mode

**Core types in `internal/model/`:**

| Type | Kind | Purpose |
|------|------|---------|
| `Severity` | string enum | `info`, `low`, `medium`, `high`, `critical` |
| `PolicyLevel` | string enum | `none`, `low`, `medium`, `high`, `critical` |
| `OutputFormat` | string enum | `text`, `json`, `sarif`, `markdown` |
| `ConfidenceClass` | string enum | `definitive`, `heuristic`, `correlated` |
| `ScanMode` | string enum | `developer`, `ir`, `deep` |
| `ScanStyle` | string enum | `pattern`, `behavior`, `focus`, `policy` |
| `ThreatMode` | string enum | `all`, `machine-identity`, `agentic`, `ci-cd`, `supply-chain` |
| `RuleQualityMode` | string enum | `off`, `warn`, `strict` |
| `RuleTarget` | string enum | File-type targeting for rules |
| `ScanProfile` | string enum | Preset profile names |
| `Rule` | struct | ID, pattern, severity, metadata, file targeting |
| `RuleSpec` | struct | Serializable rule definition (JSON rule packs) |
| `RulePack` | struct | Collection of RuleSpecs with metadata |
| `Finding` | struct | Match result with file, line, rule, confidence |
| `Report` | struct | Scan results: findings, stats, mode, timing |
| `ScanOptions` | struct | All scan configuration: paths, rules, workers, limits |
| `RuleTestCase` | struct | Expected match/no-match for a rule |
| `RuleTestPack` | struct | Collection of test cases for a rule pack |
| `CompiledPattern` | interface | Abstraction over compiled regex patterns |
| `ScanLogger` | interface | Structured logging during scans |

**Confidence and mode system:**

- **`ConfidenceClass`** — `definitive`, `heuristic`, or `correlated`; stored on each `Finding` (and optional override on `Rule`). Default derivation: `DefaultConfidenceForRuleID(ruleID)` from rule ID prefix (wedge/structural prefixes → definitive, `COR-`/`DRIFT-` → correlated, else heuristic).
- **`ScanMode`** — `developer` (default), `ir`, or `deep`; carried on `ScanOptions.Mode` and `Report.Mode`. Modes apply before presets in config resolution (`ModePresetValues`).
- **`DefaultConfidenceForRuleID`** — maps a rule ID to a default `ConfidenceClass` for rules that do not set an override.
- **`IsGateEligible(ruleID, mode)`** — in `developer` mode, only wedge-family prefixes can contribute to `--fail-on` exit-code gating; `ir` and `deep` treat gating as non-eligible for failure (advisory).
- **`FilterFindingsByMode`** — presentation filter after detection: in `developer`, show definitive + correlated at all severities, heuristic only at critical; `ir`/`deep` show all.
- **`FilterFindingsByThreatMode`** — filters findings by threat domain when `--threat-mode` is not `all`.
- **`internal/mcp.BuildTrustAssessment`** — exported helper building the `trust_assessment` object for MCP (`verdict`, counts, `risk_areas`, `review_priority`).

### Type Aliases in `main.go`

`cmd/skeptic/main.go` uses a single type alias (`type runRawOptions = configpkg.RunRawOptions`) to bridge the config package into `package main`. The former `model_aliases.go` file has been removed. When `cmd/skeptic/` code needs an internal type, prefer direct qualified imports (e.g., `configpkg.RunRawOptions`, `model.Finding`).

## Code Style

### Formatting and Linting

- Run `go fmt ./...` before every commit
- Run `go vet ./...` — must pass with zero warnings
- Run `make lint` (`golangci-lint`) — must pass with zero issues
- Target: no function exceeds 200 lines. Break large functions into named helpers.

### Naming

- Exported functions in `internal/` use PascalCase: `RunCorrelation`, `BuildRuleSet`
- Package-internal helpers use camelCase: `matchesAllPatterns`, `extractRuleIDs`
- Test files: `<package>_test.go` colocated in the same directory as the code they test
- Rule IDs follow the prefix conventions in `CONTRIBUTING.md` (e.g., `AGT-SKL-001`, `BHV-SUPPLY-001`, `CI-PRT-001`, `ATK-IMDS-001`)

### Error Handling

Two patterns, used consistently by layer:

| Layer | Pattern | Example |
|-------|---------|---------|
| `internal/` library functions | Return `(T, error)` | `func LoadConfig(path string) (Config, error)` |
| CLI entry points (called from `main.go`) | Return `int` exit code, print to stderr | `func RunIngest(...) int` |

Never mix: a function should not both print to stderr AND return an error.

### Comments

- Every exported function and type in `internal/` gets a doc comment
- Comments explain **why**, not **what** — do not narrate obvious code
- No `// TODO` without a tracking issue or plan reference

## Testing Requirements

### Every PR Must

1. **Not break existing tests**: `go test ./...` must pass
2. **Not break integration tests**: `go test -tags=integration ./cmd/skeptic/` must pass
3. **Not break vet**: `go vet ./...` must produce zero output
4. **Not break lint**: `make lint` must pass with zero issues
5. **Add tests for new code**: every new exported function gets at least one test

### Test Organization

| Test type | Location | Build tag | Runner |
|-----------|----------|-----------|--------|
| Unit tests | Same package as code (`internal/<pkg>/<pkg>_test.go` or `cmd/skeptic/*_test.go`) | none | `make test` |
| Integration tests | `cmd/skeptic/integration_*_test.go` (daemon, scan, perf, pipeline, corpus, helpers) | `integration` | `make integration` |
| Benchmarks | `cmd/skeptic/bench_test.go` | none | `make bench` |

### Colocated Internal Tests

Each `internal/` package should have its own `_test.go`. Do not rely solely on `cmd/skeptic/` tests to cover internal logic. When migrating or adding features to `internal/`, add colocated tests that:

- Test the exported API of that package in isolation
- Use `t.TempDir()` for filesystem fixtures (never write to working directory)
- Use table-driven tests for functions with multiple input/output cases
- Test both success and error paths

### Integration Tests

Integration tests in `integration_daemon_test.go`, `integration_scan_test.go`, `integration_perf_test.go`, `integration_pipeline_test.go`, `integration_corpus_test.go`, and `integration_helpers_test.go` use the `integration` build tag and test process-level behavior:

- Daemon startup, HTTP API, scheduled scans
- MCP JSON-RPC protocol, tool invocation, approval gates
- Performance characteristics (incremental cache, worker scaling)
- Large-corpus correctness
- Encrypted corpus init/fetch/scan/purge lifecycle

When adding a new user-facing feature (subcommand, flag, scan mode), add or extend an integration test that exercises it end-to-end.

### Race Detection

All tests must pass under `-race`. The CI runs `go test -race ./...`. Shared mutable state must be protected by `sync.Mutex`, `sync.RWMutex`, or channels. Never use package-level mutable variables without synchronization.

## Performance Expectations

- **File scanning**: worker pool with configurable concurrency (`--workers`, defaults to `runtime.NumCPU()`)
- **Large files**: skip files exceeding `--max-bytes` (default 2MB)
- **Incremental cache**: mtime + size check, SHA256 fallback when size matches but mtime differs, ruleset hash invalidation
- **Regex compilation**: compile patterns once at startup, not per-file
- **Memory**: streaming reads via `bufio.Scanner`, bounded result channels, no full-file `[]byte` retention after scanning

When adding new scan-time logic (checks, decoders, correlations), consider the per-file cost. If it requires reading the full file content, gate it behind a flag or scan style.

## Security Model

### Scanner Hardening

skeptic scans for threats — it must not become one.

- All external input (URLs, file paths, rule packs) is validated before use
- URL fetching respects `--allow-host` allowlists; default is deny-all for ingest
- Rule packs support Ed25519 detached signature verification
- The daemon binds to loopback by default with token authentication
- MCP tools are allowlisted; `--mcp-allowed-roots` restricts filesystem access
- Symlinks are resolved with `filepath.EvalSymlinks` before path prefix checks
- World-writable sensitive artifacts generate scanner-protection findings

### Secrets in Tests

- Never commit real API keys, tokens, or credentials in test fixtures
- Use obviously fake values: `AKIA_FAKE_TEST_KEY`, `ghp_FAKE000000000000000`
- Test redaction by asserting that output contains `[REDACTED]`, not the original secret

## Adding New Rules

See `CONTRIBUTING.md` for the full rule contribution workflow. Summary:

1. Add `Rule` struct to the appropriate group file in `internal/rules/` (see `docs/RULESET_GROUPING.md`)
2. Follow ID prefix conventions
3. Use RE2-compatible regex
4. Add a test fixture proving the pattern matches expected content and does not match benign content
5. Run `make validate-rules && make test`

## Adding New Internal Packages

If a new logical domain emerges that doesn't fit existing packages:

1. Create `internal/<name>/` with a single `.go` file
2. The package must depend only on `internal/model`, `internal/security`, `internal/logging`, or stdlib
3. Add a `_test.go` in the same directory with meaningful coverage
4. Wire it into `cmd/skeptic/` via `main.go` or a dedicated `_cmd.go` file
5. Update `docs/ARCHITECTURE.md` with the new package and its dependency relationships
6. Update `docs/modules/<name>.md` with the module documentation template

## Subcommands and CLI Flags

Subcommand dispatch happens in `main.go` `run()`. The full subcommand list:

| Subcommand | Handler | Purpose |
|------------|---------|---------|
| `scan` | `performSkepticRun` | Scan files for threats (also the default when no subcommand) |
| `init` / `init-config` | `configpkg.RunInit` | Bootstrap config files and XDG data directory |
| `config` | `configpkg.RunConfig` | Print resolved config (`config show`) or set profile (`config use`) |
| `serve` / `daemon` | `runServeGlobal` | Run local daemon scheduler and API |
| `mcp` | `runMCPGlobal` | Run local MCP JSON-RPC server bridge |
| `ingest` | `runIngestGlobal` | Generate rule packs from threat intel feeds |
| `corpus` | `runCorpusGlobal` | Manage encrypted threat artifact corpus (init/fetch/info/scan/purge) |
| `waive` | `runWaiveGlobal` | Create SHA256-pinned waivers for findings |
| `bundle` | `runBundleGlobal` | Package binary + rules for distribution |
| `verify-bundle` | `runVerifyBundleGlobal` | Verify a bundle's integrity and signatures |
| `export-evidence` | `runExportEvidenceGlobal` | Export scan findings as signed evidence bundle |
| `sign-rulepack` | `rules.RunSignRulepack` | Sign external rule packs with Ed25519 |
| `gen-rule-keypair` | `rules.RunGenRulepackKeypair` | Generate Ed25519 key pair for rule signing |
| `verify-rulepack` | `rules.RunVerifyRulepack` | Verify a signed rule pack |
| `completion` | `completion.RunCompletion` | Generate shell completions (bash/zsh/fish) |
| `version` | `runVersion` | Print version, commit, Go version, rule count |

Each subcommand should:

1. Define its own `flag.FlagSet`
2. Parse args from `os.Args[2:]` (or the appropriate slice)
3. Call into `internal/` for all logic
4. Return an `int` exit code

When adding flags:

- Use `--kebab-case` naming
- Provide sensible defaults documented in the flag description
- Register the flag in the relevant preset if applicable (see `internal/config/`)
- Add the flag to `docs/CONFIGURATION.md` if user-facing

## What NOT To Do

- **Do not add external dependencies.** Not even "small" ones. Implement what you need.
- **Do not put business logic in `main.go`.** It should dispatch to `internal/` packages.
- **Do not write to the working directory in tests.** Use `t.TempDir()`.
- **Do not skip error returns.** Every `error` must be checked.
- **Do not use `os.Exit()` in library code.** Only `main()` and direct subcommand handlers may exit.
- **Do not use `init()` functions.** Explicit initialization only.
- **Do not store compiled regexes in package-level `var` without `sync.Once` or compile-time `MustCompile`.** Lazy compilation without synchronization is a data race.
- **Do not add type alias files.** Prefer direct qualified imports in `main.go` (e.g., `configpkg.RunRawOptions`).
- **Do not commit generated files** (coverage.out, bench-results.txt, bin/) — they are in `.gitignore`.
- **Do not use PCRE features in regex patterns.** Go uses RE2. No `(?<=...)`, `(?!...)`, or backreferences. Note: `\b` word boundaries **are** supported by Go's RE2 implementation.

## Design Principles

These are non-negotiable and apply to all current and future work:

- **stdlib-only.** No upstream Go dependencies. The binary's supply chain is the Go compiler and standard library.
- **Single binary.** Scanner, daemon, MCP server, ingest, signing -- one `go build` output.
- **Offline-first.** Network access is never required for scanning. Ingest and daemon are opt-in.
- **Deterministic.** Same rules + same files = same findings. No LLM inference, no probabilistic analysis.
- **Complementary.** skeptic is not a replacement for Trivy, Semgrep, or Snyk. It covers the gap between them.

## Build and Verify

```bash
make fmt           # format
go vet ./...       # vet
make lint          # golangci-lint
make test          # unit tests
make integration   # integration tests
make bench         # benchmarks
make build         # compile binary
```

All seven must pass before any code is considered complete.

## GitHub Actions Integration

The repository includes a reusable composite action (`action.yml`) that runs skeptic scans in CI. Key design points:

- Builds from source using `actions/setup-go` and `go build` with ldflags for commit/date/version injection
- Supports all output formats (`sarif`, `json`, `text`, `markdown`) via the `format` input
- Separates stderr from stdout to prevent log messages from contaminating structured output
- Uses unique result file paths (`$(date +%s)-$$` suffix) to avoid conflicts in matrix builds
- Artifact names include format and fail-on level for uniqueness (`skeptic-results-{format}-{fail-on}`)
- Exit code 3 indicates policy threshold exceeded (not a scan error)
- All action refs are SHA-pinned with version comments

## Agent Skills

Skills under `.agents/skills/` provide structured automation workflows:

| Skill | Purpose |
|-------|---------|
| `cli-flag-review` | Audit CLI flag definitions, help text, config-precedence safety |
| `doc-accuracy-audit` | Verify documentation claims against codebase, tighten prose |
| `documentation-lifecycle` | Generate/update per-module docs, architecture docs, Mermaid diagrams |
| `go-release` | Manage Go module release lifecycle: changelog, tagging, pkg.go.dev verification |
| `ruleset-lifecycle-operations` | Add/update rules, manage groups, migrate rules across groups |
| `threat-rules-ingestion` | Ingest security research into signed scanner rule packs |
| `workflow-action-updates` | Audit and update GitHub Actions to latest SHA-pinned versions |

## Reference Documents

| Document | Purpose |
|----------|---------|
| `CONTRIBUTING.md` | Rule IDs, quality gates, contribution workflow |
| `docs/ARCHITECTURE.md` | Module boundaries and operating model |
| `docs/CONFIGURATION.md` | Config file formats and auto-discovery |
| `docs/SERVER.md` | Daemon and MCP server reference |
| `docs/RUNTIME_SAFETY.md` | Deployment safety by runtime environment |
| `docs/CORPUS.md` | Encrypted corpus architecture and CLI reference |
| `docs/GITHUB_ACTION.md` | Composite action usage, inputs, and examples |
| `docs/RULESET_GROUPING.md` | Rule group file organization and naming |
| `docs/RULESET_SOURCES.md` | Threat intel sources and research references |
| `docs/modules/*.md` | Per-package detailed documentation (18 modules) |
| `.agents/README.md` | Agent skill index |
