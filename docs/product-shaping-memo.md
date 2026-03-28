# Product Shaping Memo

## Round 4 — 2026-04-05

### What changed

This round added 46 built-in rules (183 → 229), shipped the GitHub Actions composite action, restructured the CLI entry point into focused files, expanded the proof corpus from 28 to 34 directories, added CI build/environment/dependency-bot detection coverage, enriched the MCP tool surface, migrated linting to golangci-lint v2, and swept all documentation for accuracy. A follow-up weakness resolution pass fixed 8 correctness and coverage issues, added ~540 test lines, and introduced LiteralHint quality enforcement and trust assessment shape testing.

### Rule expansion: CI, dependency-bot, and infrastructure policy

The built-in rule count grew from 183 to 229 across three detection domains that were previously thin:

**CI build and environment hygiene (19 rules).** `CI-BUILD-001`–`009` detect build pipeline anti-patterns: running builds as root, disabling TLS verification, hardcoded credentials in build scripts, unverified downloads in Dockerfiles, dynamic script execution in workflows, missing branch protection, manual approval bypass, and PR auto-merge without review gates. `CI-ENV-001`–`008` detect environment variable exposure patterns: `env` dumps in CI steps, verbose tracing with secrets, `printenv` in workflows, JWT private keys in repos, and session token exposure. `CI-GOV-001`–`004` detect governance gaps: missing CODEOWNERS, missing branch protection rules, and repository settings that disable required reviews.

**Dependency-bot attack surface (9 rules).** `CI-DEPBOT-001`–`009` detect risky dependency bot configurations in both Renovate and GitHub Dependabot: `automerge: true` without adequate version pinning or release-age gates, overly broad `packageRules` match patterns, `rangeStrategy: bump` combined with automerge, missing `minimumReleaseAge`, `prCreation: immediate` without approval requirements, Dependabot configs with no reviewers or assignees (CI-DEPBOT-008), and Dependabot `allow` blocks that accept all dependency types (CI-DEPBOT-009). These target the attack pattern where an adversary publishes a malicious package update that bots auto-merge before human review.

**Infrastructure policy (3 rules).** `POL-ARGO-001` detects ArgoCD `automated` sync without `selfHeal: false`. `POL-TF-001` detects Terraform backends without state encryption. `DEP-TOOL-001` detects `eval` usage in shell scripts invoked by CI.

**Dependency lockfile integrity (4 findings).** `dep_checks.go` gained `CheckNPMLockfileIntegrity` (emitting `DEP-LOCK-001` for missing integrity hashes and `DEP-LOCK-002` for non-default registry hosts) and `CheckMissingLockfile` (emitting `DEP-LOCK-003`/`004` when a manifest exists without a corresponding lockfile).

**Other rule additions.** `AGT-MCP-015`–`020` expand MCP abuse coverage. `AGT-ART-010`/`011` and `AGT-SKL-002`/`017` add agentic artifact and skill patterns. `BHV-EVAL-001` detects eval-based code execution.

### Behavior chain: dependency-bot attack sequence

`BHV-DEPBOT-001` is a new multi-step behavior chain detecting the dependency-bot → auto-merge → install-hook attack pipeline. It fires when Renovate automerge configuration co-occurs with mutable `rangeStrategy` and no `minimumReleaseAge` gate. `BehaviorChainSpec` also gained an optional `ExcludePathPattern` field so chains can skip known-safe paths.

### Correlation: COR-006

`COR-006` is a new repo-level correlation spec linking dependency-bot misconfigurations (`CI-DEPBOT-001`) with supply-chain install-hook indicators (`SCM-PKG-003`, `DEP-004`, `RUGPULL-003`). It bypasses the confidence-diversity gate since both sides of the pattern may be heuristic.

### GitHub Actions composite action

`action.yml` (189 lines) ships skeptic as a reusable GitHub Action. It builds from source, runs scans in any output format, uploads results as artifacts, and supports SARIF upload for GitHub Code Scanning integration. `docs/GITHUB_ACTION.md` is the user-facing reference. `.github/workflows/action-integration-test.yml` exercises the action against the repo itself.

Design points: stderr is separated from stdout to prevent log contamination of structured output. Artifact names include format and fail-on level for matrix-build uniqueness. Exit code 3 (policy threshold exceeded) is distinguished from exit code 1 (scan error).

### CLI restructuring

`main.go` was split from ~470 lines to 260, with three focused files extracted:

- `cli_helpers.go` (166 lines): format/policy parsing, report emission, path resolution, global flag merging, version output
- `profiling.go` (128 lines): CPU/mem/trace profiling lifecycle
- `serve_cmd.go` (57 lines): `serve`/`daemon` subcommand wiring

The default path handling now treats unrecognized tokens that look like filesystem paths as implicit scan targets, improving the "just run `skeptic .`" UX without requiring explicit `scan` subcommand.

### MCP enrichment

The MCP tool surface gained several improvements:

- `skeptic_scan_repo` accepts `preset`, `profile`, `include_rules`, `exclude_rules`, `workers`, `incremental`, `baseline`, `diff_only` parameters. Response now includes `risk_score`, `mode`, and sample findings with count/note.
- `skeptic_daemon_report` accepts `top` and `min_severity` for bounded queries.
- New tool `skeptic_daemon_metrics` exposes Prometheus-format daemon metrics.
- New resource `skeptic://config/active` returns resolved configuration.
- `skeptic://report/latest` prefers durable on-disk reports and caps summary output.

### Proof corpus expansion: 28 → 34 directories

Six new proof directories exercise the round's new detection coverage:

| Directory | Purpose |
|-----------|---------|
| `agentic-mcp-creds` | MCP configs with embedded credentials |
| `ci-build-hygiene` | Root builds, TLS disable, unverified downloads |
| `ci-depbot-config` | Risky Renovate automerge + missing release-age gates |
| `ci-env-exposure` | Environment variable dumps, JWT keys in repos |
| `depbot-ci-attack-chain` | Combined dependency-bot + install-hook attack sequence |
| `infra-policy` | ArgoCD auto-sync, Terraform unencrypted state |

### Linting: golangci-lint v2 migration

`.golangci.yml` was migrated to v2 config format. `errcheck` exclusions were added for `fmt.Fprint*` functions that are intentionally unchecked in report output. `make lint` uses the new config.

### Documentation sweep

All 18 module docs were audited against code. Fragile claims (test counts, line counts, fixture counts) were removed from Test Surface tables across every module doc and `ARCHITECTURE.md` — these drifted on every PR and added maintenance burden without helping contributors. Substantive factual corrections were applied where docs had drifted from code (phantom exports, wrong finding ID descriptions, missing dependencies, incorrect Mermaid diagrams).

### Agent skills

- **Added:** `workflow-action-updates` — audits GitHub Actions workflow files for outdated action references and upgrades to SHA-pinned latest versions
- **Added:** `doc-accuracy-audit` — verifies documentation claims against code and tightens prose
- **Updated:** `documentation-lifecycle` — refined scope

### Codebase metrics

| Metric | Round 3 | Round 4 | Delta |
|--------|---------|---------|-------|
| Tracked files | 344 | 379 | +35 |
| Go source lines | 23,235 | 25,823 | +2,588 |
| Go test lines | 16,537 | 20,187 | +3,650 |
| Built-in rules | 183 | 229 | +46 |
| Internal packages | 18 | 18 | — |
| CLI subcommands | 18 | 18 | — |
| Proof corpus dirs | 28 | 34 | +6 |
| All tests pass | yes | yes | — |

### What was fixed since the initial round-4 assessment

Eight of the ten weaknesses identified in the initial assessment were resolved in a follow-up pass:

1. **BuildTrustAssessment mode threading.** `BuildTrustAssessment` now reads `report.Mode`; IR/deep mode bypasses gate-eligibility filtering so non-wedge definitive findings surface in verdicts. Three mode-sensitive tests added to `mcp_test.go`.
2. **AGT-SKL confidence overrides.** Six rules (003, 004, 007, 013, 015, 017) promoted to `ConfidenceClass: definitive` — structurally unambiguous patterns with no legitimate benign use. Ten rules kept heuristic where ambiguity exists.
3. **CI-DEPBOT Dependabot coverage.** All nine CI-DEPBOT PathPatterns now match `.github/dependabot.yml` alongside Renovate paths. Two new Dependabot-specific rules added (CI-DEPBOT-008: no reviewers, CI-DEPBOT-009: allows all dependency types). Proof fixture created.
4. **dep_checks error handling and tests.** `CheckNPMLockfileIntegrity` emits `DEP-LOCK-ERR` on parse failure instead of silent nil. `CheckMissingLockfile` propagates walk errors as informational findings. Table-driven tests cover both functions.
5. **Trust assessment shape contract.** `TestTrustAssessmentShape` validates all top-level keys and nested structure of `BuildTrustAssessment` output. `BuildTrustAssessment` now emits structured `review_priority` objects (with `file`, `score`, `reasons`) and `risk_score`.
6. **Integration tests for new rule families.** `TestIntegrationNewRuleFamilies` exercises CI-BUILD, CI-DEPBOT, CI-ENV, and POL families through the full scan pipeline with the integration build tag.
7. **MCP parameter validation tests.** `TestMCPScanRepoParams` covers `include_rules`, `exclude_rules`, `workers=0`, invalid preset, and nonexistent baseline — all handled gracefully.
8. **LiteralHint quality enforcement.** `TestLiteralHintQuality` asserts all content rules have hints ≥ 3 chars. ~99 rules received fallback hints via a centralized map in `rules_literal_hint_fallbacks.go`. ~38 rules exempted where no single 3-char substring can appear on every match.

Two items were deliberately excluded: CI-BUILD-002/CI-ENV-004 path constraints (broad matching is intentionally adversarial-aware for these patterns) and GitHub Action pre-built binary (deferred to a release distribution round).

### What was fixed since the second round-4 assessment

Three more weaknesses from the "what's weak now" list were resolved:

9. **`EnrichReport` nil-logger guard and history logging.** `EnrichReport` now accepts nil logger gracefully (substitutes a no-op discard logger). `enrichBehaviorHistory` logs `LoadProfileHistory` failures at WARN level instead of silently replacing with empty history. 10 test functions in `enrich_test.go` (up from 8) cover all nil-logger code paths plus a dedicated test that asserts the warning is emitted on corrupt history files.
10. **Integration tests for `ingest`, `bundle`, `export-evidence`, and `deep` mode.** New file `integration_subcommands_test.go` adds 5 integration tests: `TestIntegrationBundle` (unsigned bundle creation, tar member validation, manifest field verification), `TestIntegrationBundleSignVerify` (Ed25519 sign/verify round-trip, wrong-key rejection), `TestIntegrationExportEvidence` (scan-to-evidence pipeline, tar member validation, findings count consistency), `TestIntegrationIngest` (STIX source to rulepack generation), `TestIntegrationDeepMode` (deep vs developer mode filtering, report.Mode field, finding superset assertion).
11. **Expanded unit tests for thin packages.** `rules_core_test.go`: 7 test functions (up from 2) — ID uniqueness, field integrity, pattern compilation, group ordering, literal hint extraction. `rules_attack_tactics_test.go`: 4 test functions (up from 1) — positive pattern matching across 10 rules, false positive resistance, field validation (Mitre, category, severity). `entropy_test.go`: 5 test functions (up from 1) — edge cases (empty, single-byte, uniform, all-random), parameter defaults, window merging, `ShannonEntropy` known values. `xor_decoder_test.go`: 5 test functions (up from 1) — edge cases (empty, nil, low-entropy), all-key coverage (key=0xFF), `LooksLikeText` gating, hint matcher rejection. The memo's claim that `internal/ingest` has "no focused `ingest_test.go`" was incorrect: it has 27 test functions across 3 files.

### What's weak now

**Daemon `filterReportForResponse` mutates shared findings slice.** `Report()` returns a copy of the `model.Report` struct, but the `Findings` slice still aliases the backing array of `lastReport.Findings`. When `/report` is called with `sort` or `top` parameters, `filterReportForResponse` calls `sort.Slice` in place, reordering findings for all future readers. Concurrent `/report` and `/metrics` requests can race on the same backing array. No test calls `filterReportForResponse` directly or asserts that stored findings order is preserved after an HTTP query.

**MCP protocol: no JSON-RPC error for malformed requests.** In `mcp.go`, if a frame parses as JSON but fails to decode into an `MCPRequest`, the read loop continues without emitting a JSON-RPC error response. For any request that included an `id` field, the client will never receive an error or result — this is a protocol-level hang.

**`mcpToolSuccess` swallows marshal errors.** When `json.MarshalIndent` fails in `mcpToolSuccess`, the function substitutes `"{}"` and returns `isError: false`. A tool that produces un-marshalable results silently returns empty success instead of an error.

**Correlation comment/code mismatch.** `ContentHashFindings` in `correlation.go` comments say emission requires "three or more distinct files," but the condition is `len(g.files) < 4`, requiring at least four. The comment is wrong, or the threshold is wrong — either way it's not tested.

**SARIF `informationUri` and path format.** SARIF output sets `informationUri` to a hardcoded GitHub URL that may not match the actual project. `artifactLocation.uri` uses plain filesystem paths instead of `file:///` URIs, which SARIF consumers may interpret inconsistently. No test asserts URI format.

**Four CI/GOV rules lack path constraints.** CI-BUILD-002 (`--build-arg` with secrets), CI-ENV-004 (`source <(curl …)`), CI-GOV-002 (`gh pr merge --auto`), and CI-GOV-004 (`gh pr merge --admin`) have no `PathPattern`. These patterns can match documentation, runbooks, or unrelated markdown — not just CI files and scripts. CI-BUILD-002 and CI-ENV-004 were previously noted; CI-GOV-002 and CI-GOV-004 are newly identified.

**GitHub-centric CI rule bias.** Most CI-ENV and CI-GOV rules are scoped to `.github/workflows/*.yml`. Similar issues in GitLab CI (`.gitlab-ci.yml`), Jenkins (`Jenkinsfile`, shared libs), CircleCI, and Buildkite are structurally under-covered. The rules detect GitHub-specific patterns but not equivalent misconfigurations in other CI systems.

**No Windows CI.** The CI matrix runs on Ubuntu and macOS only. Path handling, line endings, and symlink behavior on Windows are untested.

### Priorities

1. **Fix daemon findings slice aliasing.** `filterReportForResponse` must copy the slice before sorting or filtering. Add a test that verifies stored findings order is preserved after an HTTP `/report` query.
2. **Fix MCP malformed-request protocol hang.** Emit a JSON-RPC error response when a frame has an `id` but fails to decode, instead of silently continuing.
3. **Fix correlation comment/code mismatch.** Either update the comment to say "four or more" or change the threshold to `< 3`. Add a test that pins the threshold.
4. **Extend CI rules beyond GitHub Actions.** Add PathPattern coverage for GitLab CI and Jenkinsfile where existing patterns translate directly.

---

## Round 3 — 2026-04-02

### What changed

This round added the corpus subsystem, overhauled config management into a layered profile system, swept CLI flag consistency across all subcommands, externalized campaign rules to signed rulepacks, and added the `internal/corpus` package — the largest single-round package addition to date. The codebase grew from ~280 tracked files to 344, with source lines reaching 23k and test lines reaching 16.5k.

### Corpus subsystem: encrypted malware sample management

The headline feature is `skeptic corpus` — a complete lifecycle for curating, encrypting, scanning, and annotating malicious agentic directive samples. This addresses a gap that existed since inception: skeptic could detect agentic poisoning patterns, but had no safe, persistent way to collect and regression-test against real-world malicious samples.

The subsystem spans six files in `internal/corpus/` (corpus.go, crypto.go, fetch.go, manifest.go, safety.go, scan.go) totaling ~1,186 source lines, plus 1,570 lines of colocated tests. The CLI surface in `cmd/skeptic/corpus_cmd.go` (422 lines) wires five subcommands and a SHA-prefix artifact addressing scheme:


| Subcommand              | Purpose                                                                  |
| ----------------------- | ------------------------------------------------------------------------ |
| `corpus init`           | Create encrypted corpus directory with AES-256-GCM key                   |
| `corpus fetch`          | Ingest samples from URLs or local files with validation and sanitization |
| `corpus info`           | Inventory with SHA prefixes, expected rules, metadata                    |
| `corpus scan`           | Decrypt-to-temp, scan in IR mode, compare against expected detections    |
| `corpus purge`          | Confirmed deletion of curated data                                       |
| `corpus <SHA> metadata` | Append-only timestamped analyst annotations                              |


Security model: six-layer defense (filesystem isolation via XDG data dirs, agent exclusion markers, content validation, AES-256-GCM encryption at rest, scan isolation in IR mode with no cache/MCP/correlation, no network from scan path). Path safety validates against git worktrees, MCP roots, dependency directories, and scan targets.

Integration tests in `integration_corpus_test.go` (175 lines) and `rulepack_corpus_test.go` (59 lines) exercise the full lifecycle.

### Config overhaul: profiles, show, use

`internal/config/` was substantially expanded with three new files:

- `**config_show.go**` (169 lines): `skeptic config show` prints the fully resolved configuration with source annotations, showing which values came from which config file, profile, or flag. Supports `--json`, `--system`, and `--profile` filters.
- `**config_use.go**` (78 lines): `skeptic config use <name>` sets the active named profile by writing a pointer file. Profiles live in `~/.config/skeptic/profiles/`.
- `**config_paths_test.go**` (205 lines), `**config_test.go**` (243 lines), `**config_show_test.go**` (222 lines), `**config_use_test.go**` (120 lines): Colocated tests for the expanded config surface.

The `config` subcommand is now a proper subcommand tree (`config show`, `config use`, `config init`) rather than a single action.

### CLI flag consistency sweep

A systematic pass across all subcommands added short flags for commonly used options and ensured global flags (verbose, quiet, config, profiling) pass through consistently. The `cli-flag-review` agent skill was created to codify the review process. Key changes:

- Short flags added: `-v` (verbose), `-q` (quiet), `-c` (config), `-s` (source), `-p` (path), `-f` (format), `-o` (out), `-e` (expected-rules), `-H` (allow-host), `-M` (metadata), `-m` (max-corpus-bytes), `-t` (corpus-timeout), `-r` (rules-dir), `-y` (confirm)
- Global flag extraction: verbose, quiet, config, cpu-profile, mem-profile, trace, perf-debug, log-file are parsed once in `main.go` and threaded through a `globalFlags` struct
- Help text quality improved across all subcommands

### Campaign rules externalized to signed rulepacks

`rules_supply_chain_campaigns.go` (675 lines, the largest single rule file) was deleted. Campaign IOC rules moved entirely to signed JSON rulepacks under `rulepacks/campaigns/`:


| Campaign             | Rulepack                                                         |
| -------------------- | ---------------------------------------------------------------- |
| TeamPCP              | `rulepacks/campaigns/teampcp/rules.2026-03-28.json`              |
| Axios NPM compromise | `rulepacks/campaigns/axios-npm-compromise/rules.2026-03-31.json` |
| Iolitelabs VSCode    | `rulepacks/campaigns/iolitelabs-vscode/rules.2026-03-28.json`    |


Each campaign directory now includes a `.sig` file and a `rules.test.*.json` test fixture. The `rulepack_corpus_test.go` validates that campaign rulepacks load and contain expected rule IDs.

Built-in rule count dropped from 221 to 183 (the delta moved to rulepacks, not deleted). This aligns with the detection philosophy in AGENTS.md: structural rules are built-in, campaign IOCs are signed external packs.

### Rulepack test runner

`internal/rules/rulepack_test_runner.go` (116 lines) provides a reusable test harness for validating signed rulepacks: load, verify signature, parse rules, check for expected IDs, and validate RE2 pattern compilation. Used by `rulepack_corpus_test.go`.

### New internal package: corpus


| Package           | Source lines | Test lines | Purpose                                            |
| ----------------- | ------------ | ---------- | -------------------------------------------------- |
| `internal/corpus` | ~1,186       | 1,570      | Encrypted sample management, fetch, scan isolation |


This is the 18th `internal/` package, joining the existing 17. Dependency direction: `corpus` → `model`, `security`, `logging`, `scan`, `config`.

### Documentation

- `docs/CORPUS.md` (198 lines): Complete reference for the corpus subsystem
- `docs/modules/corpus.md`: Module documentation for `internal/corpus`
- `docs/CONFIGURATION.md`: Updated with profile system, `config show`, `config use`
- `docs/ARCHITECTURE.md`: Updated with `internal/corpus` package and dependency graph
- `docs/RULESET_GROUPING.md`: Updated to reflect campaign rule externalization
- `AGENTS.md`: Updated module structure with `internal/corpus`

### Agent skills

- **Added**: `cli-flag-review` — systematic CLI flag audit process
- **Added**: `repo-statistics` — codebase metrics collection (later moved to personal skill)
- **Removed from repo**: `repo-statistics` (moved to `~/.agents/skills/`)
- **Updated**: `ruleset-lifecycle-operations` — fixed stale `rules_supply_chain_campaigns.go` reference

### Codebase metrics


| Metric            | Round 2 | Round 3 | Delta                    |
| ----------------- | ------- | ------- | ------------------------ |
| Tracked files     | ~295    | 344     | +49                      |
| Go source lines   | ~18k    | 23,235  | +5k                      |
| Go test lines     | ~12k    | 16,537  | +4.5k                    |
| Built-in rules    | 221     | 183     | -38 (moved to rulepacks) |
| Internal packages | 17      | 18      | +1 (corpus)              |
| CLI subcommands   | 16      | 18      | +2 (corpus, config tree) |
| All tests pass    | yes     | yes     | —                        |

---

## Round 2 — 2026-03-31

### What changed

This round closed the proof corpus gap, extracted the enrichment pipeline, restructured rulepacks for maintainability, and split the integration test monolith. The focus was shipping hygiene: every strength lane now has dedicated test fixtures, the post-scan pipeline is independently testable, and documentation reflects the actual codebase.

### Proof corpus: 5 fixtures → 30

The previous round left the proof corpus at five directories covering basic detection presence. This round expanded it to 30 directories with targeted fixtures for every rule family and a negative-test directory for false positive regression.

The four strength lanes each have dedicated proof:

- **Agentic ecosystem poisoning**: `agentic-skills/` (AGT-SKL- with prompt injection, credential disclosure, scanner suppression), `agentic-output-injection/` (AGT-OUT- with tool output containing embedded instructions), expanded `agentic-poisoning/` now individually asserts AGT-TRUST-013 (lockfile), -015 (IDE config), -017 (backup file), -018 (desktop.ini)
- **CI/CD trust boundaries**: `ci-secret-hygiene/` (CI-SECRET-001..004 with env dumps, verbose tracing, secret upload, token persistence), symlink fixtures for SCM-SYM-001..003
- **"Nobody reviews this" surfaces (the moat)**: `low-review-surfaces/` — the most comprehensive proof directory, with poisoned `package-lock.json`, `.vscode/settings.json`, `desktop.ini`, `.gitattributes` with smudge filter, `CODEOWNERS`, `.bak` backup, and `docs/generated-api.md` with HTML comment directives
- **Cross-finding correlation**: `correlation-multi/` with a multi-file layout (workflow + IAM policy + MCP config + SKILL.md) designed to trigger COR- directory-level and repo-level correlation

Additional families now covered: DROP-001..004 (dropper techniques), TPCP-NPM/CRED (npm campaign IOCs), BHV-SC/ORD (behavior chains), GRAPH/MID (identity graph), IAC-HELM-002 (Helm secrets), ATK-EXE/LAT/COL (attack execution), OBF-ENT-001 (obfuscation entropy).

Negative test directory `negative-benign/` validates that legitimate `.gitattributes`, normal editor settings, and standard Makefiles do not fire low-review surface rules.

### Enrichment pipeline extraction

`enrichReportFindings` (94 lines of post-scan orchestration calling dep checks, identity graph, provenance, SBOM, MCP discovery, behavior drift, and git correlation) was extracted from `cmd/skeptic/perform_skeptic_run.go` into `internal/enrich/`. The new `enrich.EnrichReport()` function takes an `enrich.Options` struct and is independently testable. The CLI file dropped from 698 lines to ~580 and lost three direct imports (checks, correlation, provenance).

`resolveRunConfig` (157 lines of config file + mode + preset layer merging) was partially extracted: the core layer-application logic moved to `config.ResolveConfigLayers()`, while flag parsing and validation remain in `cmd/skeptic/`. This makes config merging testable without standing up a full CLI.

### Integration test split

The 2829-line `integration_cicd_test.go` (15 tests, hardcoded sleep polling) was split into:


| File                           | Tests | Concern                                                 |
| ------------------------------ | ----- | ------------------------------------------------------- |
| `integration_daemon_test.go`   | 2     | MCP/daemon E2E, concurrent scans                        |
| `integration_scan_test.go`     | 4     | Small corpus, decoders, provenance, correlation         |
| `integration_perf_test.go`     | 4     | Incremental cache, worker scaling, large corpus, stress |
| `integration_pipeline_test.go` | 5     | Full pipeline, concurrent safety, filters, waivers      |
| `integration_helpers_test.go`  | —     | Shared utilities, `pollUntil` deadline-aware helper     |


`pollUntil(t, timeout, interval, checkFn)` replaces raw `time.Sleep` polling loops with a ticker + deadline pattern.

### Rulepacks layout

Campaign rule packs and signing keys moved from `cmd/skeptic/rules/` (inside the Go source tree) to `rulepacks/campaigns/` and `rulepacks/signing/` at the repo root. Default `--out` and `--rules-out-dir` flags updated. `rulepacks` added to scan engine's skip list so campaign IOC patterns no longer self-detect during repo scans. Ghost directory `cmd/skeptic/cmd/` deleted.

### Rule count stabilization

All documentation and skills now say "200+ built-in rules." The exact count lives only in `rules_core_test.go`'s `assertRuleCount` assertion (currently 221). A comment marks this as the single source of truth.

### Documentation

- `README.md` now opens with a "Detection Focus" section naming all four strength lanes
- `docs/ARCHITECTURE.md` updated with `internal/enrich/` package and dependency graph
- `AGENTS.md` module structure updated with `internal/enrich/` and integration test split
- `docs/modules/cli.md` test table reflects the five split integration files
- All rulepacks path references updated across docs and skills

---

## Round 1 — 2026-03-29

### What changed

This phase transformed skeptic from a rule portfolio into a product with a confidence model, user-facing operating modes, and an MCP trust-audit experience.

### Confidence taxonomy

Every `Finding` now carries a `ConfidenceClass` (definitive, heuristic, or correlated). The class is derived automatically from the rule ID prefix via `DefaultConfidenceForRuleID`; rules may override it in metadata. This avoids a manual annotation pass across 200+ rules while still allowing precision where it matters.

Key mapping: `AGT-TRUST-`, `AGT-MEM-`, `AGT-OUT-`, `SCM-`, `GRAPH-`, `CI-MUTABLE-`, `CI-PRT-`, `CI-EXEC-`, `CLOUD-ID-`, `DISC-MCP-`, `NON-CODE-` default to definitive. `COR-`, `DRIFT-` default to correlated. Everything else (including `AGT-SKL-`, `ATK-`, `BHV-`, `TPCP-IOC-`, `DEP-`, `ENC-`, `DOM-TYPO-`) defaults to heuristic.

Confidence affects presentation and summarization. It does not directly gate builds.

### Operating modes

Three modes sit above presets in config resolution: `developer` (default), `ir`, and `deep`. Each applies a small set of defaults (`ModePresetValues`): developer sets hybrid scan, policy on, fail-on critical; ir and deep default fail-on to none (advisory).

Presentation filtering (`FilterFindingsByMode`): developer shows definitive and correlated at all severities, heuristic only at critical. IR and deep show everything.

### Mode-driven gating

`ThresholdExceeded` now checks rule family eligibility via `IsGateEligible(ruleID, mode)` before counting a finding toward the exit-code threshold. In developer mode, only wedge families (AGT-*, CI-MUTABLE-*, SCM-*, GRAPH-*, DISC-MCP-*, DOM-TYPO-*) can trigger failure. IR and deep have no gate-eligible families.

This means: confidence affects what you see; mode/family/severity affect what blocks.

### MCP trust assessment

`skeptic_scan_repo` accepts a `mode` parameter and returns a `trust_assessment` object: verdict (`action_required`, `review_advised`, `no_issues_found`), confidence counts, risk areas by category, and review-priority file ranking. Files are ranked by wedge relevance (AGT- tier 1, CI- tier 2, DOM-TYPO- tier 3, then severity and count).

### Output formats

Text and markdown output include a trust summary header (definitive/heuristic/correlated counts, mode, files scanned, risk score). Per-finding lines show `[SEVERITY/CONFIDENCE]`. Trust-laundering findings display a "(low-review surface)" tag. SARIF results include `confidence_class` in properties.

### Proof corpus

`testdata/proof/` contains five fixture directories: clean-repo (zero findings in developer mode), agentic-poisoning (AGT-TRUST-* fires), ci-trust-abuse (mutable ref / PR target findings), domain-impersonation (DOM-TYPO-* fires), campaign-artifacts (TPCP-IOC visible in ir mode). Tests validate both raw findings and `BuildTrustAssessment` verdicts.

### How the developer-audit use case improved

Before: running skeptic on a fresh clone produced a flat list of findings at mixed severity with no indication of epistemic strength or review priority. A developer had to mentally triage which findings were structural problems versus statistical noise.

After: `skeptic --mode developer --path .` shows only definitive and correlated findings (plus critical heuristics). The text output opens with a trust summary. Through MCP, `skeptic_scan_repo` returns a verdict and ranked files for review. The developer sees "action_required: review these 3 files" instead of "here are 47 findings, figure it out."

### How IR mode differs

IR mode shows all findings at all severities and confidences. Nothing is filtered. Campaign IOC rules (TPCP-IOC-*) are visible and prominent. No rule family triggers automatic build failure. The intent is broad surfacing for manual triage, not noise reduction.