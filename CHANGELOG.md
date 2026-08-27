# Changelog

## v0.4.0 — 2026-08-27

### Detection

- Remove `POL-GHA-001`; `SCM-TRUST-001` is now the canonical mutable GitHub
  Action reference detection (#64).
- Move `CI-PRT-001` and `CI-PRT-002` from unconditional line patterns to
  workflow-level checks that require a privileged trigger plus unsafe checkout,
  repository-code execution, risky commands, or write permissions (#90).
- Restrict `POL-CLOUDID-001` wildcard matching to OIDC trust-policy claims, and
  scope `CLOUD-ID-001` to IAM and RBAC policy paths and context (#91, #64).

### Infrastructure

- Roll up co-located duplicate findings under a primary result with
  `related_rule_ids`, and score only the rolled-up set. Correlations are
  suppressed when all of their constituent findings are waived (#63).
- Record stable finding identities in file-pinned waivers. Waiver refreshes now
  stop for review when a file introduces a new finding while allowing unchanged
  accepted finding sets to be re-pinned mechanically (#100).

### CLI

- Add `--sarif-base-path`, defaulting to the detected Git repository root, and
  emit repository-relative SARIF artifact URIs with `%SRCROOT%` metadata. SARIF
  tool links now derive from module build metadata (#62).
- Give every subcommand a structured help header with a synopsis and runnable
  example (#71).

### Documentation

- Document skeptic as a scanner, threat-intelligence pipeline, and repair-eval
  oracle; add an audience-oriented documentation index, repair corpus guide,
  and adjacent-tool comparison (#70).

## v0.3.1 — 2026-08-09

### Fixed

- Apply `--ignore-paths` to the `GRAPH-`, `DEP-`, and `PROV-` check families.
  All three walk the tree themselves and never received the patterns, so an
  explicitly excluded directory still produced `high` and `critical` findings
  that counted toward `--fail-on`. They also reported the walked path rather
  than one relative to the scan root, which no repo-relative pattern could match
  and which leaked the scanning host's directory layout. The matcher moves to
  `internal/pathfilter` so the two walkers cannot disagree about what "ignored"
  means (#88)
- Omit waived findings from SARIF. Code scanning turns every result into an
  alert and does not honor `result.suppressions`, so a waived finding opened an
  alert the repository had already reviewed and failed the check on any pull
  request touching that file. The complete record stays in the JSON report,
  which carries `suppressed` and `suppression_reason` (#96, #98)
- Label waived findings in markdown output. They rendered identically to live
  ones, reading as open findings nobody had acted on (#96)
- `model.ExpandHomePath` concatenated the home directory with the rest of the
  path, so `~/foo/bar` became `C:\Users\me/foo/bar` on Windows (#66)
- `correlation.filePathRelativeToRepo` accepted paths outside the repository on
  Windows. `filepath.IsAbs` is false for a rooted path with no volume, so
  `/etc/passwd` was joined onto the repo root and passed containment (#66)
- `security.CheckWorldWritableArtifacts` reported every artifact as
  world-writable on Windows. Go synthesizes `0666` for any writable file there,
  so the POSIX other-write bit carries no information. It now reports nothing on
  Windows rather than noise (#66)
- `corpus.groupFindingsByArtifact` bucketed a finding under an empty artifact ID
  when its path began with a separator (#66)
- The results artifact was named from `format` and `fail-on` alone, so two
  invocations of the action in one job collided

### Added

- `windows-latest` job running `go vet` and `go test -race`.
  `internal/corpus/flock_windows.go` shipped in v0.3.0 and had never executed;
  its first run confirmed `LockFileEx`/`UnlockFileEx` work. Integration tests
  stay POSIX-only (#66)
- Sigstore build provenance on every release archive and `checksums.txt`, via
  `actions/attest-build-provenance`. Verify with
  `gh attestation verify <archive> --repo TGPSKI/skeptic`. Attestation runs
  before the release is published, so a failure produces no release; dry runs
  skip it (#4)
- Committed `.skeptic.json` and `.skeptic-waivers.json`. They gate this
  repository's CI and are the reference pair to copy. Markdown stays scanned;
  accepted findings are waived with a `file_sha256` pin, so a waiver lapses when
  the file changes (#65)
- `make waivers-check` and `make waivers-refresh`. Editing a waived file breaks
  its pin, which is the mechanism working and needs a supported way to re-pin.
  `waivers-refresh` prints the findings each waiver will suppress again, because
  re-pinning without reading turns a waiver back into an ignore rule (#93)
- `.github/workflows/ruleset-drift.yml`, `scripts/ruleset-drift.py`, and
  `make ruleset-drift` compare committed `.github/ruleset-*.json` against the
  live rulesets weekly, on dispatch, and on any PR touching them. A token
  without repo admin scope receives a reduced view with `bypass_actors` absent,
  which the script detects and reports as a skip rather than diffing against it
  (#85)
- `run-id` action output, carried into the results artifact name
- `.gitattributes` pinning LF on checkout, so Windows `core.autocrlf` cannot
  rewrite line endings and break `gofmt` or a fixture hash (#66)

### Changed

- The CI self-scan blocks. It discarded stderr and its exit code with
  `|| true`, so 487 findings and a 100/100 risk score enforced nothing. It now
  runs through the local composite action, which also exercises `action.yml` on
  every CI run (#65)
- The release workflow waits for `ci.yml` to reach `completed` instead of
  reading its conclusion once. An in-progress run has a null conclusion and a
  run not yet created returns nothing, and both read as failure — exactly the
  window between merging and dispatching a release (#67)
- `.github/ruleset-main.json` declared `"bypass_actors": []` while the live
  ruleset grants `RepositoryRole` 5 an always bypass. All three ruleset files
  are regenerated from live (#85)
- `.gitignore` stops ignoring `.skeptic.json` and `.skeptic-waivers.json` (#65)
- `test-windows` is a required status check on `main`

### Documentation

- `docs/GITHUB_ACTION.md` gains a permissions table, a runner OS and
  architecture support matrix, a recipe for running the action twice in one job,
  and a statement that SARIF excludes waived findings while JSON retains them.
  `go-version` said "Go version for building skeptic" without noting it applies
  only to the source-build fallback
- README documents installing from a release archive — download, checksum,
  attestation verify, extract — which did not exist though v0.3.0 shipped five
  archives (#4)
- README documents the committed scan config as a worked example, including why
  a SHA-pinned waiver beats an ignore rule for markdown (#65)
- `CONTRIBUTING.md` gains **Provenance**, **Branch rulesets**, and **Scan
  waivers** sections. The second states that a ruleset change goes in the file
  and on the server in the same change (#4, #85, #93)

### Known limitations

- The ruleset drift check needs a `RULESET_READ_TOKEN` secret with repo admin
  scope. Without it the default `GITHUB_TOKEN` returns a reduced view and the
  workflow warns and skips rather than comparing (#85)
- `.skeptic.json` excludes `internal/rules/` and `internal/checks/`, so skeptic
  does not scan its own detection sources. Every pattern it looks for is present
  there as a literal by construction
- Waiver pins cover a whole file, so an unrelated edit invalidates them and two
  pull requests touching the same waived file conflict on the pin (#100)

## v0.3.0 — 2026-08-09

### Security

- Fix expression injection in `action.yml`: inputs were interpolated into the
  `run:` body, so a quote in any input executed arbitrary commands on the runner.
  Inputs now pass through `env:` and the command is built as a bash array (#56)
- Pass expressions through `env:` in `release.yml` and
  `action-integration-test.yml` (#56)

### Fixed

- Build for Windows. `internal/corpus` called `syscall.Flock`, which is
  Unix-only, so `GOOS=windows go build ./...` failed. Locking moves behind
  build-tagged `lockFileExclusive`/`unlockFile`; Windows uses `LockFileEx` over
  the full byte range (#77)
- Gate `CLOUD-ID-` and `POL-GHA-` findings in developer mode. Both were
  classified `definitive` but omitted from gate eligibility, so a workflow with
  `permissions: write-all` produced two HIGH findings and exited `0` under
  `--preset ci --fail-on high` (#55)
- Remove rule families `CI-MUTABLE-`, `CI-EXEC-`, and `NON-CODE-`. They were
  declared in the confidence and gating tables and documented as shipping, but
  no rule emitted them; `SCM-TRUST-001` and `CI-ABUSE-*` cover those conditions
  (#57)

### Changed

- `report.WriteJSONReport` writes atomically, so `--write-baseline` output and
  the daemon report cannot be read half-written (#61)
- Confidence class and gate eligibility now come from one `ruleFamilies` table.
  A definitive family must gate or record an `UngatedReason` (#55)
- Gate `CI-ABUSE-` and `CI-SECRET-` in developer mode (#55)

### Added

- Publish release archives for `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`,
  and `windows/amd64`, plus `checksums.txt` (#59)
- Move the `vX` and `vX.Y` tags to each release. `v0` is what
  `TGPSKI/skeptic@v0` resolves to (#59)
- The GitHub Action downloads a checksum-verified release binary when pinned to
  a version tag, and installs no Go toolchain. It falls back to a source build
  for a branch, a commit SHA, or a local `uses: ./`. A checksum mismatch fails
  the step (#59)
- Warn on a passing run when findings at or above `--fail-on` were excluded by
  gate eligibility, naming the rule IDs (#55)
- `model.RuleFamilies()` and `model.GateSuppressedRuleIDs()` (#55)

### Removed

- `make start` and `make stop`. Both invoked `./scripts/start` and
  `./scripts/stop`, which do not exist in the tree (#5)

### Documentation

- Replace the `yourorg/skeptic` placeholder in `docs/GITHUB_ACTION.md` with
  `TGPSKI/skeptic@v0`, and state that the caller must check out the code — the
  action does not (#2)
- Document the release tag and artifact scheme in `CONTRIBUTING.md` (#59)
- Fix the README key-flags table. Unescaped `|` inside enum values split the
  cells, truncating six rows after their first value (#58)
- Point the "Binary + completions" install at `make install-completions`.
  `make install` installs the binary only (#58)
- Fix two TOC anchors: `#design` and `#rule-ingestion-and-rule-packs` (#6)
- Correct `ScanStyle` and `ThreatMode` value lists in `AGENTS.md`. Three of the
  five documented `ThreatMode` values were rejected by the CLI (#60)
- Correct the module path, the `rules_non_code_surfaces.go` rule count, and the
  verification date in `docs/ARCHITECTURE.md` (#60)

## v0.2.1 — 2026-05-19

### Documentation
- Add package documentation for pkg.go.dev directories view (#14)

### CI/CD
- Add release workflow (manual dispatch) (#12)

## v0.2.0 — 2026-04-10

### License

- Relicense from Apache 2.0 to GNU General Public License v3.0

### CI/CD

- Fix auto-label/CI race condition: remove `opened` from CI pull_request triggers
- Fix test-action required check for path-filtered PRs: add `changes` gate job and `test-action-result` rollup job
- Update `main-ci-and-integrity` ruleset to require `test-action-result`

## v0.1.0 — 2026-04-06

Initial public release.

### Detection

- 229 built-in rules across 5 threat domains: CI/CD trust boundaries, agentic
  ecosystem poisoning, persistence/stealer artifacts, machine identity abuse,
  and supply chain structural hygiene
- 16 behavior chains with ordered and unordered multi-step detection
- 12 payload decoders (base64, base32, hex, URL, gzip, zlib, PowerShell,
  Unicode, HTML, ROT13, quoted-printable, PEM) with entropy-based bonus
  recursion
- Identity graph analysis with BFS traversal across AWS, Azure, GCP, and
  Kubernetes RBAC configurations
- Cross-finding correlation: per-directory, repo-level, content-hash,
  file-basename, and git-temporal (COR-*, DRIFT-*)
- Shannon entropy anomaly detection for embedded encrypted/encoded payloads
- NFKC normalization to defeat fullwidth/homoglyph evasion
- XOR brute-force decoder for single-byte XOR on high-entropy content
- Polyglot detection for binary magic bytes in text files

### Rule families

- **CI/CD** (CI-BUILD, CI-ENV, CI-GOV, CI-DEPBOT, CI-PRT, CI-ABUSE, CI-EXFIL,
  CI-SECRET, POL-GHA, SCM-TRUST): build hygiene, environment exposure,
  governance gaps, dependency-bot attack surface, pull request target abuse,
  execution injection, credential exfiltration, secret hygiene, workflow policy,
  mutable action refs
- **Agentic** (AGT-SKL, AGT-MCP, AGT-MEM, AGT-OUT, AGT-TRUST, AGT-ART):
  SKILL.md directive injection, MCP tool shadowing and credential interpolation,
  memory persistence poisoning, tool-output instruction injection,
  trust-laundering through low-review surfaces
- **Supply chain** (SCM-PKG, SCM-TRUST, SCM-SYM, DEP-LOCK, DEP-TOOL, BHV-SC,
  BHV-DEPBOT, BHV-ORD): lockfile integrity, package install hooks, symlink
  abuse, dependency-bot to auto-merge to install-hook behavior chain
- **Identity** (GRAPH-*, MID-*, CLOUD-ID): over-privileged IAM, wildcard OIDC
  federation, static client secrets, broad token exchange
- **Attack tactics** (ATK-*, DROP-*, OBF-*, ENC-*): persistence artifacts,
  dropper techniques, obfuscation, encoding anomalies

### Infrastructure

- Incremental scan cache with mtime + size + SHA256 state and ruleset-hash
  invalidation
- SHA256-pinned waiver suppression
- Ed25519-signed external rule packs with detached signature verification
- Encrypted-at-rest threat artifact corpus (AES-256-GCM) with scan isolation
- 3 signed campaign rule packs (TeamPCP, axios-npm-compromise, iolitelabs-vscode)
- 34 proof corpus directories for regression testing

### Runtimes

- CLI scanner with 18 subcommands
- Stdio MCP JSON-RPC server for agentic tooling integration
- Local HTTP daemon with scheduled scans and token authentication
- GitHub Actions composite action with SARIF upload support

### Output formats

- Text, JSON, SARIF, Markdown
- Trust summary header with confidence class counts and risk score
- Baseline comparison and diff-only mode

### Operating modes

- `developer` (default): definitive + correlated findings, heuristic only at
  critical severity, wedge-family gating
- `ir`: all findings at all severities and confidences, no gating
- `deep`: full analysis with all decoders and correlation

### Build

- stdlib-only Go 1.24, single static binary, zero runtime dependencies
- Apache License 2.0
