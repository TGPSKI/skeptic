# Changelog

## v0.3.0 — unreleased

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