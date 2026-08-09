# Contributing to skeptic

## Rule Contribution Guide

### Rule ID Conventions

| Prefix | Domain |
|--------|--------|
| **Campaign indicators** | |
| `TPCP-*` | TeamPCP / Trivy campaign IOCs — shipped as JSON rule packs under `rulepacks/campaigns/teampcp/` (e.g. `rules.2026-03-28.json`), not as Go structs in `internal/rules` |
| **Agentic surfaces** | |
| `AGT-SKL-*` | Agentic skill poisoning |
| `AGT-MCP-*` | MCP tool/config attacks |
| `AGT-MEM-*` | Agent memory poisoning |
| `AGT-OUT-*` | Agent output manipulation |
| `AGT-EXP-*` | Expanded agentic threats |
| `AGT-ART-*` | Agent artifact manipulation |
| `AGT-TRUST-*` | Agent trust boundary violations (001–018), including “nobody reviews this” low-review file surfaces |
| **MITRE ATT&CK tactics** | |
| `ATK-EXE-*` | Execution |
| `ATK-PER-*` | Persistence |
| `ATK-DEF-*` | Defense Evasion |
| `ATK-LAT-*` | Lateral Movement |
| `ATK-COL-*` | Collection |
| `ATK-C2-*` | Command and Control |
| `ATK-IMDS-*` | Cloud metadata service (IMDS) credential access |
| `ATK-SWEEP-*` | Credential path / env sweep patterns |
| `ATK-MEM-*` | Process memory / `/proc` access patterns |
| `ATK-K8S-*` | Kubernetes secret sweep patterns |
| `ATK-EXFIL-*` | Credential packaging / exfil staging |
| `ATK-MEMDUMP-*` | Process memory dumping |
| `ATK-WIPER-*` | Destructive / wiper logic |
| **CI/CD and SCM** | |
| `POL-GHA-*` | GitHub Actions policy |
| `CI-SECRET-*` | CI secret exposure |
| `CI-PRT-*` | `pull_request_target` / privileged checkout trust boundaries |
| `CI-EXFIL-*` | CI credential exfiltration (e.g. token + outbound request) |
| `CI-ABUSE-*` | CI runner abuse |
| `CI-BUILD-*` | CI build script hygiene (credential on CLI, no-op scripts, stale toolchains) |
| `CI-ENV-*` | CI environment exposure (credential templates, hardcoded creds, EOL runtimes) |
| `CI-DEPBOT-*` | Dependency bot configuration weaknesses (Renovate/Dependabot) |
| `CI-GOV-*` | GitHub governance (auto-merge, CODEOWNERS, workflow_run) |
| `SCM-TRUST-*` | SCM trust/integrity |
| `SCM-GIT-*` | Git configuration risks |
| `SCM-PKG-*` | Package manager risks |
| `SCM-SYM-*` | Symlink abuse |
| `SCM-CACHE-*` | Committed build cache |
| `SCM-TEMP-*` | Temporary file exposure |
| **Cloud and identity** | |
| `CLOUD-ID-*` | Cloud identity |
| `MID-*` | Machine identity |
| **Infrastructure as Code** | |
| `IAC-TF-*` | Terraform misconfigurations |
| `IAC-ANS-*` | Ansible misconfigurations |
| `IAC-HELM-*` | Helm chart misconfigurations |
| `POL-TF-*` | Terraform policy (state backend encryption, sensitive variables) |
| `POL-ARGO-*` | ArgoCD policy (auto-sync, prune, self-heal) |
| **Encoding and obfuscation** | |
| `ENC-EXFIL-*` | Encoded exfiltration |
| `ENC-ENTROPY-*` | Entropy anomaly detection |
| `ENC-POLYGLOT-*` | Polyglot file detection |
| `ENC-STEGO-*` | Multi-step encoding / steganography-style evasion |
| `OBF-CMD-*` | Obfuscated commands |
| `OBF-ENT-*` | Entropy-flagged obfuscation |
| **Persistence and containers** | |
| `CTR-ESC-*` | Container escape |
| `RUGPULL-*` | Rug-pull indicators |
| **Behavior and correlation** | |
| `BHV-*` | Behavior chain detection |
| `BHV-DEPBOT-*` | Dependency bot behavioral chain (automerge + no age gate + mutable range) |
| `BHV-EVAL-*` | Shell eval of dynamic content |
| `COR-*` | Cross-file correlation |
| `COR-TEMPORAL-*` | Temporal correlation (git history) |
| `DRIFT-*` | Drift detection |
| `DRIFT-TREND-*` | Multi-run drift trend detection |
| **Dependency and provenance** | |
| `DEP-*` | Dependency checks |
| `DEP-LOCK-*` | Lockfile integrity (missing integrity, non-default registry, missing lockfile) |
| `DEP-TOOL-*` | Build-time tool installs from external modules |
| `PROV-*` | Provenance checks |
| `PROV-SBOM-*` | SBOM cross-reference checks |
| `DOM-TYPO-*` | Structural domain typosquat (implemented in `internal/checks/domain_checks.go`, not `internal/rules`) |
| **Graph analysis** | |
| `GRAPH-*` | Identity graph (RBAC, IAM, OIDC, webhooks) |
| **Other** | |
| `AIW-*` | AI workload hardening |
| `DISC-MCP-*` | MCP auto-discovery |
| `SKN-PROT-*` | Scanner self-protection |

### “Nobody reviews this” and low-review surfaces

Many compromises land in files that rarely get human code review—package manifests, lockfiles, generated HTML, editor swap files, OS metadata, IDE configs. Prefer rules that encode **attack-enabling structure** (what an attacker can rely on because reviewers skip the file) over one-off IOC strings. When proposing `AGT-TRUST-*` or non-code rules, state which review gap the pattern targets and whether another ecosystem would still match the same class of mistake.

### Adding a New Rule

1. Add the `Rule` struct to the appropriate group file in `internal/rules/` (e.g., `rules_behavioral_signals.go`, `rules_agentic_surfaces.go`, `rules_attack_tactics.go`). For literal campaign IOC strings, prefer a versioned JSON pack under `rulepacks/campaigns/<campaign>/`. See `docs/RULESET_GROUPING.md` for which file matches your detection surface.
2. Every rule requires:
   - Unique ID following the prefix convention above
   - Title (concise, < 80 characters)
   - Description (1-2 sentences explaining the risk)
   - Category (lowercase, hyphenated)
   - MITRE ATT&CK technique ID
   - Severity: `info`, `low`, `medium`, `high`, or `critical`
   - Pattern: valid Go/RE2 regex (no lookaheads or backreferences)
   - Target: `TargetContent` or `TargetPath`
   - Remediation: actionable fix text (required for `high` and `critical` severity)
3. Add a test fixture in the appropriate `*_test.go` file proving the pattern matches.
4. Run `make validate-rules` to verify all patterns compile.
5. Run `make test` to ensure the full suite passes.

### Quality Gates

Rules are validated by the `--rule-quality` system:
- **Pattern complexity**: minimum 4 characters, must not be trivially broad
- **Required fields**: ID, title, description, pattern all non-empty
- **ID format**: must follow `PREFIX-NNN` convention
- **MITRE format**: must match `T[0-9]{4}` or `TA[0-9]{4}` pattern

### Running Tests

```bash
make test                # Unit tests
make integration         # Process-level integration tests
make bench               # Benchmarks
make ci                  # Full CI suite
make validate-rules      # Rule pattern validation
```

### Code Style

- **stdlib-only**: no external dependencies
- Go formatting enforced via `make fmt`
- Method-level documentation for non-obvious logic
- Tests for every exported function and every rule pattern

## Branch rulesets

`.github/ruleset-main.json`, `.github/ruleset-main-reviews.json`, and
`.github/ruleset-fork-only.json` are committed copies of server-side state.
**A ruleset change goes in the file and on the server, in the same change.**
Editing one without the other is how `test-action` stayed listed as a required
check for two releases after the ruleset was supposed to point at
`test-action-result` (#83).

`.github/workflows/ruleset-drift.yml` compares them weekly, on manual dispatch,
and on any PR touching a ruleset file. Run it locally with:

```bash
python3 scripts/ruleset-drift.py
```

It compares `name`, `target`, `enforcement`, `conditions`, `bypass_actors`, and
each rule's `type` and `parameters`. Server-managed fields (`id`, `created_at`,
`_links`, and similar) are stripped first. Lists are order-normalized, because
the API does not promise a stable order.

Reading rulesets needs a token with repo admin scope. The default
`GITHUB_TOKEN` can list them, but the API returns a **reduced view** with
`bypass_actors` absent — not empty, absent. Diffing against that would report
drift that does not exist, so the script detects the withheld field and exits 78
rather than comparing. The workflow turns 78 into a warning, so a missing
permission never reads as "no drift" and never as a false alarm either.

Set a `RULESET_READ_TOKEN` secret with repo admin scope to make the check
actually run in CI.

To apply a file to the server:

```bash
gh api -X PUT repos/TGPSKI/skeptic/rulesets/<id> --input .github/ruleset-main.json
```

## Releases

Releases are cut by `.github/workflows/release.yml` via manual dispatch. The
workflow computes the next version from the latest `vX.Y.Z` tag, requires a
matching `CHANGELOG.md` entry, builds the release archives, and publishes them.

### Tags

| Tag | Points at | Moved by |
|---|---|---|
| `vX.Y.Z` | one commit, permanently | created once per release |
| `vX.Y` | newest release in that minor line | release workflow, force-updated |
| `vX` | newest release in that major line | release workflow, force-updated |

`vX` exists because the GitHub Action is consumed as `TGPSKI/skeptic@v0`. Moving
it is what makes that ref pick up new releases.

Consumers who want an immutable ref should pin a commit SHA. skeptic reports
mutable action refs as findings (`SCM-TRUST-001`, `POL-GHA-001`), so a tag ref
shows up when scanning a repository that uses one.

### Release artifacts

Each release carries one archive per platform plus `checksums.txt`:

```
skeptic_vX.Y.Z_linux_amd64.tar.gz
skeptic_vX.Y.Z_linux_arm64.tar.gz
skeptic_vX.Y.Z_darwin_amd64.tar.gz
skeptic_vX.Y.Z_darwin_arm64.tar.gz
skeptic_vX.Y.Z_windows_amd64.zip
checksums.txt
```

The action downloads the archive matching the runner and verifies its SHA256
against `checksums.txt` before extracting. A mismatch fails the step rather than
falling back to a source build.

Adding a platform means adding it to the matrix in the `Build release archives`
step and to the OS/arch mapping in `action.yml`.

### Provenance

From v0.3.1 onward the release workflow attests every archive and
`checksums.txt` with `actions/attest-build-provenance`. Verify one with:

```bash
gh attestation verify skeptic_vX.Y.Z_linux_amd64.tar.gz --repo TGPSKI/skeptic
```

`checksums.txt` establishes that an archive is the one this repository built.
The attestation establishes that `checksums.txt` itself came from `release.yml`
running in this repository, which a checksum file alone cannot.

Attestation runs before the release is published, so a failure produces no
release. A dry run skips it — an attestation is a permanent public record, and
archives that are never published should not have one.
