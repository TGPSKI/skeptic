# skeptic

[![Go Reference](https://pkg.go.dev/badge/github.com/TGPSKI/skeptic.svg)](https://pkg.go.dev/github.com/TGPSKI/skeptic/cmd/skeptic)
[![Go Version](https://img.shields.io/github/go-mod/go-version/TGPSKI/skeptic)](https://go.dev/)
[![License](https://img.shields.io/github/license/TGPSKI/skeptic)](LICENSE)

A local repo trust auditor.

`skeptic` detects structural trust boundary vulnerabilities that enable cascading supply chain compromise. It targets attack-enabling *conditions*, not just attack artifacts — the class of weaknesses that CVE scanners, SAST tools, and secret scanners don't cover.

**stdlib-only** Go, single binary, 227 built-in rules (plus rule pack ingestion), zero runtime dependencies, and agent isolation from malicious content.

---

[What skeptic is](#what-skeptic-is) | [What skeptic is not](#what-skeptic-is-not) | [Design principles](#design-principles) | [Detection engine](#detection-engine) | [Rule packs and ingestion](#rule-packs-and-ingestion) | [Corpus](#corpus) | [GitHub Action](#github-action) | [Runtimes](#runtimes)

---

## Quick start

```sh
sudo make install-completions   # build, install, add shell completions

skeptic init                    # bootstrap config
skeptic scan                    # scan

skeptic mcp                     # start the MCP server
skeptic serve                   # start the daemon

skeptic ingest                  # ingest threat intelligence
skeptic corpus                  # manage the encrypted threat artifact corpus
```

## What `skeptic` is

The project ships three connected products:

- **Trust-boundary scanner** — deterministic file-at-rest detection and correlation for repositories, CI, machine identities, and agentic tooling.
- **Threat-intelligence pipeline** — ingest, validate, sign, and distribute campaign rule packs without adding runtime dependencies.
- **Repair-eval oracle** — vulnerable repository fixtures plus conjunction graders that verify a repair removes the defect without deleting behavior or hiding findings.

The scanner covers attack vectors in the gaps between existing tools:

- **CI/CD trust boundary violations** — Mutable action refs, unsafe `pull_request_target` patterns, over-permissioned automation identities, unpinned installs, and CI secret hygiene gaps.
- **Agentic ecosystem poisoning** — Malicious `SKILL.md` directives, MCP tool shadowing, memory persistence injection, and tool-output instruction injection.
- **"Nobody reviews this" attack surfaces** — Lockfile injection, IDE and editor config poisoning, build-cache artifacts, backups, OS metadata, and similar low-review paths.
- **Cross-finding correlation** — Per-directory, repo-level, content-hash, basename, and git-temporal links that surface composite risk (`COR-`, `DRIFT-`).

## What `skeptic` is not

- **Not a CVE scanner.** Use Trivy, Grype, osv-scanner for package vulnerabilities.
- **Not a SAST tool.** No AST parsing, no dataflow taint tracking.
- **Not a secret scanner.** Use Gitleaks or trufflehog for credential leak detection.
- **Not an EDR.** Scans files at rest, not runtime behavior.

Run `skeptic` alongside these tools to detect the gaps they don't cover.

For CI workflows, the closest adjacent tools have different jobs: **zizmor** audits GitHub Actions security, **actionlint** checks workflow syntax and expressions, **Poutine** scans CI pipeline misconfigurations across platforms, and **OpenSSF Scorecard** assesses broader project supply-chain practices. skeptic focuses on structural trust-boundary conditions and agentic/machine-identity surfaces, and complements rather than replaces them.

See the [documentation index](docs/README.md) for user, operator, contributor, and agent guides.

## Design principles

- Fill gaps missed by existing security tools.
- Deterministic output for same input and rule set.
- Single static Go binary, stdlib only.
- RE2 regex only, no unsafe patterns.
- Explicit error checking — no silent failures.
- Auditability and traceable configuration.
- Atomic file writes, no path escapes.

## Detection engine

Beyond regex pattern matching, the engine applies:

- **Behavior chains** — multi-step ordered/unordered detection across file content (16 chains, `BHV-`)
- **12 payload decoders** — base64, base32, hex, URL, gzip, zlib, PowerShell, Unicode, HTML, ROT13, quoted-printable, PEM; configurable depth with entropy-based bonus recursion
- **Identity graph analysis** — BFS traversal of IAM/RBAC/OIDC configs across AWS, Azure, GCP, and Kubernetes
- **Cross-finding correlation** — per-directory, repo-level, content-hash, file-basename, and git-temporal (`COR-`, `DRIFT-`)
- **Shannon entropy anomaly detection** — sliding-window analysis for embedded encrypted/encoded payloads
- **NFKC normalization** — defeats fullwidth/homoglyph evasion
- **Aho-Corasick pre-filter** — optional literal-keyword automaton for large-corpus speed
- **XOR brute-force** — optional single-byte XOR decoding on high-entropy content (`--xor-brute`)
- **Polyglot detection** — binary magic bytes in text files
- **Incremental cache** — mtime + size + SHA256 state file with ruleset-hash invalidation
- **Waiver suppression** — JSON waiver files with SHA256-pinned file scope; `waive` creates entries, `--waivers` applies them on scan
- **Risk scoring** — 0–100 aggregate score with diminishing returns per severity
- **Tool-context exemptions** — `--tool-name` reduces FPs when running inside specific tool contexts

### Rule Packs and Ingestion

Rule packs are used to extend the built-in rule set with real-time threat intelligence from multiple sources. Rule packs are signed with Ed25519 detached signatures to ensure integrity and authenticity.

`skeptic ingest` creates signed rule packs from URLs, files, and directories.

### Corpus

`skeptic corpus` enables encrypted-at-rest storage and scan isolation for malicious files. This feature isolates agents from ingesting malicious content during scans.

`corpus` handles initialization, encrypted storage, content validation, manifest integrity, path safety, and isolated scanning with expected-detection delta reporting. 

```bash
skeptic corpus init                  # create the corpus directory with AES-256-GCM key
skeptic corpus fetch -s ./SKILL.md   # ingest a malicious SKILL.md file 
skeptic corpus info                  # show the corpus status
skeptic corpus scan --learn          # scan the corpus and learn the expected rules
```

## GitHub Action

Add skeptic to any workflow:

```yaml
- uses: actions/checkout@v5
- uses: TGPSKI/skeptic@v0
```

The action scans the workspace, so check out your code first. It downloads a checksum-verified release binary, scans with `--preset ci --format sarif --fail-on high`, uploads findings to GitHub code scanning, and fails the step on policy violation. No container, no Go toolchain.

```yaml
- uses: TGPSKI/skeptic@v0
  with:
    scan-style: hybrid
    threat-mode: machine-identity
    fail-on: none              # advisory only
```

See [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md) for the full input/output reference and recipes.

### Worked example: this repository

`.skeptic.json` and `.skeptic-waivers.json` at the repo root gate skeptic's own
CI. They are the reference pair to copy.

`.skeptic.json` ignores only paths whose contents are attack patterns by
construction: the deliberate fixtures under `testdata/`, the signed IOC packs in
`rulepacks/campaigns/`, the rule definitions in `internal/rules/` and
`internal/checks/`, and `*_test.go` files carrying detection fixtures.

Everything else stays scanned, **including markdown**. Findings that were
reviewed and accepted go in `.skeptic-waivers.json`, pinned to the file's
SHA256:

```json
{
  "rule_id": "SCM-TRUST-001",
  "file_path": "docs/GITHUB_ACTION.md",
  "file_sha256": "1610f5aa…",
  "reason": "Documented usage example. The mutable ref is the subject of the prose."
}
```

A pinned waiver stops applying the moment the file changes. Appending one line
to `docs/GITHUB_ACTION.md` re-exposes all 12 waived findings and the scan exits
`3`. That is the difference between a waiver and an ignore rule: an ignore is
permanent and blind, a waiver is a statement about bytes you actually read.
Prefer waivers for any path where content could be added later.

## Runtimes

### CLI scan

```bash
skeptic scan {repo_path}                    # positional path
skeptic scan --path {repo_path}             # explicit flag
skeptic scan -p {repo_path} -f json        # shorthand flags
skeptic scan --preset ci --fail-on high     # CI gating
```

### MCP server

The MCP server provides agentic tooling access over stdio JSON-RPC. Configure your MCP client:

```json
{
  "mcpServers": {
    "skeptic": {
      "command": "skeptic",
      "args": ["mcp"]
    }
  }
}
```

Tools exposed: `skeptic_scan_repo`, `skeptic_waive`, `skeptic_ingest_url`, and daemon bridge tools when `--daemon-url` is provided. See [docs/SERVER.md](docs/SERVER.md) for the full tool reference.

### Daemon

The daemon adds scheduled background scans and exposes an HTTP API for status, reports, and triggered scans.

```bash
# Terminal 1: start daemon
skeptic serve --scan-interval 5m

# Terminal 2: start MCP server with daemon bridge
skeptic mcp --daemon-url http://127.0.0.1:7788 --daemon-token-file .skeptic/daemon.token
```

The daemon binds to loopback with token authentication by default. See [docs/SERVER.md](docs/SERVER.md).

## Install

### go install

```bash
go install github.com/TGPSKI/skeptic/cmd/skeptic@latest
```

### Release binary

Archives for `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`, and `windows/amd64`
are attached to each [release](https://github.com/TGPSKI/skeptic/releases/latest).

```bash
VERSION=v0.3.1
ARCHIVE="skeptic_${VERSION}_linux_amd64.tar.gz"

gh release download "$VERSION" --repo TGPSKI/skeptic --pattern "$ARCHIVE" --pattern checksums.txt
sha256sum --ignore-missing -c checksums.txt
gh attestation verify "$ARCHIVE" --repo TGPSKI/skeptic

tar -xzf "$ARCHIVE"
sudo install -m 755 "skeptic_${VERSION}_linux_amd64/skeptic" /usr/local/bin/skeptic
```

`gh attestation verify` checks the Sigstore build provenance: the archive was
produced by `release.yml` in this repository and has not been altered since.
Archives from v0.3.1 onward carry an attestation.

### Binary + completions (recommended)

```bash
sudo make install-completions
```

This builds the binary, copies it to `/usr/local/bin/`, and installs shell completion scripts for bash, zsh, and fish into their standard system directories. It skips any shell whose completion directory is not writable.

`make install` installs the binary only.

Override paths if needed:

```bash
sudo make install-completions INSTALL_DIR=/opt/bin ZSH_COMPLETION_DIR=/usr/share/zsh/site-functions
```

### Binary only

```bash
make build
sudo install -m 755 bin/skeptic /usr/local/bin/skeptic
```

### Completions only

```bash
sudo make install-completions
```

Or generate to stdout for manual placement:

```bash
skeptic completion bash > ~/.local/share/bash-completion/completions/skeptic
skeptic completion zsh  > ~/.local/share/zsh/site-functions/_skeptic
skeptic completion fish > ~/.config/fish/completions/skeptic.fish
```

### User-local install (no sudo)

```bash
make build
mkdir -p ~/.local/bin
install -m 755 bin/skeptic ~/.local/bin/skeptic

# completions (create dirs if needed)
mkdir -p ~/.local/share/bash-completion/completions
skeptic completion bash > ~/.local/share/bash-completion/completions/skeptic

mkdir -p ~/.local/share/zsh/site-functions
skeptic completion zsh > ~/.local/share/zsh/site-functions/_skeptic

mkdir -p ~/.config/fish/completions
skeptic completion fish > ~/.config/fish/completions/skeptic.fish
```

Ensure `~/.local/bin` is in your `PATH`. For zsh, add `fpath=(~/.local/share/zsh/site-functions $fpath)` before `compinit` in `.zshrc`.

### Uninstall

```bash
sudo make uninstall
```

## Development

### Testing and linting

```bash
make build              # compile binary
make check              # pre-commit: fmt (fail on diff) + vet
make test               # unit tests
make test-race          # unit tests with race detector
make integration        # fast integration tests (~10s)
make ci                 # full CI suite (race + integration)
make lint               # golangci-lint (errcheck, staticcheck, funlen, etc.)
make bench              # benchmarks (all packages)
make coverage-check     # coverage gate (fail if < 60%)
```

See `make help` for the full target list.

### Contributing

New high-signal rules (with tests), false-positive reduction, runtime hardening, and MCP safety extensions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).

## CLI patterns

### CI gating

```bash
skeptic scan -p . --preset ci -f sarif --fail-on high -o skeptic.sarif
```

### Baseline + diff-only

```bash
skeptic scan -p . -f json --write-baseline ./baseline.json
skeptic scan -p . --baseline ./baseline.json --diff-only -f json
```

### Incremental developer scan

```bash
skeptic scan --mode developer -p . --incremental --state-cache .skeptic-state.json
```

### Focused machine-identity or AI-workload assessment

```bash
skeptic scan -p . --threat-mode machine-identity --scan-style hybrid -f json
skeptic scan -p . --threat-mode ai-workload --scan-style hybrid -f json
```

### IR triage (show everything)

```bash
skeptic scan --mode ir -p . --scan-style hybrid
```

### Threat intel ingestion

```bash
skeptic ingest \
  --source "https://example.com/advisory" \
  --allow-host "example.com" \
  --ecosystems "general,pypi,npm,github-actions,container,mcp,agent-skills,go,cargo" \
  --rule-quality strict \
  --out "rulepacks/campaigns/ingested-rules.json"
```

### Signed external rule packs

```bash
skeptic gen-rule-keypair --private-out signing.key.pem --public-out signing.pub.pem
skeptic sign-rulepack --rules-file ./rules.json --private-key signing.key.pem
skeptic scan --rules-file ./rules.json --rules-pubkey signing.pub.pem --require-signed-rules
```

## CLI reference

### Key flags


| Flag              | Short | Default     | Description                                                    |
| ----------------- | ----- | ----------- | -------------------------------------------------------------- |
| `--path`          | `-p`  | `.`         | Root path to scan (also accepted as positional arg)            |
| `--format`        | `-f`  | `text`      | `text` \| `json` \| `sarif` \| `markdown`                      |
| `--out`           | `-o`  | stdout      | Write the report to a file (atomic; parents created)           |
| `--config`        | `-c`  | auto        | Config file path (`.json`, `.yaml`, `.env`)                    |
| `--mode`          |       | `developer` | `developer` \| `ir` \| `deep`                                  |
| `--preset`        |       | —           | `quick` \| `dev` \| `ci` \| `hunt` \| `machine-identity` \| `ai-workload` |
| `--profile`       |       | `repo`      | `repo` \| `developer` \| `container` \| `fullfs`               |
| `--scan-style`    |       | `pattern`   | `pattern` \| `behavior` \| `hybrid` (all three modes set `hybrid`) |
| `--threat-mode`   |       | `all`       | `all` \| `machine-identity` \| `ai-workload`                   |
| `--fail-on`       |       | `critical`  | Severity gate: `none` through `critical`                       |
| `--fail-on-score` |       | `0`         | Risk score gate (0–100, 0 disables)                            |
| `--incremental`   |       | `false`     | Skip unchanged files via mtime/hash cache                      |
| `--baseline`      |       | —           | Prior JSON report for diff comparison                          |
| `--waivers`       |       | —           | JSON waiver file; matched findings stay with `suppressed=true` |


Config resolution order: mode defaults < preset overrides < config file values < explicit CLI flags.

Full flag list: `skeptic --help` or see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

### Global flags


| Flag              | Short | Description                                      |
| ----------------- | ----- | ------------------------------------------------ |
| `--verbose N`     | `-v`  | Verbosity: 0=warn, 1=info, 2=debug, 3=perf       |
| `--quiet`         | `-q`  | Suppress non-error output                        |
| `--config F`      | `-c`  | Config file (empty = auto-discover `.skeptic.*`) |
| `--log-file F`    |       | Log file path                                    |
| `--cpu-profile F` |       | Write CPU profile to file                        |
| `--mem-profile F` |       | Write heap profile on exit                       |
| `--trace F`       |       | Write execution trace to file                    |
| `--perf-debug`    |       | Enable all profiling + per-file timing           |


### Subcommands


| Command             | Purpose                                       |
| ------------------- | --------------------------------------------- |
| `scan` *(default)*  | Scan and report                               |
| `init`              | Bootstrap config files and XDG data directory |
| `config show`       | Print resolved configuration                  |
| `config use <name>` | Set the active named profile                  |
| `corpus`            | Manage encrypted threat artifact corpus       |
| `ingest`            | Generate rule packs from threat intel sources |
| `serve`             | Persistent scheduler + local HTTP API         |
| `mcp`               | Stdio MCP server for agentic tooling          |
| `waive`             | Create SHA256-pinned waivers for findings     |
| `bundle`            | Package binary + rules for distribution       |
| `export-evidence`   | Signed evidence bundles for IR handoff        |
| `sign-rulepack`     | Sign external rule packs with Ed25519         |
| `gen-rule-keypair`  | Generate Ed25519 key pair                     |
| `verify-rulepack`   | Verify rulepack signature                     |
| `verify-bundle`     | Verify signed distribution bundle             |
| `completion`        | Shell completions (bash, zsh, fish)           |
| `version`           | Print build info and rule count               |

