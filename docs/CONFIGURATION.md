# Configuration Guide

`skeptic` supports config-first execution so it works with minimal flags.

## Quick Start

```bash
# Bootstrap config files and XDG data directory
skeptic init

# Check what got configured (always a good first step)
skeptic config show

# Run a scan with defaults from the active profile
skeptic scan

# Create a CI profile and switch to it
skeptic init --out ~/.local/share/skeptic/profiles/ci.json --preset ci
skeptic config use ci
```

> **Tip:** Run `skeptic config show` whenever configuration feels wrong. It prints every resolved value and its source (flag, config file, preset, mode default, or built-in default).

## Config Layers

skeptic separates **system config** (infrastructure settings) from **scan profiles** (scan behavior). Both are stored under the XDG data directory (`$XDG_DATA_HOME/skeptic`, default `~/.local/share/skeptic`).

### Directory layout

```
~/.local/share/skeptic/
  system.json           # infra settings (cache dir, daemon defaults)
  active-profile        # plain text: name of active profile (e.g. "dev")
  profiles/
    dev.json            # named scan profile
    ci.json
    hunt.json
```

### System config (`system.json`)

Infrastructure settings that are not scan behavior. These keys cannot appear in scan profiles.

| Key                | Default                        | Purpose                          |
| ------------------ | ------------------------------ | -------------------------------- |
| `cache-dir`        | `~/.local/share/skeptic/cache` | Incremental scan cache directory |
| `log-dir`          | `~/.local/share/skeptic/logs`  | Default log file directory       |
| `daemon-bind`      | `127.0.0.1:7788`               | Default daemon bind address      |
| `daemon-token-dir` | `~/.local/share/skeptic`       | Where daemon writes token files  |
| `default-workers`  | `0` (NumCPU)                   | Default worker count             |
| `corpus-no-rulepacks` | `false`                     | Disable auto-loading rulepacks in corpus scans |

### Named scan profiles

Identical to today's `.skeptic.json` format -- same keys, same normalization. A profile is just a scan config file stored in a known location under `profiles/`.

## Config Discovery Order

When `--config` is not set, `skeptic` auto-loads config in this order:

1. **Local config in working directory** — first match from:
   - `.skeptic.json`
   - `.skeptic.yaml` / `.skeptic.yml`
   - `.skeptic.env`
   - `skeptic.json`
   - `skeptic.yaml` / `skeptic.yml`
   - `skeptic.env`
2. **Active named profile** — `~/.local/share/skeptic/profiles/<name>.json` where `<name>` is read from `~/.local/share/skeptic/active-profile`

Local config wins when present. Named profiles are the fallback when no local config exists in the working directory.

System config (`system.json`) is **always loaded** underneath the scan profile, regardless of which source provides the scan config.

## Precedence

Resolution order for a given setting (later steps only fill values the user did not already set):

1. **System config** — infra-level defaults (`default-workers`, etc.). Always loaded when present.
2. **Operating mode** (`--mode`) — applies `ModePresetValues` first (e.g. `fail-on`, `scan-style`, `threat-mode`, `policy-checks`). Lowest scan-behavior layer.
3. **Preset** (`--preset`) — applies preset defaults on top of mode for unset fields.
4. **Scan config file** — local `.skeptic.*` or active named profile overrides mode/preset for unset fields.
5. **Explicit CLI flags** (highest) — any flag passed on the command line wins.

Built-in single-flag defaults apply where nothing else set a value.

### Exit-code gating by mode

In **`developer`** mode (default), the default `fail-on` is `critical`. Only findings whose rule IDs belong to **gate-eligible wedge families** (`IsGateEligible`) count toward crossing the severity threshold—so noisy non-wedge rules do not fail the run by themselves. In **`ir`** and **`deep`**, no rule family is gate-eligible for failure: runs remain advisory from a gate perspective unless you change mode or future policy changes eligibility.

## Supported Formats

- JSON object
- YAML key/value (flat or one-level `scan:` nesting)
- `.env` style key/value (`SKEPTIC_*` prefix)

All config keys use hyphenated names. Underscores, dots, and `SKEPTIC_` prefixes are normalized automatically.

---

## Flag Reference

### Tier 1: Day-One Flags

These are the flags most users need on their first scan.

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `.` | Directory or file to scan |
| `--out` | _(stdout)_ | Write the report to this path instead of stdout. Written atomically; parent directories are created. Also settable as the `out` config key. |
| `--mode` | `developer` | Operating mode: `developer` (default trust audit: `fail-on` critical, developer finding filter), `ir` (incident response: advisory default `fail-on` none), `deep` (expert breadth: advisory default `fail-on` none). Modes layer **below** preset and config; see [Precedence](#precedence). |
| `--preset` | _(none)_ | Simple preset: `quick`, `dev`, `ci`, `hunt`, `machine-identity`, `ai-workload` |
| `--format` | `text` | Output format: `text`, `json`, `sarif`, `markdown` |
| `--fail-on` | `critical` | Exit non-zero if any finding meets this severity: `none`, `info`, `low`, `medium`, `high`, `critical` |
| `--fail-on-score` | `0` | Exit non-zero if aggregate risk score meets or exceeds this threshold (0 = disabled) |
| `--incremental` | `false` | Skip unchanged files using mtime/hash cache |
| `--state-cache` | _(none)_ | Path for incremental cache file |

### Tier 2: Tuning and Filtering

For users customizing scan scope or rule behavior.

| Flag | Default | Description |
|------|---------|-------------|
| `--scan-style` | `pattern` | Scan mode: `pattern`, `behavior`, `hybrid` |
| `--threat-mode` | `all` | Focus: `all`, `machine-identity`, `ai-workload` |
| `--policy-checks` | `true` | Enable policy engine checks (GHA pinning, Docker digest, etc.) |
| `--include-rules` | _(all)_ | Comma-separated rule IDs or prefix globs to include |
| `--exclude-rules` | _(none)_ | Comma-separated rule IDs or prefix globs to exclude |
| `--ignore-paths` | _(none)_ | Comma-separated glob patterns to skip |
| `--waivers` | _(none)_ | Path to JSON waiver file (`.skeptic-waivers.json`) |
| `--sarif-base-path` | detected git root | Repository base used for SARIF artifact URIs; falls back to CWD |
| `--max-findings` | `20000` | Cap total findings retained in report |
| `--max-findings-per-file` | `2000` | Cap findings retained per file |
| `--redact-secrets` | `true` | Redact likely secrets in finding snippets |
| `--tool-name` | _(none)_ | Tool context for FP reduction (e.g., `bash`, `curl`). Excludes rule families expected for that tool |

### Tier 3: Performance and Advanced

For large-scale or production deployments.

| Flag | Default | Description |
|------|---------|-------------|
| `--workers` | `NumCPU` | Concurrent scan workers |
| `--max-bytes` | `2MB` | Skip files larger than this |
| `--max-files` | `0` (unlimited) | Stop after scanning this many files |
| `--aho-corasick` | `false` | Use Aho-Corasick automaton for literal-hint pre-filtering |
| `--nfkc` | `true` | Apply NFKC-subset Unicode normalization before pattern matching |
| `--auto-discover-mcp` | `false` | Scan for risky MCP client configs across known platforms |
| `--identity-graph-hops` | `3` | Max BFS hops for RBAC identity-graph analysis |
| `--ignore-permission-errors` | `true` | Skip unreadable files instead of erroring |

### Tier 4: External Rules and Baselines

For teams managing custom rule packs or baseline-diffing workflows.

| Flag | Default | Description |
|------|---------|-------------|
| `--rules-file` | _(none)_ | Path to external rule pack JSON |
| `--rules-dir` | _(none)_ | Directory of rule pack JSON files |
| `--rules-sha256` | _(none)_ | Expected SHA256 hash for rule pack integrity |
| `--rules-pubkey` | _(none)_ | Ed25519 public key for rule pack signature verification |
| `--require-signed-rules` | `false` | Reject unsigned external rule packs |
| `--no-default-rules` | `false` | Disable built-in rules (use only external) |
| `--rule-quality` | `warn` | Rule quality control: `off`, `warn`, `strict` |
| `--baseline` | _(none)_ | Path to baseline JSON for diff comparison |
| `--diff-only` | `false` | Only report findings not in baseline |
| `--write-baseline` | _(none)_ | Write current findings as new baseline |
| `--behavior-baseline` | _(none)_ | Path for behavior profile baseline (drift detection) |
| `--behavior-history` | _(none)_ | Path for behavior profile history (trend detection across runs) |
| `--drift-severity-multiplier` | `2.0` | Severity shift multiplier for drift findings (used with `--behavior-baseline`) |
| `--drift-allowed-chains` | _(none)_ | Comma-separated path globs of new behavior chains to ignore for drift alerts |
| `--provenance-manifest` | _(none)_ | Provenance manifest for hash verification |
| `--require-signed-manifest` | `false` | Reject provenance manifests without valid Ed25519 signature (PROV-003/004) |
| `--sbom` | _(none)_ | Path to CycloneDX or SPDX JSON SBOM for cross-reference against lockfile hashes (PROV-SBOM-*) |
| `--git-correlation` | `false` | Enable temporal correlation via git history (COR-TEMPORAL-001) |
| `--xor-brute` | `false` | Enable single-byte XOR brute-force decoding on high-entropy content (CPU intensive) |
| `--max-decode-depth` | `3` | Maximum recursive payload decoding depth |

### Tier 5: Diagnostics

For debugging and profiling.

| Flag | Default | Description |
|------|---------|-------------|
| `--verbose` | `0` | Verbosity level: 0 (warn), 1 (info), 2 (debug), 3 (perf — debug + per-file timing) |
| `--quiet` | `false` | Suppress all non-finding output |
| `--log-file` | _(none)_ | Write logs to file in addition to stderr (uses `io.MultiWriter`) |
| `--perf-debug` | `false` | Enable all profiling: cpu.prof, mem.prof, trace.out |
| `--cpu-profile` | _(none)_ | Write CPU profile to file |
| `--mem-profile` | _(none)_ | Write heap profile to file |
| `--trace` | _(none)_ | Write execution trace to file |

---

## Presets

Presets apply a bundle of defaults. CLI flags and config file values override preset defaults.

| Preset | Profile | Style | Threat Mode | Policy | Fail-on | Notes |
|--------|---------|-------|-------------|--------|---------|-------|
| `quick` | repo | hybrid | all | on | high | Fast first-scan |
| `dev` | developer | hybrid | all | on | high | Local development (incremental, MCP discovery) |
| `ci` | repo | hybrid | all | on | high | CI gate with JSON output |
| `hunt` | repo | behavior | all | on | medium | Deep threat hunting |
| `machine-identity` | repo | hybrid | machine-identity | on | medium | Identity-focused scan |
| `ai-workload` | repo | hybrid | ai-workload | on | medium | Agentic/MCP-focused scan |

## Example Configs

### JSON

```json
{
  "preset": "dev",
  "path": ".",
  "incremental": true,
  "state-cache": ".skeptic-state.json",
  "fail-on": "high"
}
```

### YAML

```yaml
scan:
  preset: dev
  path: .
  incremental: true
  state-cache: .skeptic-state.json
  fail-on: high
```

### .env

```env
SKEPTIC_PRESET=dev
SKEPTIC_PATH=.
SKEPTIC_INCREMENTAL=true
SKEPTIC_STATE_CACHE=.skeptic-state.json
SKEPTIC_FAIL_ON=high
```

---

## Waivers

- **Config key:** `waivers` — path to the waiver JSON file (same as CLI [`--waivers`](#tier-2-tuning-and-filtering)).
- **`skeptic init`** writes a starter config that includes `waivers` set to `.skeptic-waivers.json` next to the output file. If that waiver file does not already exist, it is created with `version` 1 and an empty `waivers` array.

### `.skeptic-waivers.json` format

The waiver file is a JSON object with:

| Field | Description |
|-------|-------------|
| `version` | Integer schema version; must be ≥ 1 |
| `waivers` | Array of waiver objects |

Each element of `waivers` may include `rule_id`, `file_path`, `file_sha256`, `finding_keys`, `reason`, `expires_at`, `author`, and `created_at` (JSON keys as written; timestamps use RFC3339 when present). `finding_keys` records the accepted finding identities used by `make waivers-refresh` to stop on new or modified findings:

| Field | Description |
|-------|-------------|
| `rule_id` | Rule ID to suppress |
| `file_path` | Path within the repo (pattern matching per suppress logic) |
| `file_sha256` | Optional hex digest; when set, the waiver applies only if the file’s content matches |
| `reason` | Human-readable justification |
| `expires_at` | Optional; omit or empty for no expiry |
| `author` | Optional string |
| `created_at` | Optional |

---

## Subcommand Flags

### `skeptic serve` (daemon mode)

| Flag | Default | Description |
|------|---------|-------------|
| `--bind` | `127.0.0.1:7788` | HTTP listen address |
| `--scan-interval` | `5m` | Schedule interval duration (e.g. `30s`, `5m`, `1h`) |
| `--cron` | _(none)_ | Cron-style interval; supports only `@every <duration>` |
| `--run-on-start` | `true` | Run an initial scan immediately on startup |
| `--auth-token` | _(none)_ | Bearer token for API authentication |
| `--auth-token-file` | _(none)_ | Path to file containing bearer token |
| `--allow-unauthenticated` | `false` | Disable HTTP authentication (not recommended) |
| `--dry-run` | `false` | Print resolved configuration and exit without starting |
| `--watch` | `false` | Enable filesystem polling mode (triggers scan on changes) |
| `--watch-paths` | `.` | Comma-separated paths to watch (used with `--watch`) |
| `--pprof` | _(none)_ | Address for pprof HTTP endpoint (e.g. `localhost:6060`) |
| `--verbose` | `0` | Verbosity: 0=warn, 1=info, 2=debug |
| `--quiet` | `false` | Only emit error logs |
| `--log-file` | _(none)_ | Write logs to file in addition to stderr |

After the daemon flags, remaining arguments are passed through as scan flags (same as the default `skeptic` scan).

### `skeptic ingest` (threat-intel ingestion)

| Flag | Default | Description |
|------|---------|-------------|
| `--source` | _(repeatable)_ | Source input: URL, file path, or directory (repeatable) |
| `--allow-host` | _(repeatable)_ | Allowed hostname for URL sources (repeatable, **required** when URL sources are present) |
| `--sources-file` | _(none)_ | Path to newline-delimited list of sources |
| `--out` | `rulepacks/campaigns/ingested-rules.json` | Output rule pack JSON path |
| `--name` | _(none)_ | Rule pack name |
| `--description` | _(none)_ | Optional rule pack description |
| `--ecosystems` | `general,pypi,npm,github-actions,container,mcp,agent-skills,go,cargo` | Comma-separated ecosystems to extract |
| `--max-rules` | `500` | Maximum generated rules |
| `--min-severity` | `medium` | Minimum severity: `info`, `low`, `medium`, `high`, `critical` |
| `--timeout-sec` | `20` | HTTP timeout in seconds for URL sources |
| `--max-source-bytes` | `2097152` | Max bytes to read per source document |
| `--max-files-per-dir` | `200` | Max files when source is a directory |
| `--strict` | `false` | Fail if any source cannot be read |
| `--include-command-heuristics` | `true` | Include suspicious command regex rules |
| `--include-contextual-iocs` | `true` | Generate IOC rules from risk-context lines |
| `--allow-http` | `false` | Allow `http://` URL sources (not recommended) |
| `--max-redirects` | `5` | Maximum redirects for URL sources |
| `--input-format` | `auto` | Input format: `auto`, `stix`, `sigma`, `yara` |
| `--rule-quality` | `warn` | Quality control: `off`, `warn`, `strict` |
| `--verbose` | `0` | Verbosity: 0=warn, 1=info, 2=debug |
| `--quiet` | `false` | Only emit error logs |
| `--log-file` | _(none)_ | Write logs to file in addition to stderr |

### `skeptic mcp` (MCP JSON-RPC server)

| Flag | Default | Description |
|------|---------|-------------|
| `--daemon-url` | `http://127.0.0.1:7788` | Skeptic daemon URL |
| `--daemon-token` | _(none)_ | Daemon bearer token |
| `--daemon-token-file` | _(none)_ | Path to file containing daemon bearer token |
| `--rules-out-dir` | `rulepacks/campaigns` | Directory for MCP-generated rule packs |
| `--allow-remote-daemon` | `false` | Allow non-loopback daemon URLs (not recommended) |
| `--allow-trigger` | `true` | Enable daemon trigger tool |
| `--allow-ingest` | `true` | Enable threat-intel URL ingestion tool |
| `--require-ingest-approval` | `false` | Require approval step before URL ingestion executes |
| `--mcp-allowed-roots` | _(cwd only)_ | Comma-separated directory prefixes for `scan_repo` |
| `--mcp-ingest-allowed-hosts` | _(none)_ | Comma-separated hosts allowed for `ingest_url` (required for MCP ingest) |
| `--mcp-trigger-cooldown` | `30s` | Minimum interval between scan triggers |
| `--audit-log` | _(none)_ | File path for MCP audit log (JSON lines) |
| `--auto-daemon` | `false` | Auto-start a local daemon process; stop it on MCP exit |
| `--auto-daemon-args` | _(none)_ | Extra args for auto-started daemon (e.g. `'--scan-interval 5m'`) |
| `--verbose` | `0` | Verbosity: 0=warn, 1=info, 2=debug |
| `--quiet` | `false` | Only emit error logs |
| `--log-file` | _(none)_ | Write logs to file in addition to stderr |

### `skeptic bundle` / `verify-bundle`

**bundle:**

| Flag | Default | Description |
|------|---------|-------------|
| `--platform` | _(current os/arch)_ | Target platform (e.g. `linux/amd64`) |
| `--sign` | `false` | Sign bundle with Ed25519 key |
| `--private-key` | _(none)_ | Ed25519 private key PEM for signing |
| `--out` | _(none)_ | Output bundle path |

**verify-bundle:**

| Flag | Default | Description |
|------|---------|-------------|
| `--bundle` | _(none)_ | Path to bundle `.tar.gz` |
| `--public-key` | _(none)_ | Ed25519 public key PEM for verification |

### `skeptic export-evidence`

| Flag | Default | Description |
|------|---------|-------------|
| `--report` | _(none)_ | Path to JSON scan report |
| `--out` | _(none)_ | Output `.tar.gz` path (default: `evidence-<timestamp>.tar.gz`) |
| `--sign` | `false` | Sign bundle with Ed25519 private key |
| `--private-key` | _(none)_ | Ed25519 private key PEM path for signing |

### `skeptic init`

Bootstraps the XDG data directory, creates `system.json` with defaults if it does not exist, and writes a starter scan profile. `init-config` is accepted as a backward-compatible alias.

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | `~/.local/share/skeptic/profiles/dev.json` | Output config path |
| `--format` | `json` | Config format: `json`, `yaml`, `env` |
| `--force` | `false` | Overwrite existing config file |
| `--preset` | `dev` | Starter preset: `quick`, `dev`, `ci`, `hunt`, `machine-identity`, `ai-workload` |

Generated config includes the `waivers` key (see [Waivers](#waivers)). YAML and `.env` output emit `waivers` / `SKEPTIC_WAIVERS` when applicable.

### `skeptic config show`

Prints the fully resolved configuration: system config + active scan profile (or local override). Shows which files were loaded and the effective values.

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Output as JSON |
| `--system` | `false` | Show only system config |
| `--profile` | `false` | Show only the active scan profile |

### `skeptic config use <name>`

Sets the active named profile. The profile must exist under `~/.local/share/skeptic/profiles/`.

```bash
skeptic config use ci
# active profile: ci (~/.local/share/skeptic/profiles/ci.json)
```

### Global Flags

Global flags can appear anywhere on the command line and are inherited by **all** subcommands (corpus, ingest, serve, mcp, bundle, waive, export-evidence, and the default scan path):

| Flag | Short | Purpose |
|------|-------|---------|
| `--verbose N` | `-v N` | Verbosity: 0=warn, 1=info, 2=debug, 3=perf |
| `--quiet` | `-q` | Suppress verbose output |
| `--cpu-profile FILE` | | Write CPU profile (pprof) |
| `--mem-profile FILE` | | Write heap profile on exit |
| `--trace FILE` | | Write execution trace |
| `--perf-debug` | | Enable all profiling + debug verbosity |
| `--log-file FILE` | | Write logs to file |
| `--config FILE` | | Config file path (overrides auto-discovery) |

### `skeptic corpus` (encrypted .md corpus)

See [docs/CORPUS.md](CORPUS.md) for full reference.

Common flags across corpus subcommands:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--path` | `-p` | XDG data dir | Corpus directory (overrides `corpus-path` in config) |

**`corpus fetch`** additional flags:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--source` | `-s` | _(required)_ | URL or local file path |
| `--allow-host` | `-H` | _(none)_ | Comma-separated allowed hostnames |
| `--allow-http` | | `false` | Allow plain HTTP URLs |
| `--expected-rules` | `-e` | _(none)_ | Comma-separated expected rule IDs |
| `--max-corpus-bytes` | `-m` | `52428800` | Max total corpus size (50 MiB) |
| `--metadata` | `-M` | _(none)_ | Metadata to attach (text, JSON, or YAML) |

**`corpus info`** additional flags:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--sha` | | `false` | Show full SHA256 hashes |

**`corpus scan [SHA]`** additional flags (optional SHA prefix scans a single artifact; use `skeptic -v 1 corpus scan` for lifecycle logging):

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `text` | Output format: `json`, `text`, `sarif`, `markdown` |
| `--out` | `-o` | _(stdout)_ | Write output to file |
| `--rules-dir` | `-r` | _(none)_ | Additional rules directory |
| `--fail-on` | | _(none)_ | Exit non-zero at or above severity |
| `--corpus-timeout` | `-t` | `60` | Scan timeout in seconds |

**`corpus purge`** requires `--confirm` / `-y` to prevent accidental deletion.

**`corpus <SHA> metadata <string>`** appends an append-only metadata entry to an artifact. See [CORPUS.md](CORPUS.md#skeptic-corpus-sha-metadata-string).

---

## Unicode Normalization (--nfkc)

Skeptic applies a security-focused subset of NFKC normalization before pattern matching, enabled by default. This defeats common evasion techniques where attackers substitute visually identical Unicode characters for ASCII to bypass regex rules.

### What it normalizes

| Category | Example | Normalized to |
|----------|---------|---------------|
| Fullwidth ASCII (U+FF01–U+FF5E) | `ｃｕｒｌ` | `curl` |
| Fullwidth digits | `１２３` | `123` |
| Cyrillic confusables | `сurl` (Cyrillic с) | `curl` |
| Greek confusables | `Αdmin` (Greek Α) | `admin` |
| Zero-width characters | `cu​rl` (with ZWSP) | `curl` |
| Soft hyphens | `cu­rl` (with SHY) | `curl` |

### Why not full NFKC?

Full NFKC normalization lives in `golang.org/x/text/unicode/norm`, which is an external module. Skeptic is stdlib-only. Instead, skeptic implements the subset of NFKC that matters for security evasion detection: fullwidth-to-ASCII mapping, zero-width stripping, and a curated homoglyph table covering Cyrillic and Greek confusables.

Tools like [aguara](https://github.com/statico/aguara) take a similar focused approach — mapping confusable characters to ASCII equivalents rather than implementing full Unicode normalization. Skeptic's normalizer is purpose-built for the scanner's threat model: it covers the character classes actually seen in supply chain evasion while adding near-zero overhead for pure-ASCII content (the common case).

### Disabling normalization

```bash
skeptic --nfkc=false --path ./target
```

Disable if normalization causes unexpected behavior with intentional Unicode content (e.g., scanning localized documentation where Cyrillic is expected).
