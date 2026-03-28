# Corpus

`skeptic corpus` is a curated, encrypted-at-rest collection of potentially malicious agentic directive files (SKILL.md, AGENTS.md) used to validate that skeptic's AGT-\* rule families detect real-world agentic poisoning patterns.

## Quick Start

```bash
skeptic corpus init
skeptic corpus fetch -s ./samples/malicious-SKILL.md -e AGT-SKL-001,AGT-SKL-003
skeptic corpus fetch -s https://raw.githubusercontent.com/.../SKILL.md \
  -H raw.githubusercontent.com -M '{"campaign":"teampcp","source":"github"}'
skeptic corpus info
skeptic corpus info --sha                # show full SHA256 hashes
skeptic corpus scan                      # scan all artifacts
skeptic corpus scan dbe7fd02             # scan single artifact by SHA prefix
skeptic -v 1 corpus scan -f json         # verbose lifecycle + JSON output
skeptic corpus dbe7fd02 metadata "analyst note: confirmed malicious"
skeptic corpus dbe7fd02 expected-rules AGT-SKL-003,SCM-TRUST-002
skeptic corpus purge -y                  # confirm deletion
```

## Storage Model

The corpus is **persistent user data**, not cache. Samples are expensive to reconstruct -- URLs go dead, repos get cleaned up, yanked packages disappear.

**Default location:** XDG data directory

| Platform | Default path |
|----------|-------------|
| Linux | `$XDG_DATA_HOME/skeptic/corpus/` (default `~/.local/share/skeptic/corpus/`) |
| macOS | `~/Library/Application Support/skeptic/corpus/` |

**Custom paths** are allowed only when explicitly configured via `--path` flag or `corpus_path` in `.skeptic.json`:

```json
{
  "corpus_path": "/data/skeptic-corpus"
}
```

Resolution order: `--path` flag > `.skeptic.json` `corpus_path` > platform default.

**Encryption at rest:** All artifacts are encrypted with AES-256-GCM. The 32-byte key is generated at `corpus init` and stored in `.corpus-key` (mode 0600). Files are stored as `artifacts/<sha256>.enc` with original filenames recorded only in the `corpus.lock` manifest.

## Global Flags

These flags can appear anywhere on the command line before or after any subcommand. They apply to **all** skeptic subcommands (corpus, ingest, serve, mcp, bundle, waive, export-evidence, and the default scan path):

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

Example: `skeptic -v 2 --cpu-profile corpus.prof corpus scan -f json`

## CLI Reference

### `skeptic corpus init [-p <dir>]`

Creates the corpus directory with restricted permissions, generates the AES-256 encryption key, writes agent exclusion markers, and creates an empty manifest. Prints the resolved path.

### `skeptic corpus fetch -s <URL|FILE> [flags]`

Fetches a `.md` file from a URL or local path. Validates (must be `.md`, must be text, max 1 MiB), sanitizes (strips ANSI escapes, replaces Unicode bidi overrides, truncates long lines), encrypts, and stores.

| Flag | Short | Default | Purpose |
|------|-------|---------|---------|
| `--source` | `-s` | (required) | URL or local file path |
| `--path` | `-p` | (auto) | Corpus directory |
| `--allow-host` | `-H` | (none) | Comma-separated allowed hostnames for URL fetch |
| `--allow-http` | | `false` | Allow plain HTTP URLs |
| `--expected-rules` | `-e` | (none) | Comma-separated rule IDs expected to fire on this artifact |
| `--max-corpus-bytes` | `-m` | `52428800` | Max total corpus size in bytes (50 MiB) |
| `--metadata` | `-M` | (none) | Metadata to attach (plain text, JSON, or YAML) |

### `skeptic corpus info [-p <dir>] [--sha]`

Shows corpus status: artifact count, total size, creation time. Lists each artifact with source, original name, SHA256 prefix, expected rules, and metadata entries.

| Flag | Short | Default | Purpose |
|------|-------|---------|---------|
| `--path` | `-p` | (auto) | Corpus directory |
| `--sha` | | `false` | Show full SHA256 hashes (plaintext + encrypted) |

### `skeptic corpus scan [-p <dir>] [flags] [SHA]`

Decrypts artifacts to namespaced temp directories, scans with all rules in IR mode, reports results. If `expected_rules` are defined per artifact, reports expected-vs-actual detection delta. Use `skeptic -v 1 corpus scan` for lifecycle logging (decrypt, scan, wipe).

With no positional argument, scans **all** artifacts. Pass a SHA prefix to scan a single artifact:

```bash
skeptic corpus scan                     # scan entire corpus
skeptic corpus scan dbe7fd02            # scan one artifact
skeptic -v 1 corpus scan dbe7fd02 -f json
skeptic corpus scan --learn             # scan and auto-annotate expected rules
skeptic corpus scan --learn -f json -o results.json
```

| Flag | Short | Default | Purpose |
|------|-------|---------|---------|
| `--format` | `-f` | `text` | Output format: `json`, `text`, `sarif`, `markdown` |
| `--out` | `-o` | (stdout) | Write output to file |
| `--rules-dir` | `-r` | (none) | Additional rules directory |
| `--fail-on` | | (none) | Exit non-zero if findings at or above severity |
| `--corpus-timeout` | `-t` | `60` | Scan timeout in seconds |
| `--learn` | | `false` | Auto-append detected rule IDs to each artifact's `expected_rules` |

When `--learn` is set, each artifact's `expected_rules` is updated to include every rule ID that fired during the scan. Rules already present are not duplicated. The manifest is saved after the scan completes. On subsequent scans (with or without `--learn`), any rule that was previously learned but no longer fires will appear in the delta as `MISSING`.

### `skeptic corpus purge [-p <dir>] -y`

Removes the corpus directory. Requires `--confirm` / `-y` to prevent accidental deletion of curated data. Without it, prints what would be removed and exits non-zero.

### `skeptic corpus <SHA> metadata <string>`

Appends an **append-only** timestamped metadata entry to the artifact identified by SHA prefix. Entries are never edited or deleted. The value can be plain text, JSON, or YAML. Each entry is automatically prefixed with an RFC 3339 UTC timestamp.

```bash
skeptic corpus dbe7fd02 metadata "analyst: confirmed malicious directive"
# stored as: "2026-04-02T06:30:25Z analyst: confirmed malicious directive"

skeptic corpus dbe7fd02 metadata '{"campaign":"teampcp","confidence":"high"}'
skeptic corpus dbe7fd02 metadata "tags: supply-chain, skill-injection"
```

Metadata attached at fetch time via `--metadata` / `-M` is also timestamped.

SHA prefixes must be at least 4 hex characters and unambiguous (match exactly one artifact). Use `skeptic corpus info --sha` to see full hashes.

### `skeptic corpus <SHA> expected-rules <RULE-1,RULE-2,...>`

Sets (replaces) the expected rules for the artifact identified by SHA prefix. These rule IDs are compared against actual scan findings during `corpus scan` to produce a delta report (missing and unexpected rules).

```bash
skeptic corpus f757cccf expected-rules AGT-SKL-003,SCM-TRUST-002,AGT-SKL-010,AGT-TRUST-005,ATK-PER-003
skeptic corpus 61e7f56d expected-rules SCM-TRUST-001,SCM-TRUST-003
skeptic corpus dbe7fd02 expected-rules none   # clear expected rules
```

Unlike metadata (append-only), expected rules are replaced on each call. Pass `none` to clear.

## Path Safety Rules

All paths are resolved to absolute paths via `filepath.Abs` + `filepath.EvalSymlinks` before any validation. The resolved path must not be inside:

1. **A Git worktree** -- any ancestor containing `.git/`
2. **An MCP allowed root** -- any path in `--mcp-allowed-roots` or `.skeptic.json`
3. **A dependency/vendor environment** -- `node_modules`, `vendor`, `venv`, `.venv`, `site-packages`, `__pypackages__`, `.tox`
4. **A scan target** -- prevents corpus from living inside a scan tree or vice versa

## Manifest Format

`corpus.lock` is the single source of truth for artifact provenance:

```json
{
  "version": 1,
  "created": "2026-03-31T16:00:00Z",
  "corpus_sha256": "<integrity-hash>",
  "artifacts": [
    {
      "id": "<sha256-of-plaintext>",
      "original_name": "SKILL.md",
      "source": "https://raw.githubusercontent.com/...",
      "source_type": "url",
      "fetch_time": "2026-03-31T16:00:00Z",
      "plaintext_sha256": "<sha256>",
      "encrypted_sha256": "<sha256>",
      "size_bytes": 1234,
      "expected_rules": ["AGT-SKL-001", "AGT-TRUST-015"],
      "sanitizations_applied": ["ansi_stripped", "bidi_replaced"],
      "metadata": [
        "2026-03-31T16:00:00Z {\"campaign\":\"teampcp\",\"confidence\":\"high\"}",
        "2026-04-01T10:15:00Z analyst: confirmed malicious directive"
      ]
    }
  ]
}
```

The `corpus_sha256` field is a self-integrity hash computed over the manifest JSON with that field zeroed. Verified at scan time.

## Scan Isolation

Corpus scan differs from normal skeptic scans:

- Forces `ScanModeIR` (all rules, all severities, all confidence classes)
- Uses `ScanStyleHybrid` and `ThreatModeAll`
- Disables incremental cache, MCP discovery, identity graph, correlation, drift, waivers, and config auto-discovery from the corpus directory
- Decrypts to namespaced temp directories (`<artifact-id>/<original-name>`) to prevent filename collisions and enable per-artifact finding attribution
- Securely wipes temp directory after scan (zero-fill then remove)

## Security Model

Six layers protect against the corpus becoming an attack vector:

1. **Filesystem isolation** -- XDG data dir default, explicit config only, 4-check path validation
2. **Agent exclusion** -- `.gitignore`, `.cursorignore`, `.copilotignore`, `.ai-ignore` (all containing `*`), plus `.skeptic-corpus-lock` marker that triggers scan engine directory skip
3. **Content validation** -- `.md` only, text check, ANSI/bidi sanitization, line truncation
4. **Encryption at rest** -- AES-256-GCM per artifact, unique nonce, SHA256-named storage
5. **Scan isolation** -- IR mode, no cache/MCP/correlation, namespaced temp dirs
6. **No network from scan** -- only `corpus fetch` touches the network

## Known Limitations

- **Phase 1 scope:** Only `.md` files (SKILL.md, AGENTS.md). No tarballs, package registries, or ecosystem-specific extraction.
- **Windows:** Best-effort. Advisory file locking uses `syscall.Flock` (Linux/macOS only).
- **URL authentication:** Not supported. Use local files for authenticated sources.
- **No re-fetch:** If a source URL goes dead, the encrypted artifact remains but cannot be refreshed. The manifest preserves the original source for manual recovery.
