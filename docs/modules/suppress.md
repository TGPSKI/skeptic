# suppress

> Waiver-based finding suppression with SHA256 content pinning, accepted finding identities, expiration support, and interactive generation.

## Responsibility

`internal/suppress` loads waiver files (JSON format) and matches findings against suppression rules. Waivers can target specific rule IDs (exact, glob, or prefix), specific file paths, optional per-file SHA256 digests (invalidates suppression if file content changes), and can have expiration dates. Suppressed findings are annotated but never removed from results. `RunWaive` runs a caller-supplied scan, merges new waivers into a JSON file, and summarizes post-write active vs suppressed counts.

## Public API

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `LoadWaiverFile` | `(path string) (WaiverFile, error)` | Reads and validates a waiver JSON file. |
| `IsWaived` | `(f model.Finding, waivers []Waiver, now time.Time, fileHashes map[string]string) (bool, string)` | Tests whether a finding is covered by any active waiver. When `FileSHA256` is set on a waiver, compares to `fileHashes[f.File]` (case-insensitive hex). First match wins. |
| `ApplyWaivers` | `(findings []model.Finding, waivers []Waiver, fileHashes map[string]string) []model.Finding` | Returns a copy with `Suppressed` and `SuppressionReason` set for matched findings. |
| `ComputeFileHashes` | `(findings []model.Finding) map[string]string` | Builds path → hex SHA256 for unique real paths in findings; skips empty paths, synthetic `(…)` paths, and unreadable files. |
| `RunWaive` | `(opts WaiveOptions, scanFn ScanFunc) (WaiveResult, error)` | Scans via `scanFn`, filters findings, writes SHA256-pinned waivers, returns summary. Requires non-empty `Reason`; at least one of `File` or `RuleID`. |

### Types

| Type | Description |
|------|-------------|
| `Waiver` | One suppression entry: `RuleID`, `FilePath`, optional `FileSHA256`, accepted `FindingKeys`, `Reason`, `ExpiresAt`, `Author`, and `CreatedAt`. |
| `WaiverFile` | Top-level JSON: `Version` (must be ≥ 1) and `Waivers` list. |
| `ScanFunc` | `func(repoPath string) (*model.Report, error)` — scan callback so this package does not import the scan engine. |
| `WaiveOptions` | `RepoPath`, `File` (relative path; empty = all files), `RuleID` (empty = all rules on matched files), `Reason`, `WaiverPath` (default `.skeptic-waivers.json` when empty). |
| `WaiveResult` | `TotalFindings`, `MatchedFindings`, `WaiversCreated`, `WaiverPath`, `FileSHA256` (when single-file waive), `WaivedRuleIDs`, `ActiveAfter`, `SuppressedAfter`. |

## Dependencies

| Package | Why |
|---------|-----|
| `internal/model` | `Finding`, `Report` |
| `internal/security` | `SHA256FileHex` for `ComputeFileHashes`, waiver pinning in `RunWaive` / `buildWaivers` |

## Internal Design

- **Matching:** `IsWaived` walks waivers in order; inactive (expired) or empty-reason entries are skipped, then rule ID and file path patterns are applied. If `FileSHA256` is non-empty, the waiver matches only when `fileHashes` contains the finding’s path and the digest equals the waiver (case-insensitive).
- **Hashes for apply:** Callers typically pass `ComputeFileHashes(findings)` (or a precomputed map) into `ApplyWaivers` / `IsWaived`. Omitted or empty `FileSHA256` on a waiver preserves backward compatibility (path/rule matching only).
- **Waive flow:** `RunWaive` invokes `scanFn`, filters by file and/or rule, deduplicates by `(rule_id, file)`, sets `FileSHA256` per real file path via `SHA256FileHex`, merges into the target JSON (upsert by rule + path), then reloads and runs `ApplyWaivers` with `ComputeFileHashes(report.Findings)` to fill `ActiveAfter` / `SuppressedAfter`.
- **Refresh review:** `make waivers-refresh` compares current stable finding identities with `FindingKeys`. Unchanged sets re-pin mechanically; new or modified findings stop refresh.

## Test Surface

| File | Tests |
|------|-------|
| `suppress_test.go` | Load/validate errors, rule and path matching, expiration, `FileSHA256` match/mismatch/omitted, `ComputeFileHashes`, full `ApplyWaivers` |
| `waive_test.go` | `RunWaive` per-file, per-finding, rule-only, merge existing, missing reason, missing file and rule |

```bash
go test ./internal/suppress -count=1
```

## Related Docs

- [cli module](cli.md) — `--waivers` feeds `LoadWaiverFile` + `ApplyWaivers`; `waive` subcommand uses `RunWaive`
- [CONFIGURATION.md](../CONFIGURATION.md) — waiver file configuration
