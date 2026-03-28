# provenance

> Dependency provenance verification, signed manifests, SBOM cross-referencing, and multi-ecosystem lockfile hash extraction.

## Responsibility

`internal/provenance` verifies dependency integrity by comparing lockfile hashes against a user-provided provenance manifest. It discovers lockfiles across 6 ecosystems (npm, Go, Cargo, Poetry, pnpm, Yarn), extracts package integrity hashes, supports Ed25519-signed provenance manifests, performs bidirectional manifest checking, and cross-references SBOM components against discovered lockfile hashes. Emits `PROV-*` and `PROV-SBOM-*` findings.

**Invocation:** Provenance verification and SBOM cross-reference are strictly opt-in. They run only when the user passes `--provenance-manifest` and/or `--sbom` on the CLI; no scan profile enables them by default.

## Public API

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `LoadProvenanceManifest` | `(path string) (ProvenanceManifest, error)` | Reads JSON manifest mapping package names to expected hashes. |
| `LoadSignedProvenanceManifest` | `(path string, requireSigned bool) (ProvenanceManifest, []model.Finding)` | Loads manifest with optional Ed25519 signature verification. Emits PROV-003/PROV-004 findings on signature issues. |
| `RunProvenanceChecks` | `(scanRoots []string, manifestPath string, requireSigned bool, redactSecrets bool) []model.Finding` | Compares lockfile hashes against manifest. Emits PROV-001 (hash mismatch), PROV-002 (lockfile package missing from manifest), PROV-003 (missing signature), PROV-004 (signature verification failure), PROV-005 (orphan manifest entry), PROV-ERR (read/parse errors). |
| `ExtractPackageHashes` | `(ecosystem string, data []byte) map[string]string` | Pulls integrity hashes from lockfile content. Dispatches to ecosystem-specific extractors. |
| `ExtractNpmLockHashes` | `(data []byte) map[string]string` | Reads `package-lock.json` v2/v3 SRI entries. |
| `ExtractCargoLockHashes` | `(data []byte) map[string]string` | Reads `Cargo.lock` checksum entries. |
| `ExtractPoetryLockHashes` | `(data []byte) map[string]string` | Reads `poetry.lock` hash entries. |
| `ExtractPnpmLockHashes` | `(data []byte) map[string]string` | Reads `pnpm-lock.yaml` integrity entries. |
| `ExtractYarnLockHashes` | `(data []byte) map[string]string` | Reads `yarn.lock` resolved/integrity entries. |
| `NpmPackageNameFromLockPath` | `(lockPath string) string` | Derives npm package name from lock `packages` key. |
| `ParseCycloneDXBOM` | `(data []byte) ([]SBOMComponent, error)` | Parses CycloneDX JSON SBOM into component list. |
| `ParseSPDXBOM` | `(data []byte) ([]SBOMComponent, error)` | Parses SPDX JSON SBOM into component list. |
| `CrossReferenceSBOM` | `(components []SBOMComponent, lockfileHashes map[string]string, sbomPath string, redact bool) []model.Finding` | Compares SBOM components against lockfile hashes. Emits PROV-SBOM-001 (missing from lockfiles), PROV-SBOM-002 (hash mismatch), PROV-SBOM-003 (SBOM component not in any lockfile). |

### Types

| Type | Description |
|------|-------------|
| `ProvenanceManifest` | `map[string]string` — package name to expected hash. |
| `SignedProvenanceManifest` | Manifest with `Packages`, `PublicKey`, and `Signature` fields for Ed25519 verification. |
| `SBOMComponent` | `{Name, Version, Hash}` — normalized SBOM component for cross-referencing. |

### Finding IDs

| ID | Description |
|----|-------------|
| PROV-001 | Package hash mismatch between lockfile and manifest |
| PROV-002 | Package found in lockfile but missing from provenance manifest |
| PROV-ERR | Manifest or lockfile read/parse error |
| PROV-003 | Provenance manifest missing Ed25519 signature (when `--require-signed-manifest`) |
| PROV-004 | Ed25519 signature verification failure |
| PROV-005 | Orphan manifest entry: package in manifest but not in any scanned lockfile |
| PROV-SBOM-001 | SBOM component missing from lockfiles |
| PROV-SBOM-002 | SBOM component hash mismatch with lockfile |
| PROV-SBOM-003 | SBOM component not found in any lockfile |

## Dependencies

| Package | Why |
|---------|-----|
| `internal/model` | `Finding` type |
| `internal/security` | Hash utilities |
| `internal/checks` | `DiscoverManifests` for lockfile discovery |

## Test Surface

| File | Tests |
|------|-------|
| `provenance_test.go` | Manifest loading, Go sum extraction, npm lock hashes, Cargo/Poetry/pnpm/Yarn extractors, signed manifest load, PROV-005 orphan entries, happy path, mismatch, no manifest, missing file |
| `sbom_test.go` | CycloneDX/SPDX parsing, SBOM cross-reference match, hash mismatch |

```bash
go test ./internal/provenance -count=1
```

## Related Docs

- [checks module](checks.md) — `DiscoverManifests` reused for lockfile discovery
- [cli module](cli.md) — `--provenance-manifest`, `--require-signed-manifest`, `--sbom` flags
- [CONFIGURATION.md](../CONFIGURATION.md) — flag defaults and descriptions
