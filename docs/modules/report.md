# report

> Output generation: text, JSON, SARIF, and markdown reports; baseline diffing; evidence bundles; distribution bundles.

## Responsibility

`internal/report` owns all output formats and finding-export workflows. It renders human-readable text reports with remediation guidance for Critical/High findings, GitHub-flavored markdown summaries with severity tables and top findings, SARIF 2.1.0 schema output with rule remediation in `help.text` and `RiskScore` in run properties, JSON baselines with stable finding identity keys, signed evidence bundles for IR handoff, and signed distribution bundles containing rules snapshots with integrity manifests.

## Public API

### Text / JSON / SARIF / Markdown Output

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `WriteTextReport` | `(out io.Writer, report model.Report)` | Human-readable report with trust summary header (confidence counts, mode, files scanned, risk score) and per-finding `[SEVERITY/CONFIDENCE]` annotations. |
| `WriteSARIFReport` | `(out io.Writer, report model.Report) error` | SARIF 2.1.0 with rules, results, run timing, and `confidence_class` in both rule properties and result properties. |
| `WriteJSONReport` | `(path string, report model.Report) error` | JSON report file with parent directory creation. |
| `BuildSARIFRun` | `(report model.Report) map[string]any` | SARIF run payload builder. |
| `SARIFLevelFromSeverity` | `(sev model.Severity) string` | Severity-to-SARIF-level mapping. |
| `WriteMarkdown` | `(out io.Writer, report model.Report)` | GitHub-flavored markdown with trust summary block, severity table, confidence column, top 10 findings, file summary, and risk score. |

### Baseline Diffing

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `LoadBaselineReport` | `(path string) (model.Report, error)` | Reads prior JSON report for diffing. |
| `ApplyBaselineDiff` | `(report *model.Report, baseline model.Report, diffOnly bool)` | Annotates findings with `new`/`unchanged` state; `diffOnly` filters to new only. |
| `FindingIdentityKey` | `(f model.Finding) string` | Stable identity: `RuleID|File|SHA256(match)[:8]`. |
| `FindingIdentityKeyV1` | `(f model.Finding) string` | Legacy line-based identity for migration. |

### Evidence Bundles

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `RunExportEvidence` | `(stdout, stderr io.Writer, opts ExportEvidenceOptions) int` | Creates signed `.tar.gz` evidence bundle for IR handoff. |
| `BuildEvidenceManifest` | `(report model.Report, reportJSON []byte) map[string]any` | Manifest metadata builder. |
| `BuildEvidenceSnippets` | `(report model.Report) []map[string]any` | Per-finding snippet records. |
| `AddTarEntry` | `(tw *tar.Writer, name string, data []byte) error` | Appends a named entry to a tar archive. |
| `SignWithEd25519` | `(privKeyPath string, data []byte) ([]byte, error)` | Signs data with an Ed25519 private key from a PEM file. |
| `ParseEd25519PrivateKeyPEM` | `(data []byte) (ed25519.PrivateKey, error)` | Parses raw PEM bytes into an Ed25519 private key. |
| `ParseEd25519PublicKeyPEM` | `(data []byte) (ed25519.PublicKey, error)` | Parses raw PEM bytes into an Ed25519 public key. |

### Distribution Bundles

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `RunBundle` | `(stdout, stderr io.Writer, opts BundleOptions) int` | Creates signed distribution bundle with rules snapshot and SHA256 manifest. |
| `RunVerifyBundle` | `(stdout, stderr io.Writer, opts VerifyBundleOptions) int` | Verifies bundle signature, rule count, and rules snapshot SHA256. |

## Dependencies

| Package | Why |
|---------|-----|
| `internal/model` | `Report`, `Finding`, `Rule` types |
| `internal/security` | Ed25519 key parsing and SHA256 hashing for evidence and distribution bundle signing |

## Test Surface

| File | Tests |
|------|-------|
| `baseline_test.go` | Write/load JSON, identity keys v1 and v2 |
| `bundle_test.go` | Bundle creation, verify missing, full rules + manifest SHA256 |
| `export_evidence_test.go` | Evidence bundle creation, missing report handling |
| `sarif_test.go` | SARIF baseline state, severity levels, driver version, mode properties |
| `text_test.go` | Single/multi target, all branches, SARIF output, baseline diff, evidence manifest |
| `text_regression_test.go` | No-findings threshold line omission |
| `markdown_test.go` | Zero findings, mixed severity, threshold exceeded |

```bash
go test ./internal/report -count=1
```

## Related Docs

- [scan module](scan.md) — produces `model.Report` consumed here
- [rules module](rules.md) — `[]Rule` used for bundle snapshots
- [ARCHITECTURE.md](../ARCHITECTURE.md) — report in dependency graph
