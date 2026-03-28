# GitHub Action

Run skeptic as a GitHub Action to detect structural trust boundary vulnerabilities in CI.

## Minimal usage

```yaml
- uses: yourorg/skeptic@v1
```

This checks out your code, builds skeptic, scans with `--preset ci --format sarif --fail-on high`, uploads SARIF to GitHub code scanning, and fails the step on policy violation.

## Full example

```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  skeptic:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: yourorg/skeptic@v1
        with:
          path: '.'
          format: sarif
          preset: ci
          fail-on: high
          scan-style: hybrid
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Root path to scan |
| `format` | `sarif` | Output format: `text\|json\|sarif\|markdown` |
| `mode` | `developer` | Operating mode: `developer\|ir\|deep` |
| `preset` | `ci` | Scan preset: `quick\|dev\|ci\|hunt\|machine-identity\|ai-workload` |
| `fail-on` | `high` | Severity gate: `none\|info\|low\|medium\|high\|critical` |
| `fail-on-score` | `0` | Risk score gate (0--100, 0 disables) |
| `scan-style` | `pattern` | Detection style: `pattern\|behavior\|hybrid` |
| `threat-mode` | `all` | Focus area: `all\|machine-identity\|ai-workload` |
| `config` | _(empty)_ | Path to `.skeptic.*` config file (empty = auto-discover) |
| `rules-file` | _(empty)_ | Path to external rule pack JSON |
| `rules-pubkey` | _(empty)_ | Ed25519 public key for rule pack signature verification |
| `baseline` | _(empty)_ | Prior JSON report for diff-only gating |
| `waivers` | _(empty)_ | JSON waiver file path |
| `go-version` | `1.24` | Go version used to build skeptic |
| `sarif-upload` | `true` | Auto-upload SARIF to GitHub code scanning |
| `extra-args` | _(empty)_ | Additional CLI flags passed directly to `skeptic scan` |

## Outputs

| Output | Description |
|---|---|
| `exit-code` | skeptic exit code: `0`=pass, `1`=error, `2`=bad args, `3`=policy failure |
| `sarif-file` | Path to SARIF results file (when `format=sarif`) |
| `result-file` | Path to results file (any format) |

## Exit codes

The action preserves skeptic's exit code semantics:

| Code | Meaning |
|---|---|
| 0 | Scan passed, findings below threshold |
| 1 | Runtime error |
| 2 | Invalid arguments |
| 3 | Policy failure: `--fail-on` threshold exceeded or `--fail-on-score` met |

Exit code 3 fails the workflow step. Set `fail-on: none` for advisory-only scans.

## Recipes

### Advisory mode (never fail)

```yaml
- uses: yourorg/skeptic@v1
  with:
    fail-on: none
```

### Diff-only with baseline

```yaml
- uses: yourorg/skeptic@v1
  with:
    baseline: ./skeptic-baseline.json
    extra-args: '--diff-only'
```

### Custom signed rule packs

```yaml
- uses: yourorg/skeptic@v1
  with:
    rules-file: ./rulepacks/campaigns/custom.json
    rules-pubkey: ./rulepacks/signing/rulepack-signing.pub.pem
    extra-args: '--require-signed-rules'
```

### Machine-identity focused scan

```yaml
- uses: yourorg/skeptic@v1
  with:
    threat-mode: machine-identity
    scan-style: hybrid
```

### AI-workload focused scan

```yaml
- uses: yourorg/skeptic@v1
  with:
    threat-mode: ai-workload
    scan-style: hybrid
```

### JSON output without SARIF upload

```yaml
- uses: yourorg/skeptic@v1
  with:
    format: json
    sarif-upload: 'false'
```

### IR triage (show everything)

```yaml
- uses: yourorg/skeptic@v1
  with:
    mode: ir
    scan-style: hybrid
    fail-on: none
```

### Using with waivers

```yaml
- uses: yourorg/skeptic@v1
  with:
    waivers: ./.skeptic-waivers.json
```

## SARIF and code scanning

When `format` is `sarif` (default) and `sarif-upload` is `true` (default), the action automatically uploads results to GitHub's code scanning. Findings appear in the Security tab of your repository.

The upload runs even when the scan exits with code 3 (policy failure), so findings are always visible regardless of whether the step passes or fails.

Your workflow needs the `security-events: write` permission for SARIF upload:

```yaml
permissions:
  contents: read
  security-events: write
```

## Ref pinning

Pin the action to a full commit SHA for supply chain safety:

```yaml
- uses: yourorg/skeptic@abc123def456 # v1.0.0
```

skeptic itself detects mutable action refs (`POL-GHA-*` rules), so using a tag reference would trigger a finding in your own scan.

## How it works

The action is a composite action that:

1. Sets up Go using `actions/setup-go`
2. Builds skeptic from source (fast -- stdlib-only, no dependency download)
3. Runs `skeptic scan` with the configured inputs
4. Uploads SARIF to GitHub code scanning (if enabled)
5. Uploads the results file as a workflow artifact
6. Fails the step on policy violation (exit code 3)
