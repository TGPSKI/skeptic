# GitHub Action

Run skeptic as a GitHub Action to detect structural trust boundary vulnerabilities in CI.

## Minimal usage

```yaml
- uses: actions/checkout@v5
- uses: TGPSKI/skeptic@v0
```

The action scans the workspace, so **your workflow must check out the code first** — the action does not do it for you.

It scans with `--preset ci --format sarif --fail-on high`, uploads SARIF to GitHub code scanning, and fails the step on policy violation.

## Permissions

| Permission | When it is needed |
|---|---|
| `contents: read` | always — the action reads the checked-out workspace |
| `security-events: write` | only when `sarif-upload` is `true` (the default) |

The SARIF upload is the only step that needs more than read access. Set
`sarif-upload: 'false'` if you would rather not grant it; the results file is
still produced and still uploaded as a workflow artifact.

## Runner support

| Runner OS | Arch | How skeptic is obtained |
|---|---|---|
| Linux | x64, arm64 | prebuilt release binary |
| macOS | x64, arm64 | prebuilt release binary |
| Windows | x64 | prebuilt release binary |
| Windows | arm64 | source build |
| any | other | source build |

The prebuilt path applies when the action is pinned to a version tag. See
[How it works](#how-it-works) for when it falls back to a source build.

Windows runners execute skeptic's unit tests on every CI run as of v0.3.1.
Two platform limits stand: file permissions are not enforceable through the
stdlib on Windows, so `CheckWorldWritableArtifacts` reports nothing there, and
committed symlinks are materialized by git as plain text files unless the
runner holds `SeCreateSymbolicLinkPrivilege`, so `SCM-SYM-` rules do not fire on
them.

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
      - uses: actions/checkout@v5

      - uses: TGPSKI/skeptic@v0
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
| `go-version` | `1.24` | Go version for the source-build fallback. Unused when a prebuilt binary is downloaded (see [How it works](#how-it-works)) |
| `sarif-upload` | `true` | Auto-upload SARIF to GitHub code scanning |
| `extra-args` | _(empty)_ | Additional CLI flags passed directly to `skeptic scan` |

## Outputs

| Output | Description |
|---|---|
| `exit-code` | skeptic exit code: `0`=pass, `1`=error, `2`=bad args, `3`=policy failure |
| `sarif-file` | Path to SARIF results file (when `format=sarif`) |
| `result-file` | Path to results file (any format) |
| `run-id` | Per-invocation suffix; disambiguates the results artifact when the action runs more than once in a job |

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
- uses: TGPSKI/skeptic@v0
  with:
    fail-on: none
```

### Diff-only with baseline

```yaml
- uses: TGPSKI/skeptic@v0
  with:
    baseline: ./skeptic-baseline.json
    extra-args: '--diff-only'
```

### Custom signed rule packs

```yaml
- uses: TGPSKI/skeptic@v0
  with:
    rules-file: ./rulepacks/campaigns/custom.json
    rules-pubkey: ./rulepacks/signing/rulepack-signing.pub.pem
    extra-args: '--require-signed-rules'
```

### Machine-identity focused scan

```yaml
- uses: TGPSKI/skeptic@v0
  with:
    threat-mode: machine-identity
    scan-style: hybrid
```

### AI-workload focused scan

```yaml
- uses: TGPSKI/skeptic@v0
  with:
    threat-mode: ai-workload
    scan-style: hybrid
```

### JSON output without SARIF upload

```yaml
- uses: TGPSKI/skeptic@v0
  with:
    format: json
    sarif-upload: 'false'
```

### IR triage (show everything)

```yaml
- uses: TGPSKI/skeptic@v0
  with:
    mode: ir
    scan-style: hybrid
    fail-on: none
```

### Using with waivers

```yaml
- uses: TGPSKI/skeptic@v0
  with:
    waivers: ./.skeptic-waivers.json
```

A waiver may pin `file_sha256`, in which case it stops applying as soon as that
file changes. That is what makes a waiver safer than an ignore rule for any path
whose content could grow later — documentation especially. skeptic's own
repository uses this; see the worked example in the
[README](../README.md#worked-example-this-repository).

### Running the action twice in one job

```yaml
- uses: TGPSKI/skeptic@v0
  id: app
  with:
    path: ./app
    fail-on: high

- uses: TGPSKI/skeptic@v0
  id: infra
  with:
    path: ./infra
    fail-on: critical
```

Each invocation writes its own results artifact. The artifact name carries the
`run-id` output, so two scans with the same `format` and `fail-on` do not
collide.

Set `sarif-upload: 'false'` on all but one invocation. Code scanning keys
results by category, the action does not expose that input, so a second upload
in the same job replaces the first rather than adding to it. To publish both,
upload them yourself from `sarif-file` with distinct `category` values:

```yaml
- uses: github/codeql-action/upload-sarif@c10b8064de6f491fea524254123dbe5e09572f13 # v4.35.1
  with:
    sarif_file: ${{ steps.infra.outputs.sarif-file }}
    category: infra
```

That ref is SHA-pinned to match how `action.yml` pins the same action. The
`TGPSKI/skeptic@v0` refs elsewhere on this page are moving tags on purpose —
see [Ref pinning](#ref-pinning).

## SARIF and code scanning

When `format` is `sarif` (default) and `sarif-upload` is `true` (default), the action automatically uploads results to GitHub's code scanning. Findings appear in the Security tab of your repository.

The upload runs even when the scan exits with code 3 (policy failure), so findings are always visible regardless of whether the step passes or fails.

**Waived findings are excluded from SARIF.** Code scanning turns every SARIF result into an alert and has no way to express "found and accepted" — it does not honor the SARIF `suppressions` property. Emitting a waived finding would open an alert the repository has already reviewed, and fail the check on any pull request touching that file.

The complete record lives in the other formats: JSON carries `suppressed` and `suppression_reason` per finding, and the text and markdown reports label waived findings in place. Use `format: json` when you want the full set.

Your workflow needs the `security-events: write` permission for SARIF upload:

```yaml
permissions:
  contents: read
  security-events: write
```

## Ref pinning

`v0` is a moving tag that follows the latest `v0.x` release. It is the easiest ref to start with, and it is what the examples above use.

For supply chain safety, pin to a full commit SHA instead:

```yaml
- uses: TGPSKI/skeptic@<40-char-sha> # v0.3.0
```

skeptic detects mutable action refs itself (`SCM-TRUST-001`), so a tag reference will show up as a finding when you scan your own repository.

A SHA-pinned ref builds skeptic from source, because a commit SHA does not identify a release. Pin to an exact version tag (`@v0.3.1`) to get the prebuilt binary and a SHA-verified download.

From v0.3.1 the release archives also carry Sigstore build provenance. Verify one outside CI with:

```bash
gh attestation verify skeptic_v0.3.1_linux_amd64.tar.gz --repo TGPSKI/skeptic
```

## How it works

The action is a composite action that:

1. Resolves the pinned ref to a release and downloads the matching prebuilt binary, verifying its SHA256 against the release `checksums.txt`
2. Falls back to `actions/setup-go` plus a source build when no release matches the ref — a branch, a commit SHA, or a local `uses: ./`
3. Runs `skeptic scan` with the configured inputs
4. Uploads SARIF to GitHub code scanning (if enabled)
5. Uploads the results file as a workflow artifact
6. Fails the step on policy violation (exit code 3)

A checksum mismatch fails the step. It does not fall back to a source build, because that would hide a tampered download.

The download path skips the Go toolchain entirely. The source-build path is unchanged and needs no external dependencies — skeptic is stdlib-only.
