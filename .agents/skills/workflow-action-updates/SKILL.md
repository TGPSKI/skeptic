---
name: workflow-action-updates
description: >-
  Audit and update GitHub Actions workflow files to use the latest action
  releases pinned to full commit SHAs. Scans all .github/workflows/*.yml
  files, resolves current vs latest versions, and applies upgrades. Use when
  the user asks to update actions, check for outdated workflow dependencies,
  pin actions to SHAs, or audit CI workflow hygiene.
---

# Workflow Action Updates

Audit all GitHub Actions workflow files, identify outdated action versions,
resolve latest releases, and update references to SHA-pinned latest versions.

## Workflow

1. **Discover** — find all workflow files under `.github/workflows/`.
2. **Inventory** — extract every `uses:` reference with its current SHA pin and version comment.
3. **Resolve** — for each action, determine the latest release tag and its commit SHA.
4. **Compare** — produce a table showing current vs latest for each action.
5. **Upgrade** — update workflow files, preserving the `# vX.Y.Z` comment convention.
6. **Verify** — confirm YAML is still valid after edits.

## Action Reference Format

All action references must follow this exact format:

```yaml
- uses: owner/action@<full-40-char-sha> # vX.Y.Z
```

### Requirements

- **Full commit SHA**: always pin to the full 40-character commit SHA, never a tag or branch name.
- **Version comment**: always include a trailing `# vX.Y.Z` comment with the semver tag the SHA corresponds to.
- **No short SHAs**: never use abbreviated commit hashes.
- **No mutable refs**: never use branch names (`main`, `master`) or moving tags (`v4`, `latest`).

### Example

```yaml
# CORRECT
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2

# WRONG — mutable tag
- uses: actions/checkout@v6

# WRONG — no version comment
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd

# WRONG — short SHA
- uses: actions/checkout@de0fac2e # v6.0.2
```

## Resolving Latest Versions

### Step 1: Extract current pins

For each `uses:` line, parse:
- `owner/action` — the action repository
- `sha` — the pinned commit SHA
- `version` — the semver from the trailing comment

### Step 2: Look up latest release

For each unique `owner/action`, determine the latest release. Use one of:

**Option A — GitHub API (preferred when `gh` is available):**

```bash
gh api repos/OWNER/ACTION/releases/latest --jq '.tag_name'
```

**Option B — Web search:**

Search for `OWNER/ACTION latest release` and extract the tag from results.

**Option C — git ls-remote:**

```bash
git ls-remote --tags https://github.com/OWNER/ACTION.git | \
  grep -oP 'refs/tags/v\K[0-9]+\.[0-9]+\.[0-9]+$' | \
  sort -V | tail -1
```

### Step 3: Resolve the commit SHA for a tag

```bash
# Try annotated tag first (dereference)
SHA=$(git ls-remote https://github.com/OWNER/ACTION.git "refs/tags/TAG^{}" | cut -f1)

# If empty, it's a lightweight tag — use the tag ref directly
if [ -z "$SHA" ]; then
  SHA=$(git ls-remote https://github.com/OWNER/ACTION.git "refs/tags/TAG" | cut -f1)
fi
```

Always verify the SHA is exactly 40 hex characters before using it.

### Step 4: Produce comparison table

Before making changes, output a table:

```
| Action                          | Current  | Latest   | Status  |
|---------------------------------|----------|----------|---------|
| actions/checkout                | v6.0.2   | v6.0.2   | Current |
| actions/setup-go                | v6.3.0   | v6.3.0   | Current |
| actions/upload-artifact         | v6.0.0   | v7.0.0   | Behind  |
```

## Applying Upgrades

### Same-major upgrades

Apply automatically. Replace the SHA and update the version comment.

### Cross-major upgrades

Flag for review. Check the release notes for breaking changes relevant to the
current usage before applying. Common breaking changes to watch for:

- Node.js runtime version bumps (may require newer runner)
- Renamed or removed inputs/outputs
- Changed default behavior for existing inputs
- Minimum runner version requirements

If the upgrade is safe for the current usage, apply it. If breaking changes
affect the workflow, report them and ask for confirmation.

### Replacement pattern

Use `StrReplace` with `replace_all: true` when the same `owner/action@old-sha`
appears multiple times in a file (e.g. `upload-artifact` used in several steps).

## Post-Upgrade Verification

After all edits:

1. Verify each updated `uses:` line has exactly 40 hex characters before the `#`.
2. Verify the version comment matches the tag that was resolved.
3. Confirm no other YAML structure was disturbed.
4. List the changes made in a summary table.

## Audit Mode

When asked to audit without upgrading, produce the comparison table and stop.
Do not modify files. Report:

- Actions that are behind
- Actions pinned to branches or short SHAs (security risk)
- Actions missing version comments
- Actions from archived or deprecated repositories

## Skipped Actions

Do not modify `uses:` references in:

- `testdata/` directories (these are test fixtures, not real workflows)
- Composite action definitions (`action.yml`) unless explicitly requested
- Reusable workflow calls (`uses: ./.github/workflows/...`) — these are local refs

## Quick Checklist

- [ ] All `uses:` lines pinned to full 40-char SHA
- [ ] All `uses:` lines have `# vX.Y.Z` trailing comment
- [ ] No mutable refs (branch names, short tags)
- [ ] All actions on latest release (or cross-major flagged for review)
- [ ] `testdata/` workflow files left untouched
- [ ] Changes summarized in a comparison table
