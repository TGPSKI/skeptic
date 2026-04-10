---
name: go-release
description: >-
  Manage the full Go module release lifecycle: determine next semver version,
  update CHANGELOG.md, create and push a git tag, and verify pkg.go.dev
  picks up the new version. Use when the user asks to tag a release, bump
  the version, update the changelog, or publish a new module version.
---

# Go Release

Tag a new semver release for the skeptic Go module. The release process
is lightweight — no GoReleaser, no binary uploads. The git tag is the
version, the CHANGELOG is the source of truth, and pkg.go.dev resolves
the rest.

## When to use

- User asks to "release," "tag," "bump," or "publish" a new version
- A set of changes on `main` is ready to be versioned
- pkg.go.dev needs to pick up a new module version

## Semver rules for skeptic

| Bump | When |
|------|------|
| **patch** | Bug fixes, CI/CD changes, documentation, test improvements |
| **minor** | New rules, new features, new subcommands, license changes |
| **major** | Breaking CLI changes (renamed/removed flags, changed exit codes, removed subcommands) |

No major release has been made yet. Reserve `v1.0.0` for when the CLI
surface is considered stable.

## Version injection

skeptic does **not** embed a semver string via ldflags. The Makefile
injects `buildCommit`, `buildDate`, and `buildGoVersion` at build time.
The semver lives only in the git tag and CHANGELOG. No code changes are
needed for a tag to work.

## Workflow

### 1. Determine the next version

```bash
git tag --sort=-v:refname | head -5
git log $(git describe --tags --abbrev=0)..HEAD --oneline
```

Review the commits since the last tag. Apply the semver rules above to
decide whether this is a patch, minor, or major bump.

### 2. Update CHANGELOG.md

Add a new section at the top of the changelog, below the `# Changelog`
heading and above the previous version entry:

```markdown
## vX.Y.Z — YYYY-MM-DD

### Category

- Change description
```

Group changes under categories that match the nature of the work:

| Category | Use for |
|----------|---------|
| **Detection** | New rules, rule changes, behavior chains |
| **Infrastructure** | Scan engine, cache, decoders, correlation |
| **CLI** | New flags, subcommands, output changes |
| **CI/CD** | Workflow fixes, action updates |
| **License** | License changes |
| **Documentation** | Doc updates shipped with the release |
| **Build** | Toolchain, Makefile, build process |

Only include categories that have changes. Keep descriptions concise —
one line per change.

### 3. Commit the changelog

The changelog update must be committed to `main` before tagging. Since
`main` has branch protection, this goes through a PR:

```bash
git checkout -b release/vX.Y.Z-prep
git add CHANGELOG.md
git commit -m "Add vX.Y.Z changelog entry"
git push -u origin HEAD
gh pr create --title "Release vX.Y.Z" --body "Changelog entry for vX.Y.Z."
```

Merge the PR before proceeding to the tag step.

### 4. Tag the release

After the changelog PR is merged and `main` is up to date:

```bash
git checkout main
git pull origin main
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

Use an annotated tag (`-a`), not a lightweight tag. The message should
be the version string.

### 5. Verify pkg.go.dev

After pushing the tag, the Go module proxy needs to index the new
version. Trigger it and verify:

```bash
curl -s "https://proxy.golang.org/github.com/TGPSKI/skeptic/@v/vX.Y.Z.info"
```

Then check the pkg.go.dev page:

```
https://pkg.go.dev/github.com/TGPSKI/skeptic@vX.Y.Z
```

It may take a few minutes for pkg.go.dev to update. Verify that:

- The version appears in the versions list
- The license is detected correctly
- The module documentation renders

### 6. Optionally create a GitHub release

If the release warrants release notes beyond the changelog:

```bash
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file - <<'EOF'
Release notes here. Can reference the CHANGELOG for details.
EOF
```

For most releases, the changelog entry is sufficient and a GitHub
release is not required.

## Guardrails

- **Never tag on a dirty working tree.** `git status` must be clean.
- **Never tag a commit that hasn't passed CI.** Verify checks on `main`
  before tagging.
- **Never force-push or delete a published tag.** Once pushed, a tag is
  immutable. If a mistake is found, create a new patch release.
- **Never skip the changelog.** Every tagged version must have a
  corresponding CHANGELOG entry committed before the tag.
- **Branch protection applies.** Changelog commits go through PRs, not
  direct pushes to `main`. The tag itself can be pushed directly since
  rulesets apply to branch refs, not tag refs.

## Quick checklist

- [ ] Commits since last tag reviewed
- [ ] Semver bump level determined (patch/minor/major)
- [ ] CHANGELOG.md updated with new version section
- [ ] Changelog committed to `main` (via PR if branch protection active)
- [ ] `git status` clean on `main`
- [ ] CI passing on `main`
- [ ] Annotated tag created and pushed
- [ ] pkg.go.dev shows the new version
- [ ] License detected correctly on pkg.go.dev
