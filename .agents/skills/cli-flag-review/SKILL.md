---
name: cli-flag-review
description: >-
  Audit and optimize CLI flag definitions across all skeptic subcommands.
  Reviews help text quality, global-vs-local flag modeling, short flag
  coverage, shorthand config-precedence safety, help formatter consistency,
  and test isolation. Use when adding flags, reviewing CLI ergonomics,
  refactoring subcommand interfaces, or debugging flag override behavior.
---

# CLI Flag Review

Systematic audit of every CLI flag in skeptic. Covers help text, short aliases,
global passthrough decisions, config-precedence safety, help output formatting,
test isolation, and implementation correctness.

## Workflow

1. **Inventory** — collect every `fs.*Var` registration across `cmd/skeptic/` and `internal/` subcommand entry points.
2. **Help text audit** — apply the quality rules below to every help string.
3. **Short flag audit** — assign single-letter aliases per the priority table.
4. **Shorthand precedence audit** — verify every shorthand is registered in the config-layer maps (see below).
5. **Help formatter audit** — verify `printScanFlags` and `scanFlagShorthands` are in sync with registrations.
6. **Global vs local audit** — decide whether each flag should be global (pre-parsed in `extractGlobalFlags`) or local to its subcommand `FlagSet`.
7. **Test isolation audit** — verify every test calling `run()` or `ResolveConfigLayers()` sets `XDG_DATA_HOME`.
8. **Implement** — edit flag registrations, update maps, run `go fmt && go vet && go test -race ./...`.

## Help Text Quality Rules

Each help string must:

- Start lowercase (Go `flag` convention)
- Be a noun phrase or imperative verb phrase, not a sentence
- State the **effect**, not just the name (bad: `"output format"`, good: `"output format: json|text|sarif|markdown"`)
- List allowed values inline when the set is small (≤6 values)
- Include the unit for numeric flags (`"bytes"`, `"seconds"`, `"goroutines"`)
- State the zero-value behavior when non-obvious (`"0 = auto"`, `"empty = auto-discover"`)
- Not exceed ~90 characters
- Not duplicate the flag name verbatim as the first word
- Use **identical** help text for both the short and long registration (no `(shorthand)` suffix — the custom help formatter merges them)

### Examples

```
BAD:  "path"                          → just restates the flag name
GOOD: "file or directory to scan"

BAD:  "Output format"                 → capitalized, no values listed
GOOD: "output format: text|json|sarif|markdown"

BAD:  "workers"                       → no unit or zero-value note
GOOD: "parallel scan goroutines (0 = NumCPU)"
```

## Short Flag Assignment

### Priority tiers

Assign short flags to the **most frequently typed** options first. A flag
qualifies for a short alias when it is used interactively (not just in config
files or CI scripts).

| Tier | Criteria | Examples |
|------|----------|---------|
| 1 — always | Every subcommand that has it | `-v` verbose, `-q` quiet, `-c` config |
| 2 — high | Primary I/O flags | `-o` out, `-f` format, `-p` path |
| 3 — medium | Commonly toggled behavior | `-r` rules-dir, `-s` source, `-n` dry-run |
| 4 — skip | Rarely typed or dangerous | `--require-signed-rules`, `--xor-brute` |

### Letter reservation

These letters are reserved project-wide to avoid collisions:

| Letter | Reserved for |
|--------|-------------|
| `-v` | `--verbose` (global) |
| `-q` | `--quiet` (global) |
| `-c` | `--config` (global) |
| `-o` | `--out` |
| `-f` | `--format` |
| `-p` | `--path` |
| `-r` | `--rules-dir` or `--rules-file` |
| `-s` | `--source` |
| `-n` | `--dry-run` or `--name` |
| `-t` | `--timeout` variants |
| `-m` | `--max-*` variants |
| `-e` | `--expected-rules` or `--ecosystems` |
| `-H` | `--allow-host` |
| `-M` | `--metadata` |
| `-y` | `--confirm` |

A short flag must not collide with another short flag **on the same FlagSet**.
Different subcommands may reuse the same letter for different flags if the
semantics are analogous (e.g. `-o` always means output path).

### Registration pattern

Always register the short form as a separate `fs.*Var` pointing to the same
variable, immediately after the long form. Use identical help text for both:

```go
fs.StringVar(&outPath, "out", "", "write report to file")
fs.StringVar(&outPath, "o", "", "write report to file")
```

Do **not** add a `(shorthand)` suffix — the custom help formatter (`printScanFlags`)
merges both onto one line automatically.

## Shorthand Config-Precedence Safety

**This is the most common source of CLI flag bugs.** Go's `flag.Visit` records
the `Flag.Name` that was parsed, not aliases. When a user passes `-f json`,
the visited set contains `"f"`, not `"format"`. If `ApplyRunConfigValues` only
checks `FlagWasSet(visited, "format")`, it sees `format` as unset and allows
config/preset/profile layers to silently overwrite the user's explicit choice.

### Three synchronization points

Adding or removing a shorthand requires updates in **three** places:

| Location | Map | Direction | Purpose |
|----------|-----|-----------|---------|
| `internal/config/config.go` `ApplyRunConfigValues` | `flagShorthands` | canonical → short (`"format": "f"`) | Config-layer precedence: prevents config/preset/profile from overwriting CLI shorthand values |
| `cmd/skeptic/main.go` | `scanFlagShorthands` | short → canonical (`"f": "format"`) | Help formatter: merges `-f` and `--format` onto one line, suppresses standalone shorthand entry |
| `cmd/skeptic/perform_skeptic_run.go` `registerRunFlags` | (the `fs.*Var` calls) | Both names registered | Actual flag registration with Go's `flag` package |

**When adding a new shorthand**, update all three. When reviewing existing flags,
verify all three are in sync.

### How `ApplyRunConfigValues` uses the map

```go
flagShorthands := map[string]string{
    "format": "f",
    "path":   "p",
}

flagExplicit := func(flagName string) bool {
    if FlagWasSet(visited, flagName) {
        return true
    }
    if short, ok := flagShorthands[flagName]; ok {
        return FlagWasSet(visited, short)
    }
    return false
}
```

Every `setString` / `setBool` / `setInt` / `setFloat64` call in that function
uses `flagExplicit(name)` instead of raw `FlagWasSet(visited, name)`.

### Flags that also need shorthand checks in `ResolveConfigLayers`

`--mode` and `--preset` are checked directly in `ResolveConfigLayers` (before
`ApplyRunConfigValues` runs) with bare `FlagWasSet` calls. If shorthands are
ever added for these flags, those call sites must also check the short name.
Both have inline comments flagging this.

## Help Output Formatting

### Custom formatter (`printScanFlags`)

The scan `--help` output uses `printScanFlags` (in `main.go`) instead of Go's
`fs.PrintDefaults()`. This formatter:

- Merges shorthand and long-form flags on one line (`-f, --format VALUE`)
- Uses `--` prefix for all multi-char flags (POSIX convention)
- Suppresses standalone shorthand entries (they appear merged)
- Omits global flags already shown in the hand-written header section
- Uses contextual type hints (`PATH`, `VALUE`, `N`, `GLOB`) via `flagTypeName`/`inferStringMeta`

### When to update the formatter

- **Adding a shorthand**: add to `scanFlagShorthands` map
- **Adding a path-like flag**: add its name to `inferStringMeta` so it gets `PATH` label
- **Adding a glob-like flag**: add its name to `inferStringMeta` so it gets `GLOB` label
- **Adding a new global flag**: add to the `globals` map inside `printScanFlags`

### Manual verification

After any flag change, build and check output visually:

```bash
go build -o /tmp/skeptic-test ./cmd/skeptic/
/tmp/skeptic-test scan --help 2>&1 | head -80
rm -f /tmp/skeptic-test
```

Verify: no duplicate entries, no single-dash long flags, shorthands merged,
type hints make sense, globals not repeated in scan section.

## Global vs Local Decision

### When a flag should be global

A flag belongs in `extractGlobalFlags` (pre-parsed before subcommand dispatch)
when **all** of these are true:

1. It applies to **every** subcommand (or nearly every one).
2. It controls **infrastructure** (logging, profiling, config loading), not scan behavior.
3. It does not conflict with a subcommand-specific flag of the same name.

Current globals: `--verbose/-v`, `--quiet/-q`, `--cpu-profile`, `--mem-profile`,
`--trace`, `--perf-debug`, `--log-file`, `--config/-c`.

### When a flag should be local

A flag is local when:

- It only makes sense for one subcommand (e.g. `--bind` for `serve`).
- It controls scan behavior that varies by context (e.g. `--scan-style`).
- It has a subcommand-specific default (e.g. `--fail-on` defaults differ).

### Passthrough patterns

| Pattern | When to use | Example |
|---------|-------------|---------|
| Direct field access (`gf.Verbosity`) | Subcommand handler is in `cmd/skeptic/` and receives `globalFlags` | corpus subcommands |
| `mergeGlobalFlagsIntoArgs` | Subcommand parses its own `FlagSet` in `internal/` and needs globals as argv | `ingest`, default scan |
| Prepend `--config` only | Subcommand only needs config path from globals | `waive`, `serve`, `mcp` |
| `globalProfileAndStop` only | Subcommand only needs profiling from globals | `bundle`, `export-evidence` |

When adding a new subcommand, choose the **simplest** pattern that covers the
globals it needs. Do not merge all globals if only config is needed.

## Test Isolation for Config-Loading Code

Any test that calls `run()`, `performSkepticRun()`, or `ResolveConfigLayers()`
exercises the config auto-discovery path: `LoadConfigValues` → `DiscoverConfigPath`
→ `ActiveProfilePath`. If `XDG_DATA_HOME` is not isolated, the test picks up the
developer's real XDG profile (e.g. `~/.local/share/skeptic/profiles/dev.json`),
which can set `preset`, `format`, `waivers`, and other values that silently change
test behavior.

### Required isolation

```go
func TestAnythingThatCallsRun(t *testing.T) {
    t.Setenv("XDG_DATA_HOME", t.TempDir())  // FIRST LINE
    // ... rest of test
}
```

### When isolation is required

| Calls | Needs `XDG_DATA_HOME` isolation? |
|-------|----------------------------------|
| `run(...)` | **Yes** — always |
| `performSkepticRun(...)` | **Yes** — always |
| `ResolveConfigLayers(...)` | **Yes** — always |
| `LoadConfigValues(...)` | **Yes** — always |
| `DiscoverConfigPath()` | **Yes** — always |
| `ActiveProfilePath()` / `ActiveProfileName()` | **Yes** — always |
| `LoadSystemConfig("")` (empty path) | **Yes** — auto-discovers from XDG |
| `LoadSystemConfig("/explicit/path")` | No — explicit path bypasses discovery |
| `ApplyRunConfigValues(...)` | No — pure value merge, no filesystem access |
| `FlagWasSet(...)` / `VisitedFlagNames(...)` | No — pure map lookups |
| Validation-only tests (exit code 2 before config loads) | Technically safe but **still isolate** for robustness |

### Audit checklist

When reviewing tests:

1. Search `cmd/skeptic/*_test.go` and `internal/config/*_test.go` for `run(`, `performSkepticRun(`, `ResolveConfigLayers(`
2. Verify each match has `t.Setenv("XDG_DATA_HOME", t.TempDir())` before the call
3. If the test also uses `os.Chdir`, the `XDG_DATA_HOME` setenv must come **before** the chdir

## Verification

After any flag change:

```bash
go fmt ./...
go vet ./...
go build ./...
go test -race -count=1 ./cmd/skeptic/ ./internal/config/ ./internal/corpus/
```

Check `--help` output for each modified subcommand to verify formatting.

## Quick Checklist — Adding a New Shorthand

- [ ] Register both `fs.*Var(&field, "long-name", ...)` and `fs.*Var(&field, "x", ...)` in `registerRunFlags`
- [ ] Use identical help text for both (no `(shorthand)` suffix)
- [ ] Add `"long-name": "x"` to `flagShorthands` in `ApplyRunConfigValues` (`internal/config/config.go`)
- [ ] Add `"x": "long-name"` to `scanFlagShorthands` in `main.go`
- [ ] If the flag is also checked directly in `ResolveConfigLayers`, update that call site
- [ ] Add a test case to `TestApplyRunConfigValuesShorthandFlagPrecedence` verifying the shorthand blocks config override
- [ ] Run `go test -race -count=1 ./cmd/skeptic/ ./internal/config/`
- [ ] Build and visually verify `--help` output shows merged `-x, --long-name` line
