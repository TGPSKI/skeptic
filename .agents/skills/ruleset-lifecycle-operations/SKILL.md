---
name: ruleset-lifecycle-operations
description: Add or update rule definitions, create and manage rule groups, and migrate rules across groups in skeptic using the property-based layout. Use when the user asks to add/update rules, add/manage groups, or reorganize `internal/rules`.
---

# Ruleset Lifecycle Operations

## Required Reference

Before making any rule or group change, read:

- `docs/RULESET_GROUPING.md`

This document is the source of truth for:

- active group files
- deterministic `DefaultRules()` composition order
- per-group testing expectations
- maintenance constraints (property-based groups, no versioned buckets)

## Operations

### 1) Add Rule

1. Pick the target group file by threat property:
   - behavior/payload signals: `rules_behavioral_signals.go`
   - agentic/LLM surfaces: `rules_agentic_surfaces.go`
   - non-code SCM/config surfaces: `rules_non_code_surfaces.go`
   - identity/IaC exposure: `rules_identity_exposure.go`
   - broad ATT&CK heuristics: `rules_attack_tactics.go`
   - campaign IOCs: use the `threat-rules-ingestion` skill (signed JSON rulepacks in `rulepacks/campaigns/`, not built-in rule files)
2. Add a `Rule` literal with full metadata (`ID`, `Title`, `Description`, `Category`, `Mitre`, `Severity`, `Pattern`, `Target`). Optionally set `ConfidenceClass` to override the default derived from the rule ID prefix (see `model.DefaultConfidenceForRuleID`); most rules should omit this and rely on the prefix-based default (`AGT-TRUST-` → definitive, `AGT-SKL-` → heuristic, `COR-`/`DRIFT-` → correlated, etc.).
3. Use `PathPattern` and/or `ContextPattern` only when narrowing is required to avoid broad false positives.
4. Update that group's `_test.go`:
   - expected rule count
   - sentinel IDs where appropriate
5. If total rules changed, update `rules_core_test.go` total count and docs metadata in `docs/RULESET_GROUPING.md`.

### 2) Update Rule

1. Locate rule by stable `ID` (keep `ID` unchanged unless there is explicit migration intent).
2. Apply the minimal change (pattern, severity, description, context gates).
3. Ensure RE2 compatibility (`regexp` package only; no lookaheads/backreferences).
4. Re-run group tests and full rules tests.
5. Update docs only if behavior, grouping, or metadata summaries changed.

### 3) Add Group

1. Create a new descriptive file name: `rules_<property>_<surface>.go` (no version/phase naming).
2. Add one top-level function returning `[]Rule` for that group.
3. Create matching test file `rules_<property>_<surface>_test.go` with:
   - `assertRuleCount`
   - `validateRuleSlice` sentinel checks
4. Wire the group into `DefaultRules()` in `rules_core.go` at the correct risk-order boundary.
5. Update:
   - `docs/RULESET_GROUPING.md`
   - `docs/ARCHITECTURE.md` rules layout table

### 4) Manage Group

Use when tuning a group without introducing a new file:

- rebalance categories/severity
- tighten patterns with `PathPattern`/`ContextPattern`
- remove overlap or duplicates
- keep group cohesive by threat property

Always keep the group's test count/sentinels current.

### 5) Migrate Group

Use when moving rules between group files:

1. Move rules by property (not chronology).
2. Keep deterministic order stable unless explicitly changing strategy.
3. Update both source and target group tests (counts + sentinels).
4. Update `DefaultRules()` composition if boundaries changed.
5. Refresh docs in `docs/RULESET_GROUPING.md` and `docs/ARCHITECTURE.md`.

## Validation Commands

```bash
# Fast package validation
go test ./internal/rules -count=1

# Full verification
go test ./... -count=1
go vet ./...
```

## Non-Rule Findings

Some finding families are emitted by `internal/checks/` rather than rule files:

- `DOM-TYPO-001`–`003`: structural domain typosquat (emitted by `internal/checks/domain_checks.go`)
- `DEP-TYPO-001`–`002`: dependency typosquat (emitted by `internal/checks/dep_checks.go`)
- `GRAPH-001`–`010`, `MID-*`: identity graph findings (emitted by `internal/checks/graph*.go`)
- `POL-GHA-001`, `POL-DOCKER-001`: policy checks (emitted by `internal/checks/policy_checks.go`)
- `BHV-*`: behavior chain findings (emitted by `internal/checks/behavior_checks.go`)
- `COR-*`, `DRIFT-*`: correlation findings (emitted by `internal/correlation/`)

These are not in `internal/rules/` group files and do not count toward the built-in rule total.

## Guardrails

- Keep property-based naming and grouping.
- Avoid reintroducing versioned/phase buckets.
- Every group file must have a corresponding test file.
- Keep `DefaultRules()` as the single composition/ordering point.
- Update documentation when group structure, counts, or strategy changes.
