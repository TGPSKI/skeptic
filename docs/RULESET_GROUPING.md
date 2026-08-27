# Ruleset Grouping Strategy

This document describes the current `internal/rules` layout after refactoring to property-based groups.

## Goals

- Remove version/phase naming (`expansion_v2`, `phase1`) from the primary ruleset layout.
- Group rules by threat property and operating surface instead of implementation history.
- Keep deterministic assembly in one place (`rules_core.go`).
- Ensure each group file has a dedicated test file with count and sentinel-ID assertions.
- Ship literal campaign IOCs as signed JSON under `rulepacks/campaigns/<campaign>/` (see `docs/RULESET_SOURCES.md`), not in a dedicated `rules_supply_chain_campaigns.go` file.

## Current Group Files

| File | Purpose | Rule Count |
|---|---|---:|
| `rules_behavioral_signals.go` | Behavioral payload signals (encoding, obfuscation, CI abuse, container escape, workflow trust, CI build hygiene, CI env exposure, shell eval, infra policy, supply chain tooling) | 80 |
| `rules_agentic_surfaces.go` | Agent/LLM ecosystem poisoning, MCP abuse, memory poisoning, tool-output injection, trust-laundering, MCP credential interpolation, agent skill permissions | 67 |
| `rules_non_code_surfaces.go` | Git metadata, package-manager config poisoning, IDE/devcontainer execution surfaces, dependency bot config, container registry trust | 26 |
| `rules_identity_exposure.go` | Machine-identity policy risk (OIDC, IAM, service account) and infra credential exposure | 7 |
| `rules_attack_tactics.go` | ATT&CK tactic-aligned broad detections and structural credential/C2 patterns | 48 |
| `rules_core.go` | Deterministic composition and regex/literal-hint compilation | n/a |

Total built-in rules: **227** (see `TestDefaultRulesCompositionIncludesAllGroups` in `rules_core_test.go`).

## Composition Order

`DefaultRules()` composes groups in this fixed order:

1. Behavioral signals
2. Agentic surfaces
3. Non-code surfaces
4. Infrastructure credential exposure and machine-identity policy signals
5. ATT&CK tactic coverage

Rationale:

- Lead with high-signal behavior and workflow-trust patterns.
- Follow with agentic and non-code risk surfaces.
- Keep identity-focused policy signals together.
- Append broad ATT&CK coverage heuristics last.

## Ruleset Metadata Snapshot

- **Total rules:** 227 built-in (campaign IOCs are additional JSON rule packs when `rules_dir` is configured).
- For authoritative per-group counts and sentinel IDs, run `go test ./internal/rules/ -v`.

Severity distribution has been rebalanced to reflect skeptic's sharpened focus: CI secret hygiene (`CI-SECRET-*`) at Low, broad ATT&CK tactic heuristics (`ATK-*`) at Low where tuned for noise, and structural agentic/workflow rules at higher severities as appropriate.

## Testing Model

Each grouped rules file has its own test:

- `rules_behavioral_signals_test.go`
- `rules_agentic_surfaces_test.go`
- `rules_non_code_surfaces_test.go`
- `rules_identity_exposure_test.go`
- `rules_attack_tactics_test.go`

`rules_core_test.go` validates:

- Overall count (227, validated by `rules_core_test.go`)
- Presence of cross-group sentinel IDs
- Deterministic group boundary order in `DefaultRules()`

## Design Choices

- **Property-based naming:** filenames describe threat properties and surfaces rather than release milestones.
- **Cohesion over chronology:** related detections are kept together (for example, OIDC federation + IAM policy in one identity-focused group).
- **Agentic threat locality:** trust-laundering rules are colocated with agentic poisoning surfaces because they share the same attacker objective (instruction-channel manipulation).
- **Non-code isolation:** SCM/package-manager metadata threats are separated from code-centric behavior heuristics to keep review and tuning focused.
- **Single assembly point:** `rules_core.go` is the only place where ordering is defined and compilation steps are applied.
- **Campaign IOCs externalized:** TeamPCP-style literal indicators live in `rulepacks/campaigns/teampcp/` (and similar directories) as versioned JSON packs.

## Maintenance Guidance

- Add new rules to the file whose threat property matches best; avoid creating versioned buckets.
- If a group grows too broad, split by property (for example, split `behavioral_signals` by execution stage) rather than by chronology.
- Update the corresponding group test with both count and sentinel IDs whenever rules are added/removed.
- Add new literal campaign IOCs to the appropriate signed JSON under `rulepacks/campaigns/`, not as new built-in Go rules, unless the pattern is structural and ecosystem-agnostic.
