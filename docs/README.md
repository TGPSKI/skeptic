# skeptic documentation

Start with the section that matches what you are trying to do.

## Users

- [Configuration](CONFIGURATION.md) — scan modes, presets, config discovery, flags, and waivers.
- [GitHub Action](GITHUB_ACTION.md) — CI installation, inputs, permissions, SARIF, and recipes.
- [Encrypted corpus](CORPUS.md) — safely store and scan hostile agentic artifacts.
- [Repair corpus](REPAIR_CORPUS.md) — use the trust-boundary repair fixtures and scoring oracle.

## Operators

- [Server and MCP](SERVER.md) — daemon scheduling, HTTP API, MCP tools, authentication, and filesystem boundaries.
- [Runtime safety](RUNTIME_SAFETY.md) — deployment constraints for local, CI, container, and privileged environments.
- [Rule-set sources](RULESET_SOURCES.md) — provenance and research behind built-in and campaign detections.

## Contributors

- [Architecture](ARCHITECTURE.md) — package boundaries, scan pipeline, data flow, and testing model.
- [Rule-set grouping](RULESET_GROUPING.md) — rule ownership, composition order, counts, and maintenance guidance.
- [Module reference](modules/) — package-level APIs and implementation notes.
- [Product-shaping memo](product-shaping-memo.md) — product boundaries and design rationale.
- [Contribution guide](../CONTRIBUTING.md) — rule IDs, quality gates, and pull-request workflow.

## Agents

- [Repository agent instructions](../AGENTS.md) — hard constraints, dependency direction, and verification requirements.
- [Agent skill index](../.agents/README.md) — repository workflows for rules, docs, releases, CLI flags, and Actions updates.
- [Repair corpus](REPAIR_CORPUS.md) — the eval contract agents must preserve when repairing fixtures.
