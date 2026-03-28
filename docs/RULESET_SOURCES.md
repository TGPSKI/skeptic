# Ruleset Sources and Mapping

Last updated: 2026-04-01

This scanner's expanded ruleset uses a pattern-based approach derived from the references below.

## Primary Sources

- TeamPCP campaign landscape:
  - `trivy-threat-landscape.html` (repo-local canonical file)
  - SANS report: "When the Security Scanner Became the Weapon" (Hartman/Johnson, Mar 2026)
  - `affected_packages_public-1.csv` impacted dependency blast-radius dataset
- Agent skills poisoning taxonomy and examples:
  - [Snyk ToxicSkills study](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)
- MCP poisoning mechanics and attack examples:
  - [OWASP MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)
  - [Invariant MCP security notification](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks.html)
- MCP protocol-level security guidance:
  - [Model Context Protocol security best practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)
  - [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- Memory poisoning category context:
  - [OWASP Agent Memory Guard](https://owasp.org/www-project-agent-memory-guard/)
- 2026 scanner-risk research themes incorporated into detections:
  - scanner tag-poisoning and CI runner memory-harvesting tradecraft
  - eBPF visibility-blinding and stack-truncation evasion concepts
  - LLM security scanner evasion via multilingual/encoding manipulation
  - AI false-positive coercion and context-bypass poisoning patterns
- ATT&CK tactic references used to expand coverage:
  - [Execution TA0002](https://attack.mitre.org/tactics/TA0002/)
  - [Persistence TA0003](https://attack.mitre.org/tactics/TA0003/)
  - [Defense Evasion TA0005](https://attack.mitre.org/tactics/TA0005/)
  - [Lateral Movement TA0008](https://attack.mitre.org/tactics/TA0008/)
  - [Collection TA0009](https://attack.mitre.org/tactics/TA0009/)
  - [Command and Control TA0011](https://attack.mitre.org/tactics/TA0011/)

## Rule Family Mapping

- `TPCP-*`:
  - TeamPCP campaign indicators, hashes, IOCs, persistence artifacts, dependency/version windows — loaded from signed JSON under `rulepacks/campaigns/teampcp/` (e.g. `rules.2026-03-28.json`) when `rules_dir` includes that pack; not part of the built-in Go ruleset
- `AGT-SKL-*`:
  - Skills poisoning patterns (prompt injection directives, hidden instructions, obfuscated setup, suspicious download/execute chains, credential targeting, multilingual/encoding evasion, scanner suppression attempts)
- `AGT-MCP-*`:
  - MCP poisoning patterns (tool shadowing, hidden AI-visible instructions, insecure endpoint and startup patterns, broad scope/token risk, SSRF-prone URL usage, lookalike/typosquat server hints)
- `AGT-MEM-*`:
  - Memory poisoning indicators (cross-session persistence directives, guardrail disabling, secret persistence, context/RAG bypass poisoning)
- `AGT-OUT-*`:
  - Tool-output injection indicators (instruction-like outputs, wrapper tags, and scanner-suppression phrasing that should be treated as untrusted data)
- `AGT-ART-*`:
  - Agentic artifact discovery (skill manifests, MCP configs, persistent memory files)
- `INGEST-*` and `*-ingested` categories:
  - Auto-generated IOC and ecosystem package rules produced by `skeptic ingest` from user-supplied threat intelligence sources
- `ATK-*`:
  - ATT&CK tactic-aligned heuristics covering execution, persistence, defense evasion, lateral movement, collection, and C2 (including managed-runtime blind spots and eBPF tampering markers)
- `SKN-PROT-*`:
  - Scanner self-protection findings for high-risk local configuration integrity issues (for example world-writable sensitive scanner artifacts)
- `SCM-TRUST-*`:
  - Source control and workflow trust markers (mutable refs/tags, force-push indicators, unpinned remote bootstrap patterns)
- `CI-SECRET-*`:
  - CI secret hygiene indicators (env dumps, verbose tracing, token persistence, secret-bearing uploads)
- `CLOUD-ID-*`:
  - Machine identity risk markers (over-privileged roles, wildcard federated trust, static client secrets, broad token exchange flows)
- `POL-*`:
  - Built-in policy checks over workflow trust, dependency integrity, and cloud identity trust semantics
- `BHV-*`:
  - Behavior-chain detections requiring multi-step attack semantics in a single artifact (tamper + access + exfil)
- `MID-*` and `AIW-*`:
  - Focus-mode checks for machine identity and AI workload operating models
- `dependency-exposure`:
  - Package-exposure indicators generated from affected dependency datasets (including structured CSV sources)

## Notes on Detection Philosophy

- Rules are intentionally high-signal string/regex heuristics for portable local scanning.
- Policy and behavior checks complement regex rules with file-aware and chain-aware detections.
- The scanner is designed for **triage and hunting**, not proof of compromise by itself.
- Use findings as leads for deeper validation (runtime telemetry, provenance checks, and manual review).
- Ingested rules are generated heuristically from source text and should be reviewed before strict CI gating.

