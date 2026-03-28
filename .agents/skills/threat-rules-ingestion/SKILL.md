---
name: threat-rules-ingestion
description: Ingest fresh security research from URLs/files, generate signed scanner rule packs, and validate with policy and behavior scan styles across ecosystems. Use when the user asks to operationalize new threat intel into skeptic detections.
---

# Threat Rules Ingestion

## Workflow

1. Gather sources and ecosystems.
2. Generate a dated rule pack with strict quality checks.
3. **Curate the pack** — prune web-scrape noise and over-broad patterns.
4. **De-duplicate** — remove rules that overlap with the built-in library.
5. **Classify** — map each surviving rule to an existing group or flag as standalone.
6. Sign the pack (detached `.sig`).
7. Validate signed pack loading.
8. Run a hybrid scan with policy checks enabled.

## Commands

```bash
# Generate
go run ./cmd/skeptic ingest \
  --source "<source-1>" \
  --source "<source-2>" \
  --ecosystems "<ecosystems>" \
  --rule-quality strict \
  --out "<output-json>"

# Sign (after curation + dedup)
go run ./cmd/skeptic sign-rulepack \
  --rules-file "<output-json>" \
  --private-key "<private-key>"

# Validate signed loading in isolation
go run ./cmd/skeptic \
  --rules-file "<output-json>" \
  --rules-pubkey "<public-key>" \
  --require-signed-rules \
  --no-default-rules \
  --mode developer \
  --profile repo \
  --path .. \
  --fail-on medium

# Run combined scan (always set --profile repo to avoid dev-profile home-dir sweep)
go run ./cmd/skeptic \
  --rules-file "<output-json>" \
  --rules-pubkey "<public-key>" \
  --require-signed-rules \
  --scan-style hybrid \
  --policy-checks \
  --mode developer \
  --profile repo \
  --path .. \
  --fail-on high
```

---

## Post-Generation Curation

When sources are URLs (web pages), the HTML scrape includes page chrome
that the ingest pipeline may extract as false IOC patterns. **Always
review and prune the generated pack before signing.**

### Step 1: Identify noise

Read the generated JSON and flag rules whose `pattern` field matches any
of these categories:

| Category | Examples | Why it's noise |
|----------|----------|----------------|
| Analytics / tracking | `posthog`, `reb2b`, `segment`, `mixpanel`, `hotjar`, `gtag`, `ga4`, `hubspot`, `intercom`, `amplitude` | Site telemetry JS embedded in page HTML |
| Font / asset loaders | `webfont.load`, `typekit`, `fonts.googleapis`, `use.fontawesome` | Web font bootstrap code |
| DOM manipulation stubs | `document.createElement`, `getElementsByTagName`, `parentNode.insertBefore`, `classList`, `className` | Generic JS DOM API calls |
| JS runtime primitives | `Array.prototype`, `Object.keys`, `toString`, `push`, `split`, `length`, `async`, `src` | Ubiquitous JS tokens |
| CDN / infra domains | `cdn.jsdelivr.net`, `unpkg.com`, `cdnjs.cloudflare.com`, `ajax.googleapis.com` | Legitimate CDN origins |
| Marketing / consent | `cookieconsent`, `onetrust`, `gdpr`, `privacy-policy` | Cookie banner JS |

### Step 2: Prune noise

Remove matching rules from the `rules` array in the JSON file. Use a
script or manual edit — do not re-run ingest (that would re-generate the
noise).

```python
# Example pruning script (adjust noise_patterns as needed)
import json, re, sys

noise_patterns = [
    r"posthog", r"reb2b", r"segment\.(com|io)", r"mixpanel",
    r"hotjar", r"gtag", r"hubspot", r"intercom", r"amplitude",
    r"webfont\.load", r"typekit", r"fonts\.googleapis",
    r"document\.createElement", r"getelementsbytagname",
    r"parentnode\.insertbefore", r"classlist", r"classname",
    r"array\.prototype", r"\.tostring", r"\.push\b", r"\.split\b",
    r"\.length\b", r"\.async\b", r"\.src\b",
    r"cdn\.jsdelivr", r"unpkg\.com", r"cdnjs\.cloudflare",
    r"cookieconsent", r"onetrust",
]

with open(sys.argv[1]) as f:
    pack = json.load(f)

before = len(pack["rules"])
compiled = [re.compile(p, re.IGNORECASE) for p in noise_patterns]
pack["rules"] = [
    r for r in pack["rules"]
    if not any(c.search(r["pattern"]) for c in compiled)
]
after = len(pack["rules"])

with open(sys.argv[1], "w") as f:
    json.dump(pack, f, indent=2)

print(f"pruned {before - after} noise rules ({before} -> {after})")
```

Run: `python3 prune_noise.py <output-json>`

### Step 3: Over-Broad Pattern Heuristic

Also remove rules whose pattern is a single common token that would
match most codebases and produce excessive false positives:

- Patterns shorter than 8 characters (e.g., `e\.init`, `t\.push`)
- Patterns matching generic filenames without a distinguishing qualifier
  (e.g., bare `index\.js`, `package\.json`, `extension\.js`)
- Patterns matching language-standard API calls
  (e.g., `process\.platform`, `child_process`, `require`)

These tokens may appear in the advisory as context for the attack chain,
but as standalone regex patterns they are not actionable detections.

---

## De-Duplication Against Built-In Rules

After noise pruning and before signing, de-duplicate the ingested rules
against the 200+ built-in rules in `internal/rules/`. **Do not ingest a
rule that the built-in library already covers.**

**Note:** Some finding families are emitted by `internal/checks/` (e.g.,
`DOM-TYPO-*`, `DEP-TYPO-*`, `GRAPH-*`, `MID-*`, `POL-*`, `BHV-*`) and
by `internal/correlation/` (e.g., `COR-*`, `DRIFT-*`). These are not
in the rule files and do not appear in the prefix registry below. Ingested
rules should not try to duplicate these check-emitted finding families.

### Overlap dimensions

Check each ingested rule against the built-in library on three axes,
from strongest to weakest signal:

| Axis | How to check | Action |
|------|-------------|--------|
| **Exact ID** | Ingested rule ID matches a built-in rule ID | **Drop** — direct duplicate |
| **Pattern equivalence** | Ingested `pattern` is identical (or functionally identical after whitespace normalization) to a built-in `pattern` | **Drop** — same detection |
| **Semantic subsumption** | A built-in rule's pattern already matches a strict superset of the ingested rule's pattern (e.g., built-in `curl.*\|.*sh` subsumes ingested `curl.*\|.*bash`) | **Drop** — already covered |

When uncertain about subsumption, keep the ingested rule — false
negatives from missing a novel IOC are worse than mild overlap.

### Built-in ID prefix registry

Use this to quickly identify ID collisions:

| Prefix | Group file | Domain |
|--------|-----------|--------|
| `TPCP-ACT-*` | `rules_supply_chain_campaigns.go` | GitHub Actions campaign indicators |
| `TPCP-TRV-*` | `rules_supply_chain_campaigns.go` | Trivy/binary-image indicators |
| `TPCP-NPM-*` | `rules_supply_chain_campaigns.go` | npm supply chain |
| `TPCP-PY-*` | `rules_supply_chain_campaigns.go` | PyPI supply chain |
| `TPCP-VSX-*` | `rules_supply_chain_campaigns.go` | VSCode extension supply chain |
| `TPCP-PERSIST-*` | `rules_supply_chain_campaigns.go` | Persistence artifacts |
| `TPCP-TEL-*` | `rules_supply_chain_campaigns.go` | Telemetry/staging domains |
| `TPCP-IOC-*` | `rules_supply_chain_campaigns.go` | Network IOCs |
| `TPCP-CRED-*` | `rules_supply_chain_campaigns.go` | Credential harvesting |
| `SCM-TRUST-*` | `rules_supply_chain_campaigns.go` | SCM workflow trust |
| `CI-SECRET-*` | `rules_supply_chain_campaigns.go` | CI secret hygiene |
| `ENC-EXFIL-*` | `rules_behavioral_signals.go` | Encoded exfiltration |
| `OBF-CMD-*` | `rules_behavioral_signals.go` | Obfuscated commands |
| `OBF-ENT-*` | `rules_behavioral_signals.go` | Entropy/obfuscation |
| `AGT-EXP-*` | `rules_behavioral_signals.go` | Agentic exploit patterns |
| `CTR-ESC-*` | `rules_behavioral_signals.go` | Container escape |
| `CI-ABUSE-*` | `rules_behavioral_signals.go` | CI pipeline abuse |
| `RUGPULL-*` | `rules_behavioral_signals.go` | Rug-pull indicators |
| `AGT-ART-001..003` | `rules_agentic_surfaces.go` | Agent artifact poisoning |
| `AGT-SKL-*` | `rules_agentic_surfaces.go` | Skills poisoning |
| `AGT-MCP-*` | `rules_agentic_surfaces.go` | MCP poisoning |
| `AGT-MEM-*` | `rules_agentic_surfaces.go` | Memory poisoning |
| `AGT-OUT-*` | `rules_agentic_surfaces.go` | Tool-output injection |
| `AGT-TRUST-*` | `rules_agentic_surfaces.go` | Trust laundering |
| `SCM-GIT-*` | `rules_non_code_surfaces.go` | Git metadata surfaces |
| `SCM-PKG-*` | `rules_non_code_surfaces.go` | Package manager config |
| `AGT-ART-004..006` | `rules_non_code_surfaces.go` | IDE/devcontainer surfaces |
| `IAC-TF-*` | `rules_identity_exposure.go` | Terraform credential exposure |
| `IAC-ANS-*` | `rules_identity_exposure.go` | Ansible credential exposure |
| `IAC-HELM-*` | `rules_identity_exposure.go` | Helm credential exposure |
| `CLOUD-ID-*` | `rules_identity_exposure.go` | Machine identity policy |
| `ATK-EXE-*` | `rules_attack_tactics.go` | ATT&CK execution |
| `ATK-PER-*` | `rules_attack_tactics.go` | ATT&CK persistence |
| `ATK-DEF-*` | `rules_attack_tactics.go` | ATT&CK defense evasion |
| `ATK-LAT-*` | `rules_attack_tactics.go` | ATT&CK lateral movement |
| `ATK-COL-*` | `rules_attack_tactics.go` | ATT&CK collection |
| `ATK-CC-*` | `rules_attack_tactics.go` | ATT&CK command & control |

### De-duplication procedure

1. **Load the built-in rule list** by scanning every `ID:` and `Pattern:` field
   in `internal/rules/rules_*.go` (exclude `_test.go`, `_core.go`).
2. **For each ingested rule**, check:
   - Does the ID exist in the built-in list? → Drop.
   - Does the normalized pattern (`strings.ToLower`, collapse `\s+` to ` `)
     match a built-in pattern? → Drop.
   - Does a built-in pattern regex-match the ingested pattern's literal
     IOC content (e.g., a domain, hash, filename)? → Drop (already detected).
3. **Log every drop** with the reason and the built-in rule ID that covers it.
4. **Report the dedup summary**: `N ingested → M unique (dropped D: X ID-dupes,
   Y pattern-dupes, Z subsumed)`.

### Quick extraction commands

```bash
# Extract all built-in rule IDs
rg 'ID:\s+"([^"]+)"' internal/rules/rules_*.go -o --no-filename -r '$1' | sort > /tmp/builtin-ids.txt

# Extract all built-in patterns
rg 'Pattern:\s+"([^"]+)"' internal/rules/rules_*.go -o --no-filename -r '$1' | sort > /tmp/builtin-patterns.txt

# Check for ID collisions against an ingested pack
python3 -c "
import json, sys
with open(sys.argv[1]) as f: pack = json.load(f)
ids = {r['id'] for r in pack['rules']}
builtins = set(open('/tmp/builtin-ids.txt').read().splitlines())
dupes = ids & builtins
print(f'{len(dupes)} ID collisions: {sorted(dupes)}')
" <output-json>

# Check for pattern collisions
python3 -c "
import json, sys, re
with open(sys.argv[1]) as f: pack = json.load(f)
norm = lambda s: re.sub(r'\s+', ' ', s.lower().strip())
bp = set(open('/tmp/builtin-patterns.txt').read().splitlines())
bp_norm = {norm(p) for p in bp}
dupes = [(r['id'], r['pattern']) for r in pack['rules'] if norm(r['pattern']) in bp_norm]
print(f'{len(dupes)} pattern collisions:')
for rid, pat in dupes: print(f'  {rid}: {pat[:80]}')
" <output-json>
```

---

## Rule Group Classification

After de-duplication, classify each surviving ingested rule into an
existing built-in group — or mark it for a standalone campaign pack.

### Category → group mapping

Map each ingested rule's `category` field to the best-fit group file:

| Ingested category | Target group file | Rationale |
|-------------------|-------------------|-----------|
| `github-actions`, `npm`, `pypi`, `ide-extension`, `binary-image` | `rules_supply_chain_campaigns.go` | Ecosystem-specific supply chain |
| `persistence`, `exfiltration`, `network-ioc`, `command-control`, `credential-access` (campaign-tied IOCs) | `rules_supply_chain_campaigns.go` | Campaign indicators with specific IOCs |
| `scm-trust`, `ci-secret-hygiene` | `rules_supply_chain_campaigns.go` | SCM/CI trust signals |
| `encoded-exfiltration`, `obfuscated-command`, `obfuscation` | `rules_behavioral_signals.go` | Encoding/obfuscation behavior |
| `persistence` (generic behavioral, no specific IOC) | `rules_behavioral_signals.go` | Behavioral persistence patterns |
| `rug-pull`, `container-escape`, `ci-abuse` | `rules_behavioral_signals.go` | Behavioral attack signals |
| `mcp-agentic` | `rules_behavioral_signals.go` | Agentic behavioral patterns |
| `skills-poisoning`, `mcp-poisoning`, `memory-poisoning` | `rules_agentic_surfaces.go` | Agent/LLM attack surfaces |
| `tool-output-injection`, `trust-laundering`, `artifact` | `rules_agentic_surfaces.go` | Agentic trust manipulation |
| `non-code-surface` | `rules_non_code_surfaces.go` | Git/package/IDE metadata |
| `credential-access` (IaC/cloud, no campaign IOC) | `rules_identity_exposure.go` | Infrastructure credentials |
| `machine-identity` | `rules_identity_exposure.go` | Cloud identity policy |
| `execution`, `defense-evasion`, `lateral-movement`, `collection` | `rules_attack_tactics.go` | ATT&CK tactic heuristics |

### Disambiguation: campaign IOC vs. behavioral pattern

Many categories (e.g., `persistence`, `credential-access`, `command-control`)
appear in both `supply_chain_campaigns` and `behavioral_signals`. Use this
heuristic:

- **Campaign-specific**: the rule's pattern contains a literal IOC
  (domain, hash, filename, extension ID, IP address, known tool name).
  → `rules_supply_chain_campaigns.go`
- **Behavioral/generic**: the rule's pattern matches a technique
  (encoding method, API call pattern, configuration key) without a
  campaign-specific literal.
  → `rules_behavioral_signals.go` or `rules_attack_tactics.go`

### When to create a standalone group

Create a standalone rule pack (kept as an external `.json` file in
`rulepacks/campaigns/`) instead of merging into built-in groups when:

- The advisory is for a **specific, time-bounded campaign** with IOCs
  that will age out (C2 domains, payload hashes, extension publisher IDs).
- The rules are **not general-purpose detections** — they would not help
  scan any repository unrelated to the campaign.
- The pack should be **loadable and removable independently** without
  modifying the core rule library.

When a rule pack contains a mix of campaign IOCs and general behavioral
patterns, split them:

1. Keep campaign-specific IOCs (domains, hashes, filenames) in the
   standalone external pack.
2. Promote general behavioral patterns (technique detections that apply
   broadly) into the appropriate built-in group file via PR.

### Classification output

For each surviving rule, record its classification:

```
RULE-ID  | category         | target                              | reason
---------|------------------|-------------------------------------|--------
IOL-C2-001 | command-control | standalone: iolitelabs campaign pack | campaign-specific C2 domain
IOL-RCE-001 | execution      | rules_attack_tactics.go             | generic curl|sh pattern (promote)
IOL-GK-001 | defense-evasion | rules_behavioral_signals.go         | generic Gatekeeper bypass (promote)
```

Rules marked "promote" are candidates for merging into the built-in
library. Rules marked "standalone" stay in the external pack.

---

## Checklist

- Rule pack is non-empty and includes mixed severities.
- **Web-scrape noise has been pruned** (analytics, fonts, DOM stubs, JS primitives).
- **Over-broad patterns removed** (single common tokens, generic filenames).
- **De-duplication completed** against built-in library (ID, pattern, subsumption).
- **Dedup summary logged** (counts of ID-dupes, pattern-dupes, subsumed).
- **Each rule classified** into an existing group or standalone pack.
- **Campaign/behavioral split applied** if pack mixes IOCs and techniques.
- Top critical/high rules are manually spot-checked.
- Advisory-specific IOCs confirmed present after pruning and dedup.
- Detached signature exists and verifies.
- Pack filename is date-versioned.
- Validation scan passes argument/runtime checks.
- Validation and combined scans use `--profile repo` to avoid dev-profile home-dir sweep.
