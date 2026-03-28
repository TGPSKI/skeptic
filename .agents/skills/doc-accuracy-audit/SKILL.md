---
name: doc-accuracy-audit
description: >-
  Audit a document against the codebase for accuracy, then tighten it:
  verify claims, cut drift, simplify, restructure for the reader. Use when
  the user says a doc is loose, stale, or wrong, or asks to tighten/audit
  a README, guide, config reference, or any prose that makes claims about code.
---

# Doc Accuracy Audit

Audit a document against its codebase, then tighten the result. Every
claim the document makes — a flag name, a default value, a required
workflow step, a feature description — is either confirmed, updated,
simplified, or eliminated. The end state is a shorter, accurate document
that leads with what matters most to the reader.

## When to use

- User says a doc is "loose," "stale," "wrong," or "out of date"
- User asks to "tighten" or "audit" a specific document
- A document references flags, APIs, architecture, or workflows that may
  have drifted from the code
- After a large code change when documentation consistency is uncertain

## Inputs

1. **Target document** — the file to audit (README, guide, config ref, skill, etc.)
2. **Codebase scope** — where to verify claims (usually inferred from the repo)
3. **Audience** — who reads this document (developer, operator, contributor, agent)

If the user doesn't specify audience, infer from context: README → developer
using the tool; ARCHITECTURE.md → contributor modifying internals;
SKILL.md → AI agent executing a workflow.

## Workflow

### 1. Extract auditable claims

Read the target document. Extract every verifiable claim into a mental
checklist. Claims fall into these categories:

| Category | Examples |
|----------|----------|
| **Flag/API** | `--mode developer` is the default; `BuildTrustAssessment` returns a verdict |
| **Behavior** | "the daemon is required for scanning"; "heuristic findings are hidden in developer mode" |
| **Architecture** | "correlation runs after scan completion"; "config depends only on model" |
| **Existence** | "see ROADMAP.md for details"; "AGT-SKL-009 detects tool shadowing" |
| **Workflow** | "start daemon in terminal 1, then MCP in terminal 2" |
| **Counts/values** | "200+ built-in rules"; "default max-bytes is 2 MiB" |

### 2. Verify each claim against source

For each claim, run the minimum search to confirm or refute it:

- **Flag claims** → grep the flag registration in the CLI entry point
- **API claims** → grep the function signature in the relevant package
- **Behavior claims** → read the implementation and trace the code path
- **Existence claims** → glob or ls for the referenced file/symbol
- **Workflow claims** → trace whether each step is actually required
  (versus optional or handled automatically)
- **Count/value claims** → grep or run the relevant test assertion

Batch independent searches in parallel. Don't read entire files when a
targeted grep answers the question.

Record each claim as one of:

| Verdict | Action |
|---------|--------|
| **Confirmed** | Keep as-is (or note for later simplification) |
| **Outdated** | Update to match current code |
| **Misleading** | Rewrite to reflect actual behavior |
| **Unnecessary** | Mark for elimination — the claim adds no value to the reader |
| **Missing** | The document omits something important that the code does |

### 3. Apply tightening decisions

Work through the document applying five operations:

#### Confirm
The claim is accurate. Leave it unless it can be said more concisely.

#### Update
The claim was true once but the code changed. Replace with the current
fact. Cite the source (file, line, function) in your reasoning but not
in the document itself.

#### Simplify
The claim is accurate but overweight. Compress it. Common patterns:

- A list of 8 similar items → a table or a link to the full reference
- A paragraph explaining something the reader can see from a one-liner → the one-liner
- Three code examples that differ only in `--format` → one example with a note
- A flag dump that belongs in `--help` → a curated table of the 10 flags
  that matter, plus a link

#### Eliminate
The claim is wrong, outdated, or adds nothing. Remove it. Common
candidates:

- Fictional demo transcripts with nonexistent rule IDs
- Workflow steps that aren't actually required (e.g., "start daemon"
  when the tool works without one)
- Marketing language that doesn't help the reader use the tool
- Duplicated information available in a linked reference

#### Add
The document is missing something the reader needs. Add it concisely.
Common additions:

- A primary use case that was buried or absent
- A "what this is NOT" section to prevent misuse
- A link to the full reference when the document trimmed detail
- Honest known-weakness notes that build trust

### 4. Restructure for reader experience

After claim-level edits, evaluate the document's structure:

- **Lead with the thesis.** The first 3 lines should tell the reader
  what this thing is and why it exists — not "most tools do X."
- **Primary use case goes early.** If the tool's main value is MCP
  trust audit, don't bury it after 8 CLI workflow examples.
- **Group by reader intent, not by implementation.** "Common workflows"
  beats "list of every flag." "What it detects" beats "feature bullet dump."
- **Push reference material to references.** A README should not contain
  50 flags. A skill file should not inline an entire API surface.
- **Cut redundancy.** If three examples differ by one flag value, show
  one and mention the variants.
- **Honest weaknesses build trust.** A "Known weaknesses" or "What this
  is NOT" section makes the rest of the document more credible.

### 5. Validate

After editing:

1. **Accuracy** — re-check any claims you updated against source
2. **Links** — verify all internal links still resolve
3. **Completeness** — confirm nothing important was lost in the cut
4. **Length** — the document should be shorter or, if content was added,
   more information-dense per line
5. **Reader test** — a person who has never seen the tool should be able
   to read the first two sections and know: what it does, when to use
   it, and how to start

## Judgment calls

### When to keep detail vs. link to a reference

Keep it if the reader needs it to complete their immediate task without
leaving the document. Link it if it's supplementary, rarely needed, or
maintained in a more authoritative location.

### When to eliminate vs. demote

Eliminate if the content is wrong or actively misleading. Demote (move
to a subsection, collapse, or link) if it's accurate but distracting
from the primary narrative.

### When "shorter" is wrong

If the document is already concise but inaccurate, fixing accuracy
may make it longer. That's fine. The goal is accuracy and reader
experience, not minimum line count. But excess length is a symptom
of unfocused writing, so it's usually a valid signal.

## Example: README audit pattern

This is the pattern that produced this skill. It generalizes to any
document.

```
1. Read README (445 lines)
2. Extract claims:
   - "start daemon in terminal 1" → is daemon required? → NO, scans run in-process
   - "SCM-TRUST-001" in demo transcript → does this rule exist? → NO
   - 50 flags listed individually → are these in --help? → YES → cut to 12, link reference
   - "helfp" → typo
   - exit code 3 description → does it mention mode gating? → NO → update
3. Apply:
   - Eliminate fictional transcript
   - Update MCP section: daemonless path first, daemon optional
   - Simplify flags: table of 12 + link to CONFIGURATION.md
   - Add "What skeptic is not" section
   - Add mode/confidence explanation early
4. Restructure:
   - Generic opener → product thesis in 2 sentences
   - Feature dump → "The gap it fills" comparison table
   - MCP buried after 8 examples → promoted to primary use case
5. Validate: flag defaults, rule count, subcommands, exit codes
   all verified against source
   Result: 445 → 297 lines, more accurate, better reader experience
```

## Guardrails

- Never fabricate claims. If you can't verify something, say so.
- Preserve the document's existing voice and style when possible.
- Don't add comments explaining your edits inside the document.
- Don't expand scope — audit the document the user pointed at, not
  every doc in the repo (unless asked).
- If the audit reveals code bugs (not just doc bugs), report them
  separately rather than papering over them in documentation.
