# testdata/repair — trust-boundary repair corpus (fixtures + oracle)

Task fixtures and scoring oracle for the **trust-boundary repair** eval
(leather `examples/15-trust-repair`). This directory is the fixture/oracle
half of that eval: leather owns the harness arms, task prompts, and run
archives; skeptic owns the vulnerable repositories and the graders that
judge a candidate patch. Every leather run manifest pins the skeptic
version and the fixture tree hash, so fixture drift is corpus drift and
shows up in provenance.

This is a **new sibling of `testdata/proof/`**, not a change to it —
scanner tests depend on proof fixtures staying stable. Repair fixtures are
derived from the same defect classes the proof families demonstrate, but
they are whole small repositories with intended behavior, not minimal
trigger files.

## Task shape

One instance = one small synthetic repository containing exactly **one**
known trust-boundary defect. A candidate patch passes only when it removes
the defect **and** preserves the repository's intended behavior. Layout:

```
<family>/<defect>/
  selftest/               # shared across the defect's variants
    saint*.sh             # scripted compliant patcher(s) — must PASS the scorer
    liar-*.sh             # scripted violators — must FAIL the scorer
  <variant>/
    repo/                   # the vulnerable fixture (scan target)
    task.json               # defect family, targeted rule IDs, prompt, constraints
    tests/
      behavior.sh <repo>    # exit 0 = intended behavior preserved
      exploit.sh  <repo>    # exit 0 = the attack path is closed
    expected-findings.json  # scanner baseline: counts per rule_id (generated)
```

Saint/liar scripts run with the candidate repo copy as their working
directory.

Test-script convention: both scripts take the candidate repo directory as
`$1` and use plain exit codes. `exploit.sh` deliberately fails when the
guarded artifact (e.g. the workflow) no longer exists: "nothing left to
attack" is not a repair.

## Scoring — conjunction, never Skeptic-clean alone

A Skeptic-clean scan is **never** the sole oracle: deleting the workflow,
adding a waiver, suppressing the rule, or gutting the steps all fake it.
`tools/score-instance.sh <instance> <candidate-repo>` passes a patch only
when ALL hold:

1. every targeted finding is gone (`rule_id` count = 0);
2. `tests/exploit.sh` passes (attack path closed, checked independently of
   the scanner);
3. `tests/behavior.sh` passes (intended behavior preserved);
4. `tests/repo-tests.sh` passes, when the instance provides one;
5. no **new** finding at or above the defect's severity relative to
   `expected-findings.json`;
6. no suppression artifact added (waiver files, skeptic config) — the
   scorer also never passes `--waivers`, so waivers are inert even if
   written.

The scorer emits a JSON verdict (per-check booleans + `pass`) on stdout;
exit 0 iff the conjunction holds. Component failures are first-class
results for the eval, not noise.

## Grader validation — the bidirectional selftest

`tools/selftest.sh` is the gate that must pass **before any model run**:
for every instance, the unpatched repo must FAIL the scorer (the mutation
is live), every `selftest/saint*.sh` must PASS, and every
`selftest/liar-*.sh` must FAIL — with the check that caught each liar
reported. A suite where any saint fails or any liar passes is broken and
may not be used to score anything.

## Corpus construction rules

- **Known-good → mutate**: fixtures start from a safe form; one controlled
  mutation introduces the defect; the exploit test must fail pre-patch.
- **Contamination control**: base repositories are synthetic (invented
  projects, invented names) — never copies of public repos whose safe form
  a model may have memorized.
- **One defect per instance**; the scanner baseline must be explainable by
  the targeted rules alone.
- Fixture READMEs and helper files must avoid scanner trigger phrases so
  the baseline stays clean (the proof corpus shows prose can match rules).

## Families

| family | defect | targeted rules | status |
|---|---|---|---|
| gh-actions | mutable-action-pin | SCM-TRUST-001 | pilot v1 |
| gh-actions | unsafe-prt-checkout | CI-PRT-001, CI-PRT-002 | pilot v1 |
| gh-actions | excessive-permissions | CLOUD-ID-001 | planned |
| gh-actions | event-field-injection | CI-ABUSE-002/003/005 | planned |
