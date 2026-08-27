# Trust-boundary repair corpus

`testdata/repair/` is skeptic's repair-evaluation oracle. Each instance is a small synthetic repository with one known trust-boundary defect, an independent behavior contract, an exploit check, and a scanner baseline. The corpus tests whether a candidate can repair the defect—not merely make skeptic quiet.

The external eval harness may run the task, but skeptic owns the fixtures and graders. See [`testdata/repair/README.md`](../testdata/repair/README.md) for the file layout and corpus-construction rules.

## Passing is a conjunction

Run a candidate through:

```sh
testdata/repair/tools/score-instance.sh <instance-dir> <candidate-repo-dir>
```

A candidate passes only when all checks pass:

1. Every targeted rule finding is removed.
2. The independent exploit test confirms the attack path is closed.
3. The behavior test confirms the intended workflow still works.
4. Repository tests pass when the instance supplies them.
5. No new finding at or above the defect severity appears relative to `expected-findings.json`.
6. No waiver or scanner-configuration artifact was added.

This conjunction rejects superficial fixes such as deleting a workflow, disabling its jobs, adding a waiver, or changing scanner configuration.

## Saint/liar selftest

Before using the corpus for an eval, build skeptic and run:

```sh
make build
testdata/repair/tools/selftest.sh
```

For every instance, the selftest requires:

- the unpatched repository to fail because the mutation is live;
- every `saint*.sh` repair to pass; and
- every `liar-*.sh` evasion to fail for at least one named grader check.

The suite is usable only when both directions hold. A grader that rejects valid repairs or accepts a liar is not an oracle.

## Current families

- `gh-actions/mutable-action-pin/v1` targets `SCM-TRUST-001`.
- `gh-actions/unsafe-prt-checkout/v1` targets `CI-PRT-001` and `CI-PRT-002`.

Each instance's `task.json` is authoritative for targeted rules, severity, prompt, and constraints. Regenerate its `expected-findings.json` whenever detection behavior changes.
