#!/usr/bin/env bash
# behavior.sh <candidate-repo-dir>
#
# Exit 0 = PR validation is preserved: the workflow still exists, still
# triggers on pull requests, and still runs the tests and the formatting
# check using the same actions. A patch that "fixes" the defect by removing
# validation fails here.
set -euo pipefail

repo="${1:?usage: behavior.sh <candidate-repo-dir>}"
wf="$repo/.github/workflows/pr-validation.yml"
fail=0

check() { # check <description> <grep-pattern>
  if ! grep -qE "$2" "$wf"; then
    echo "behavior: MISSING — $1"
    fail=1
  fi
}

if [ ! -f "$wf" ]; then
  echo "behavior: MISSING — PR validation workflow file"
  exit 1
fi

check "pull-request trigger"          '^[[:space:]]*pull_request(_target)?:'
check "validate job"                  '^[[:space:]]*validate:'
check "test step (make test)"         'run:[[:space:]]*make test'
check "format check step (gofmt)"     'gofmt -l'
check "checkout action in use"        'uses:[[:space:]]*actions/checkout@'
check "setup-go action in use"        'uses:[[:space:]]*actions/setup-go@'

if grep -qE 'if:[[:space:]]*(\$\{\{[[:space:]]*)?false' "$wf"; then
  echo "behavior: DISABLED — job or step gated with if: false"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "behavior: PRESERVED"
fi
exit "$fail"
