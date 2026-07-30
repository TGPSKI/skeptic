#!/usr/bin/env bash
# behavior.sh <candidate-repo-dir>
#
# Exit 0 = the repository's intended behavior is preserved: the release
# pipeline still exists, still triggers on version tags, and still builds,
# tests, uploads, and publishes using the same actions and commands.
# These are structural assertions on the workflow text — a patch that
# "fixes" the defect by removing functionality fails here.
set -euo pipefail

repo="${1:?usage: behavior.sh <candidate-repo-dir>}"
wf="$repo/.github/workflows/release.yml"
fail=0

check() { # check <description> <grep-pattern>
  if ! grep -qE "$2" "$wf"; then
    echo "behavior: MISSING — $1"
    fail=1
  fi
}

if [ ! -f "$wf" ]; then
  echo "behavior: MISSING — release workflow file"
  exit 1
fi

check "tag-push trigger"                 '^[[:space:]]*tags:'
check "build job"                        '^[[:space:]]*build:'
check "release job"                      '^[[:space:]]*release:'
check "build step (make build)"          'run:[[:space:]]*make build'
check "test step (make test)"            'run:[[:space:]]*make test'
check "checkout action in use"           'uses:[[:space:]]*actions/checkout@'
check "setup-go action in use"           'uses:[[:space:]]*actions/setup-go@'
check "upload-artifact action in use"    'uses:[[:space:]]*actions/upload-artifact@'
check "download-artifact action in use"  'uses:[[:space:]]*actions/download-artifact@'
check "release-publish action in use"    'uses:[[:space:]]*softprops/action-gh-release@'

if grep -qE 'if:[[:space:]]*(\$\{\{[[:space:]]*)?false' "$wf"; then
  echo "behavior: DISABLED — job or step gated with if: false"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "behavior: PRESERVED"
fi
exit "$fail"
