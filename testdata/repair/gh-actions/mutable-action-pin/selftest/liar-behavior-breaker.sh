#!/usr/bin/env bash
# Scripted violator (cwd = candidate repo copy): removes every action usage
# instead of pinning it — the scan is clean and no mutable ref remains, but
# the pipeline no longer checks out, builds against a toolchain, uploads, or
# publishes. Must be caught by behavior_kept.
set -euo pipefail

for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  sed -i -E 's|uses:[[:space:]]*[^[:space:]]+|run: echo skipped-action|' "$wf"
done
