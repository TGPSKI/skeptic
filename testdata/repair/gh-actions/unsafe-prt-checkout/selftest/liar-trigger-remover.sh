#!/usr/bin/env bash
# Scripted violator (cwd = candidate repo copy): the canonical degenerate
# fix for this defect — swaps the PR trigger for workflow_dispatch, so PRs
# are simply no longer validated. Scan is clean and the head-ref line is
# gone with the trigger's threat context intact... but nothing guards pull
# requests anymore. Must be caught by exploit_blocked (no PR-triggered
# workflow) and behavior_kept (PR trigger assertion).
set -euo pipefail

for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  python3 - "$wf" <<'PYEOF'
import re, sys

path = sys.argv[1]
text = open(path).read()
text = re.sub(r"(\s*)pull_request_target:\n(\s+types:.*\n)?", r"\1workflow_dispatch:\n", text)
text = re.sub(r"^\s+with:\n\s+ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.\w+\s*\}\}\n",
              "", text, flags=re.M)
open(path, "w").write(text)
PYEOF
done
