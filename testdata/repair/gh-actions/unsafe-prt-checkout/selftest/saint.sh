#!/usr/bin/env bash
# Scripted compliant patcher (cwd = candidate repo copy): demotes the
# privileged trigger to plain pull_request and drops the explicit PR-head
# checkout (the default checkout of the merge ref is then unprivileged),
# preserving the validation steps unchanged.
set -euo pipefail

for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  python3 - "$wf" <<'PYEOF'
import re, sys

path = sys.argv[1]
lines = open(path).read().splitlines(keepends=True)
out = []
skip_with_block = False
for i, line in enumerate(lines):
    if skip_with_block:
        # Drop the "with:"/"ref:" block attached to the checkout step.
        if re.match(r"^\s+(with:|ref:\s*\$\{\{\s*github\.event\.pull_request\.head)", line):
            continue
        skip_with_block = False
    line = re.sub(r"^(\s*)pull_request_target:", r"\1pull_request:", line)
    if re.search(r"uses:\s*actions/checkout@", line):
        skip_with_block = True
    out.append(line)
open(path, "w").write("".join(out))
PYEOF
done
