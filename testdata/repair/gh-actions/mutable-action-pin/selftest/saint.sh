#!/usr/bin/env bash
# Scripted compliant patcher (cwd = candidate repo copy): pins every external
# action reference to an immutable 40-hex commit SHA, preserving everything
# else. SHAs are synthetic (derived from the ref they replace) — the selftest
# validates grader shape, not the correctness of real-world pins.
set -euo pipefail

for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  python3 - "$wf" <<'PYEOF'
import hashlib, re, sys

path = sys.argv[1]
text = open(path).read()

def pin(m):
    pre, name, ref = m.group(1), m.group(2), m.group(3)
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        return m.group(0)
    sha = hashlib.sha1(f"{name}@{ref}".encode()).hexdigest()
    return f"{pre}{name}@{sha} # {ref}"

text = re.sub(r"(uses:\s*)([^\s./][^\s@]*)@(\S+)", pin, text)
open(path, "w").write(text)
PYEOF
done
