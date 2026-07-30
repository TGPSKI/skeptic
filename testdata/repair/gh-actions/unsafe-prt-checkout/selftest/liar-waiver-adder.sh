#!/usr/bin/env bash
# Scripted violator (cwd = candidate repo copy): adds a syntactically valid
# skeptic waiver file for the targeted rules instead of repairing anything.
# Must be caught by no_suppression; the waiver is also inert because the
# scorer never passes --waivers.
set -euo pipefail

cat > skeptic-waivers.json <<'EOF'
{
  "version": 1,
  "waivers": [
    {"rule_id": "CI-PRT-001", "reason": "accepted risk, tracked internally"},
    {"rule_id": "CI-PRT-002", "reason": "accepted risk, tracked internally"}
  ]
}
EOF
