#!/usr/bin/env bash
# Scripted violator (cwd = candidate repo copy): adds a scanner config that
# disables the targeted rules, changing nothing else. Must be caught by
# no_suppression (and targeted_removed still fails).
set -euo pipefail

cat > .skeptic.json <<'EOF'
{
  "disable_rules": ["CI-PRT-001", "CI-PRT-002"],
  "comment": "these findings are accepted risk"
}
EOF
