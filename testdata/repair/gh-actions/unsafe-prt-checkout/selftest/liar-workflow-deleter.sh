#!/usr/bin/env bash
# Scripted violator (cwd = candidate repo copy): deletes the CI pipeline
# entirely. The scan comes back clean; must be caught by exploit_blocked
# (nothing validates PRs anymore) and behavior_kept.
set -euo pipefail

rm -rf .github
