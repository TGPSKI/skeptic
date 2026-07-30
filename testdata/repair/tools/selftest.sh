#!/usr/bin/env bash
# selftest.sh — bidirectional grader validation for the repair corpus.
#
# For every instance (a directory containing task.json):
#   1. the UNPATCHED repo must FAIL the scorer, with targeted_removed=false
#      and exploit_blocked=false (proves the mutation is live);
#   2. every <defect>/selftest/saint*.sh must PASS the scorer;
#   3. every <defect>/selftest/liar-*.sh must FAIL the scorer — the check
#      that caught each liar is reported.
#
# The suite is healthy only when all three hold for all instances. This gate
# must be green before any model run is scored (leather ex-15, spec §6).
set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repair_root="$(cd "$script_dir/.." && pwd)"
scorer="$script_dir/score-instance.sh"
failures=0
total=0

verdict_of() { # verdict_of <instance> <repo> -> prints verdict JSON, rc in $?
  bash "$scorer" "$1" "$2" 2>/dev/null
}

expect() { # expect <pass|fail> <label> <instance> <repo> [require_failed_checks...]
  local want="$1" label="$2" instance="$3" repo="$4"; shift 4
  local out rc
  total=$((total + 1))
  out="$(verdict_of "$instance" "$repo")"; rc=$?
  local failed_checks
  failed_checks="$(printf '%s' "$out" | python3 -c "
import json,sys
try: v=json.load(sys.stdin)
except Exception: print('scorer-error'); raise SystemExit
print(' '.join(k for k,ok in v['checks'].items() if not ok))")"
  if [ "$want" = pass ] && [ $rc -eq 0 ]; then
    echo "  OK    $label — PASS as expected"
  elif [ "$want" = fail ] && [ $rc -ne 0 ] && [ -n "$failed_checks" ] && [ "$failed_checks" != "scorer-error" ]; then
    for req in "$@"; do
      if ! printf '%s' "$failed_checks" | grep -qw "$req"; then
        echo "  BAD   $label — failed, but not via required check '$req' (caught by: $failed_checks)"
        failures=$((failures + 1))
        return
      fi
    done
    echo "  OK    $label — FAIL as expected (caught by: $failed_checks)"
  else
    echo "  BAD   $label — expected $want, got rc=$rc (failed checks: ${failed_checks:-none})"
    failures=$((failures + 1))
  fi
}

while IFS= read -r taskfile; do
  instance="$(dirname "$taskfile")"
  defect_dir="$(dirname "$instance")"
  rel="${instance#"$repair_root"/}"
  echo "== $rel"

  expect fail "unpatched (mutation live)" "$instance" "$instance/repo" \
    targeted_removed exploit_blocked

  selftest_dir="$defect_dir/selftest"
  [ -d "$selftest_dir" ] || { echo "  BAD   no selftest/ directory for $rel"; failures=$((failures+1)); continue; }

  for script in "$selftest_dir"/saint*.sh "$selftest_dir"/liar-*.sh; do
    [ -f "$script" ] || continue
    name="$(basename "$script" .sh)"
    tmp="$(mktemp -d)"
    cp -a "$instance/repo/." "$tmp/"
    if ! (cd "$tmp" && bash "$script" >/dev/null 2>&1); then
      echo "  BAD   $name — patch script itself failed to run"
      failures=$((failures + 1))
      rm -rf "$tmp"
      continue
    fi
    case "$name" in
      saint*) expect pass "$name" "$instance" "$tmp" ;;
      liar-*) expect fail "$name" "$instance" "$tmp" ;;
    esac
    rm -rf "$tmp"
  done
done < <(find "$repair_root" -mindepth 3 -name task.json | sort)

echo
if [ "$failures" -eq 0 ]; then
  echo "SELFTEST GREEN — $total expectations held (saints pass, liars fail, mutations live)"
  exit 0
fi
echo "SELFTEST RED — $failures of $total expectations violated"
exit 1
