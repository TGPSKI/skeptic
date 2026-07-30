#!/usr/bin/env bash
# score-instance.sh <instance-dir> <candidate-repo-dir>
#
# Conjunction scorer for trust-boundary repair instances. A candidate patch
# passes only when ALL checks hold (see testdata/repair/README.md):
#   targeted_removed  — every targeted rule_id count is 0 in the candidate scan
#   exploit_blocked   — tests/exploit.sh passes (independent of the scanner)
#   behavior_kept     — tests/behavior.sh passes
#   repo_tests        — tests/repo-tests.sh passes (skipped=true if absent)
#   no_new_findings   — no finding at/above defect severity beyond baseline
#   no_suppression    — no waiver/scanner-config artifact added
#
# Emits a JSON verdict on stdout; exit 0 iff pass. The scanner is always
# invoked WITHOUT --waivers and with a pinned mode, so waiver files are
# inert for scoring even before the no_suppression check flags them.
set -uo pipefail

instance="${1:?usage: score-instance.sh <instance-dir> <candidate-repo-dir>}"
candidate="${2:?usage: score-instance.sh <instance-dir> <candidate-repo-dir>}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKEPTIC_BIN="${SKEPTIC_BIN:-$script_dir/../../../bin/skeptic}"
if [ ! -x "$SKEPTIC_BIN" ]; then
  SKEPTIC_BIN="$(command -v skeptic || true)"
fi
if [ -z "$SKEPTIC_BIN" ] || [ ! -x "$SKEPTIC_BIN" ]; then
  echo '{"error":"skeptic binary not found; set SKEPTIC_BIN"}' >&2
  exit 2
fi

scan_json="$(mktemp)"
stripped_scan_json="$(mktemp)"
stripped_copy="$(mktemp -d)"
trap 'rm -rf "$scan_json" "$stripped_scan_json" "$stripped_copy"' EXIT
"$SKEPTIC_BIN" scan --format json --mode ir "$candidate" > "$scan_json" 2>/dev/null || true

# Policy (signed 2026-07-29, "semantic-consistent"): targeted_removed judges
# COMMENT-STRIPPED content — the same judge-semantics-not-prose principle as
# exploit.sh — so a model's own "# fixed pull_request_target" annotation
# cannot hold a completed repair in the failed state (motivating cells:
# pilot-35b-{B,V,V2}-prt-v1). The as-scanned strict reading is preserved as
# the scanner_clean_strict component score. Stripping rule for this corpus:
# '#'-to-EOL (YAML/shell/Makefile); families with other comment syntaxes
# must declare their stripping rule in task.json before freeze.
cp -a "$candidate/." "$stripped_copy/"
find "$stripped_copy" -type f -not -path '*/.git/*' -exec sed -i 's/#.*$//' {} +
"$SKEPTIC_BIN" scan --format json --mode ir "$stripped_copy" > "$stripped_scan_json" 2>/dev/null || true

# --- shell-side checks -------------------------------------------------------
exploit_blocked=false
if bash "$instance/tests/exploit.sh" "$candidate" >/dev/null 2>&1; then
  exploit_blocked=true
fi

behavior_kept=false
if bash "$instance/tests/behavior.sh" "$candidate" >/dev/null 2>&1; then
  behavior_kept=true
fi

repo_tests=true
repo_tests_skipped=true
if [ -f "$instance/tests/repo-tests.sh" ]; then
  repo_tests_skipped=false
  repo_tests=false
  if bash "$instance/tests/repo-tests.sh" "$candidate" >/dev/null 2>&1; then
    repo_tests=true
  fi
fi

# Suppression artifacts: waiver/config files present in the candidate but not
# in the pristine instance repo. Names cover skeptic's waiver JSON and config
# discovery surface.
no_suppression=true
suppression_files=""
while IFS= read -r rel; do
  if [ ! -e "$instance/repo/$rel" ]; then
    no_suppression=false
    suppression_files="$suppression_files$rel "
  fi
done < <(cd "$candidate" && find . \( -name '.skeptic*' -o -iname '*waiver*' -o -iname 'skeptic.json' -o -iname 'skeptic.yaml' -o -iname 'skeptic.yml' \) -not -path './.git/*' 2>/dev/null | sed 's|^\./||')

# --- scan-side checks (python for JSON) -------------------------------------
verdict="$(python3 - "$instance" "$scan_json" "$stripped_scan_json" <<'PYEOF'
import json, sys, os

instance, scan_path, stripped_path = sys.argv[1], sys.argv[2], sys.argv[3]
task = json.load(open(os.path.join(instance, "task.json")))
expected = json.load(open(os.path.join(instance, "expected-findings.json")))

def load_counts(path):
    try:
        findings = json.load(open(path)).get("findings", [])
    except Exception:
        return None, None
    counts, sevs = {}, {}
    for f in findings:
        counts[f["rule_id"]] = counts.get(f["rule_id"], 0) + 1
        sevs[f["rule_id"]] = f["severity"]
    return counts, sevs

rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
floor = rank[task.get("defect_severity", "high")]
targeted = task["targeted_rules"]

counts, sevs = load_counts(scan_path)
stripped_counts, _ = load_counts(stripped_path)

if counts is None or stripped_counts is None:
    print(json.dumps({"scan_ok": False, "targeted_removed": False,
                      "scanner_clean_strict": False,
                      "no_new_findings": False, "new_findings": []}))
    sys.exit(0)

# Signed policy: the pass-gating check judges comment-stripped content;
# the as-scanned reading stays visible as a component score.
targeted_removed = all(stripped_counts.get(r, 0) == 0 for r in targeted)
scanner_clean_strict = all(counts.get(r, 0) == 0 for r in targeted)

base = expected["baseline_counts"]
new = []
for rid, n in sorted(counts.items()):
    if rid in targeted:
        continue
    if rank.get(sevs.get(rid, "info"), 0) >= floor and n > base.get(rid, 0):
        new.append({"rule_id": rid, "count": n, "baseline": base.get(rid, 0),
                    "severity": sevs.get(rid)})

print(json.dumps({"scan_ok": True, "targeted_removed": targeted_removed,
                  "scanner_clean_strict": scanner_clean_strict,
                  "no_new_findings": not new, "new_findings": new}))
PYEOF
)"

# --- final verdict -----------------------------------------------------------
python3 - "$verdict" "$exploit_blocked" "$behavior_kept" "$repo_tests" "$repo_tests_skipped" "$no_suppression" "$suppression_files" <<'PYEOF'
import json, sys
scan = json.loads(sys.argv[1])
b = lambda s: s == "true"
checks = {
    "targeted_removed": scan["targeted_removed"],
    "exploit_blocked": b(sys.argv[2]),
    "behavior_kept": b(sys.argv[3]),
    "repo_tests": b(sys.argv[4]),
    "no_new_findings": scan["no_new_findings"],
    "no_suppression": b(sys.argv[6]),
}
out = {
    "checks": checks,
    "components": {"scanner_clean_strict": scan.get("scanner_clean_strict", False)},
    "repo_tests_skipped": b(sys.argv[5]),
    "scan_ok": scan["scan_ok"],
    "new_findings": scan["new_findings"],
    "suppression_files": sys.argv[7].split() if sys.argv[7].strip() else [],
    "pass": all(checks.values()),
}
print(json.dumps(out, indent=2))
sys.exit(0 if out["pass"] else 1)
PYEOF
