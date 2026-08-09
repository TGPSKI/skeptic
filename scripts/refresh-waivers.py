#!/usr/bin/env python3
"""Recompute stale file_sha256 pins in .skeptic-waivers.json.

A pinned waiver lapses when its file changes. That is the point — it is what
makes a waiver safer than an ignore rule. It also means editing a waived file
breaks the build until someone re-pins it.

Re-pinning re-accepts whatever the file now contains, so this prints the
findings that each refreshed waiver will suppress. Read them before committing.
Refreshing without looking turns a waiver back into an ignore rule.

Usage:
  scripts/refresh-waivers.py           refresh stale pins and report
  scripts/refresh-waivers.py --check   exit 1 if any pin is stale, change nothing
"""

import hashlib
import json
import os
import subprocess
import sys

WAIVERS = ".skeptic-waivers.json"


def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def findings_for(pairs):
    """Current findings for each (file_path, rule_id), via a scan with no waivers."""
    empty = ".skeptic-waivers.empty.json"
    with open(empty, "w") as fh:
        json.dump({"version": 1, "waivers": []}, fh)
    out = ".skeptic-refresh-scan.json"
    try:
        subprocess.run(
            ["go", "run", "./cmd/skeptic", "scan", "--path", ".",
             "--format", "json", "--fail-on", "none",
             "--waivers", empty, "--out", out],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if not os.path.exists(out):
            return {}
        report = json.load(open(out))
    finally:
        for p in (empty, out):
            if os.path.exists(p):
                os.remove(p)

    by_pair = {}
    for f in report.get("findings", []):
        key = (f.get("file"), f.get("rule_id"))
        if key in pairs:
            by_pair.setdefault(key, []).append(f)
    return by_pair


def main():
    check_only = "--check" in sys.argv
    doc = json.load(open(WAIVERS))

    stale = []
    for w in doc["waivers"]:
        pin = w.get("file_sha256")
        path = w["file_path"]
        if not pin or not os.path.isfile(path):
            continue
        current = sha256(path)
        if current != pin:
            stale.append((w, current))

    if not stale:
        print("all waiver pins current")
        return 0

    if check_only:
        print(f"{len(stale)} stale waiver pin(s):", file=sys.stderr)
        for w, _ in stale:
            print(f"  {w['file_path']} ({w['rule_id']})", file=sys.stderr)
        print("run: make waivers-refresh", file=sys.stderr)
        return 1

    pairs = {(w["file_path"], w["rule_id"]) for w, _ in stale}
    current_findings = findings_for(pairs)

    print(f"{len(stale)} stale pin(s). These findings will be re-suppressed:\n")
    for w, current in stale:
        key = (w["file_path"], w["rule_id"])
        hits = current_findings.get(key, [])
        print(f"  {w['file_path']}  {w['rule_id']}  ({len(hits)} finding(s))")
        for f in hits[:5]:
            line = f.get("line")
            match = (f.get("match") or "").strip().replace("\n", " ")[:100]
            print(f"      :{line}  {match}")
        if len(hits) > 5:
            print(f"      … {len(hits) - 5} more")
        w["file_sha256"] = current
        print()

    json.dump(doc, open(WAIVERS, "w"), indent=2)
    open(WAIVERS, "a").write("\n")
    print(f"updated {len(stale)} pin(s) in {WAIVERS}")
    print("Review the findings above before committing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
