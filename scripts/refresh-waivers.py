#!/usr/bin/env python3
"""Recompute stale file_sha256 pins in .skeptic-waivers.json.

A pinned waiver lapses when its file changes. That is the point — it is what
makes a waiver safer than an ignore rule. It also means editing a waived file
breaks the build until someone re-pins it.

Each waiver records the stable identities it accepted. A stale pin refreshes
mechanically when that set is unchanged; a new or modified finding stops the
refresh and prints the review delta.

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
        rule_ids = [f.get("rule_id")] + list(f.get("related_rule_ids", []))
        for rule_id in rule_ids:
            key = (f.get("file"), rule_id)
            if key in pairs:
                copy = dict(f)
                copy["rule_id"] = rule_id
                by_pair.setdefault(key, []).append(copy)
    return by_pair


def finding_key(finding):
    match_hash = hashlib.sha256((finding.get("match") or "").encode()).hexdigest()[:16]
    return f"{finding.get('rule_id')}|{finding.get('file')}|{match_hash}"


def main():
    check_only = "--check" in sys.argv
    doc = json.load(open(WAIVERS))

    candidates = []
    for w in doc["waivers"]:
        pin = w.get("file_sha256")
        path = w["file_path"]
        if not pin or not os.path.isfile(path):
            continue
        current = sha256(path)
        if current != pin or not w.get("finding_keys"):
            candidates.append((w, current))

    if not candidates:
        print("all waiver pins and finding identities current")
        return 0

    if check_only:
        print(f"{len(candidates)} waiver(s) need refresh or identity migration:", file=sys.stderr)
        for w, current in candidates:
            state = "stale pin" if current != w.get("file_sha256") else "missing finding identities"
            print(f"  {w['file_path']} ({w['rule_id']}): {state}", file=sys.stderr)
        print("run: make waivers-refresh", file=sys.stderr)
        return 1

    pairs = {(w["file_path"], w["rule_id"]) for w, _ in candidates}
    current_findings = findings_for(pairs)

    blocked = []
    migrations = []
    for w, current in candidates:
        key = (w["file_path"], w["rule_id"])
        hits = current_findings.get(key, [])
        current_keys = sorted({finding_key(f) for f in hits})
        accepted_keys = set(w.get("finding_keys", []))
        if accepted_keys:
            new_keys = set(current_keys) - accepted_keys
            if new_keys:
                blocked.append((w, [f for f in hits if finding_key(f) in new_keys]))
                continue
        else:
            migrations.append((w, hits))
        w["file_sha256"] = current
        w["finding_keys"] = current_keys

    if blocked:
        print("refresh stopped: new findings require review", file=sys.stderr)
        for w, hits in blocked:
            print(f"  {w['file_path']}  {w['rule_id']}  ({len(hits)} new finding(s))", file=sys.stderr)
            for f in hits[:5]:
                line = f.get("line")
                match = (f.get("match") or "").strip().replace("\n", " ")[:100]
                print(f"      :{line}  {match}", file=sys.stderr)
        return 1

    if migrations:
        print("Recording finding identities for legacy waivers. Review this one-time migration:\n")
        for w, hits in migrations:
            print(f"  {w['file_path']}  {w['rule_id']}  ({len(hits)} finding(s))")
            for f in hits[:5]:
                line = f.get("line")
                match = (f.get("match") or "").strip().replace("\n", " ")[:100]
                print(f"      :{line}  {match}")
            print()

    json.dump(doc, open(WAIVERS, "w"), indent=2)
    open(WAIVERS, "a").write("\n")
    print(f"updated {len(candidates)} waiver(s) in {WAIVERS}")
    if migrations:
        print("Review the legacy-waiver findings above before committing.")
    else:
        print("Finding sets unchanged; pins refreshed mechanically.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
