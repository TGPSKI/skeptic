#!/usr/bin/env python3
"""Compare committed .github/ruleset-*.json files against the live rulesets.

`ruleset-main.json` named `test-action` as a required check while CHANGELOG
v0.2.0 said the ruleset had been repointed at `test-action-result`. Neither the
file nor the live ruleset had been updated, and it went unnoticed for two
releases because nothing compared them (#83, #85).

Reading rulesets needs a token with repo admin scope. The default GITHUB_TOKEN
does not have it. On 403 or 404 this exits 78 (skip), never 0 — a missing
permission must not read as "no drift".

Exit codes:
  0   every committed ruleset matches its live counterpart
  1   drift, or a committed ruleset with no live counterpart
  2   usage or environment error
  78  insufficient API permission; comparison did not run
"""

import json
import os
import pathlib
import subprocess
import sys

# Server-managed. Present in the API response, never in a committed file.
VOLATILE = {
    "id",
    "node_id",
    "source",
    "source_type",
    "created_at",
    "updated_at",
    "_links",
    "current_user_can_bypass",
}

TRACKED = ("name", "target", "enforcement", "conditions", "rules", "bypass_actors")

SKIP_EXIT = 78


def gh_api(path):
    """Return parsed JSON from `gh api path`, or raise SkipError on 403/404."""
    proc = subprocess.run(
        ["gh", "api", path],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        if "403" in stderr or "404" in stderr or "Resource not accessible" in stderr:
            raise SkipError(stderr)
        raise RuntimeError(f"gh api {path} failed: {stderr}")
    return json.loads(proc.stdout)


class SkipError(Exception):
    pass


def normalize(obj):
    """Drop server-managed keys and order everything, so equal content compares equal.

    Lists are sorted by their canonical JSON form rather than left in place:
    the API does not promise a stable order for required_status_checks or
    bypass_actors, and an order-sensitive diff would report drift on a reorder.
    """
    if isinstance(obj, dict):
        return {
            k: normalize(v)
            for k, v in sorted(obj.items())
            if k not in VOLATILE
        }
    if isinstance(obj, list):
        return sorted(
            (normalize(v) for v in obj),
            key=lambda v: json.dumps(v, sort_keys=True),
        )
    return obj


def tracked_only(ruleset):
    return normalize({k: ruleset[k] for k in TRACKED if k in ruleset})


def missing_tracked(live_rulesets):
    """Tracked keys the API withheld, meaning the token sees a reduced view.

    GitHub returns bypass_actors only to a caller allowed to see it. The default
    GITHUB_TOKEN gets a response with the key absent — not empty, absent. A
    plain diff reads that as "the committed file has a bypass actor and the live
    one does not", which is a false report of drift, and a more dangerous one
    than a false pass because it trains people to ignore the check.
    """
    missing = set()
    for rs in live_rulesets:
        missing |= {k for k in TRACKED if k not in rs}
    return missing


def render(obj):
    return json.dumps(obj, indent=2, sort_keys=True).splitlines()


def main():
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        proc = subprocess.run(
            ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            print("error: set GITHUB_REPOSITORY or run inside a gh-authenticated repo",
                  file=sys.stderr)
            return 2
        repo = proc.stdout.strip()

    committed_dir = pathlib.Path(".github")
    files = sorted(committed_dir.glob("ruleset-*.json"))
    if not files:
        print("error: no .github/ruleset-*.json files found", file=sys.stderr)
        return 2

    try:
        live_index = gh_api(f"repos/{repo}/rulesets")
        live = {}
        for entry in live_index:
            full = gh_api(f"repos/{repo}/rulesets/{entry['id']}")
            live[full["name"]] = full
    except SkipError as exc:
        print(f"::warning::ruleset drift check skipped — cannot read rulesets "
              f"for {repo}. Supply a RULESET_READ_TOKEN with repo admin scope. "
              f"({exc})")
        return SKIP_EXIT
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    withheld = missing_tracked(live.values())
    if withheld:
        print(f"::warning::ruleset drift check skipped — the API withheld "
              f"{', '.join(sorted(withheld))} for {repo}, so the response is a "
              f"reduced view rather than the full ruleset. Comparing against it "
              f"would report drift that does not exist. Supply a "
              f"RULESET_READ_TOKEN with repo admin scope.")
        return SKIP_EXIT

    drifted = False
    for path in files:
        committed = json.loads(path.read_text())
        name = committed.get("name")
        if name not in live:
            print(f"::error file={path}::committed ruleset {name!r} has no live "
                  f"counterpart in {repo}")
            drifted = True
            continue

        want = tracked_only(committed)
        got = tracked_only(live[name])
        if want == got:
            print(f"ok: {path} matches live ruleset {name!r}")
            continue

        drifted = True
        print(f"::error file={path}::committed ruleset {name!r} does not match live")
        import difflib
        for line in difflib.unified_diff(
            render(want), render(got),
            fromfile=f"{path} (committed)",
            tofile=f"live {name!r}",
            lineterm="",
        ):
            print(line)

    live_only = set(live) - {json.loads(p.read_text()).get("name") for p in files}
    for name in sorted(live_only):
        print(f"::error::live ruleset {name!r} has no committed file in .github/")
        drifted = True

    return 1 if drifted else 0


if __name__ == "__main__":
    sys.exit(main())
