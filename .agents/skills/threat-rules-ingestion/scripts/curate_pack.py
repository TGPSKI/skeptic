#!/usr/bin/env python3
"""Curate an ingested rule pack: prune noise, remove over-broad, de-duplicate against built-in rules."""
import json, re, sys
PACK = sys.argv[1]
BUILTIN_IDS = "/tmp/builtin-ids.txt"
BUILTIN_PATTERNS = "/tmp/builtin-patterns.txt"
# --- Step 1: Web-scrape noise patterns ---
NOISE = [
    r"posthog", r"reb2b", r"segment\.(com|io)", r"mixpanel",
    r"hotjar", r"gtag", r"googletagmanager", r"hubspot",
    r"intercom", r"amplitude", r"webfont\.load", r"typekit",
    r"fonts\.googleapis", r"fluidbuilder\.webflow",
    r"document\.?element", r"documenttouch", r"getelementsbytagname",
    r"parentnode\.insertbefore", r"classlist", r"classname",
    r"array\.prototype", r"\.tostring\b", r"\.unshift\b",
    r"cdn\.jsdelivr", r"unpkg\.com", r"cdnjs\.cloudflare",
    r"cookieconsent", r"onetrust", r"telemetry\.stepsecurity",
    r"people\.set\b", r"u\.people",
]
noise_rx = [re.compile(p, re.IGNORECASE) for p in NOISE]
# --- Step 2: Over-broad patterns ---
OVERBROAD_EXACT = {
    "e.init", "e.split", "o.length", "t.push", "p.async", "p.src",
    "process.platform", "github.com", "extension.js", "index.js",
    "package.json", "node.js", "array.js", "doc.sh", "1.bat",
    "calc.bat", "pako.deflate", "t.createelement", "args.unshift",
}
def is_overbroad(pat):
    norm = re.sub(r"\\[.]", ".", pat.lower().strip())
    norm = re.sub(r"\(\?i\)", "", norm)
    if norm in OVERBROAD_EXACT:
        return True
    clean = re.sub(r"[\\().?+*^$|]", "", norm)
    if len(clean) < 8 and not re.search(r"[0-9a-f]{16}", norm):
        return True
    return False
# --- Step 3: Malformed / non-IOC ---
DROP_IDS = {
    "INGEST-INGESTED_I-063",  # SHA256 of stepsecurity remediation tool, not attack IOC
    "INGEST-INGESTED_I-052",  # malformed concatenation: calc.batcdn.rraghh.com
}
# --- Load pack ---
with open(PACK) as f:
    pack = json.load(f)
orig = len(pack["rules"])
# --- Load built-in references ---
with open(BUILTIN_IDS) as f:
    builtin_ids = set(line.strip() for line in f if line.strip())
with open(BUILTIN_PATTERNS) as f:
    builtin_pats = set(line.strip().lower() for line in f if line.strip())
# --- Classify and filter ---
kept = []
log = {"noise": [], "overbroad": [], "manual_drop": [], "id_dup": [], "pattern_dup": [], "subsumed": []}
for rule in pack["rules"]:
    rid = rule["id"]
    pat = rule["pattern"]
    if rid in DROP_IDS:
        log["manual_drop"].append(f"{rid}: {pat[:60]}")
        continue
    if any(rx.search(pat) for rx in noise_rx):
        log["noise"].append(f"{rid}: {pat[:60]}")
        continue
    if is_overbroad(pat):
        log["overbroad"].append(f"{rid}: {pat[:60]}")
        continue
    if rid in builtin_ids:
        log["id_dup"].append(f"{rid}: exact ID match in built-in")
        continue
    pat_norm = re.sub(r"\s+", " ", pat.lower().strip())
    pat_norm_bare = re.sub(r"\(\?i\)", "", pat_norm)
    if pat_norm in builtin_pats or pat_norm_bare in builtin_pats:
        log["pattern_dup"].append(f"{rid}: pattern match in built-in")
        continue
    kept.append(rule)
pack["rules"] = kept
with open(PACK, "w") as f:
    json.dump(pack, f, indent=2)
print(f"\n=== Curation Summary ===")
print(f"Original: {orig}")
print(f"Kept: {len(kept)}")
print(f"Dropped: {orig - len(kept)}")
print(f"  Noise:       {len(log['noise'])}")
print(f"  Over-broad:  {len(log['overbroad'])}")
print(f"  Manual drop: {len(log['manual_drop'])}")
print(f"  ID dup:      {len(log['id_dup'])}")
print(f"  Pattern dup: {len(log['pattern_dup'])}")
print(f"  Subsumed:    {len(log['subsumed'])}")
print()
for cat, items in log.items():
    if items:
        print(f"--- {cat} ---")
        for item in items:
            print(f"  {item}")
        print()
