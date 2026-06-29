"""
Aggregate all verified triplets across all runs into a single dataset.jsonl.
Deduplicates by exploit hash. Classifies each entry by vulnerability class.

Usage:  python aggregate.py
Output: dataset.jsonl
"""

import json
import glob
import hashlib
import re
from collections import Counter


def classify(exploit_code: str) -> str:
    code = exploit_code.lower()
    if any(t in code for t in ["/promote", "promote/", "promote(", "elevate", "/grant"]):
        return "privilege_escalation"
    if re.search(r'(is_admin|"admin"|role.*admin|"role":\s*"admin")', code):
        if 'patch' in code or 'put' in code:
            return "mass_assignment"
    if any(t in code for t in ["jwt", "base64", "b64decode", "b64encode", "alg", "forge", "forged", "tamper", "tampered"]):
        if any(t in code for t in ["token", "role", "admin", "user_id", "is_admin"]):
            return "token_forgery"
    if "../" in code or "/etc/passwd" in code:
        return "path_traversal"
    if "or 1=1" in code or "union select" in code:
        return "sql_injection"
    if re.search(r'no.{0,3}auth|no.{0,3}token|no.{0,3}header|unauthen', code):
        return "missing_auth"
    if any(t in code for t in ["user_a", "user_b", "alice", "bob", "victim", "attacker", "user1", "user2"]):
        return "idor"
    if any(t in code for t in ["169.254.169.254", "metadata.google.internal", "file://", "gopher://"]):
        return "ssrf"
    if any(t in code for t in ["internal_url", "callback_url", "webhook_url", "target_url"]):
        if any(t in code for t in ["metadata", "localhost", "127.0.0.1", "internal"]):
            return "ssrf"
    return "other"


# Try to recover full seed prompts by matching truncated seeds (first 80 chars)
# against the full prompts we know about (manual + most-recent synthesized).
import os
known_prompts: list = []
try:
    from prompts import MANUAL_PROMPTS
    known_prompts.extend(MANUAL_PROMPTS)
except Exception:
    pass
if os.path.exists("generated_prompts.json"):
    with open("generated_prompts.json") as f:
        known_prompts.extend(json.load(f))

# Build prefix lookup
prefix_lookup = {p[:80]: p for p in known_prompts}


def rehydrate_seed(truncated: str) -> str:
    """Return the full prompt if we can match the truncated form, else the truncated."""
    if len(truncated) < 80:
        return truncated  # not truncated
    return prefix_lookup.get(truncated, truncated)


paths = glob.glob("results/[0-9]*/verified/*.json") + glob.glob("results/verified/*.json")
seen = set()
entries = []

for path in paths:
    with open(path) as f:
        r = json.load(f)
    h = hashlib.sha256(r.get("exploit_code", "").encode()).hexdigest()[:16]
    if h in seen:
        continue
    seen.add(h)

    entries.append({
        "id": h,
        "seed_prompt": rehydrate_seed(r["seed"]),
        "vuln_class": classify(r.get("exploit_code", "")),
        "app_files": r["app_files"],
        "spec_test": r["spec_code"],
        "exploit": r["exploit_code"],
        "exploit_output": r.get("exploit_output", ""),
        "patched_files": r["patched_files"],
        "source_file": path,
    })

with open("dataset.jsonl", "w") as f:
    for e in entries:
        f.write(json.dumps(e) + "\n")

# Print stats
print(f"Wrote {len(entries)} entries to dataset.jsonl")
print(f"\nVulnerability class distribution:")
dist = Counter(e["vuln_class"] for e in entries)
for cls, count in dist.most_common():
    print(f"  {cls:25s} {count:3d}  ({100*count/len(entries):.0f}%)")
