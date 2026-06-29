"""
Prepare SFT + DPO training data from the verified dataset and eval results.

SFT (Supervised Fine-Tuning):
  Each row is one (prompt, ideal_response) pair.
  Teaches the model the format and content of a good security patch.

DPO (Direct Preference Optimization):
  Each row is one (prompt, chosen, rejected) triplet.
  Teaches the model to prefer good patches over bad ones.
  We pull "rejected" patches from eval_results.jsonl (failed model attempts).

Outputs four JSONL files in training_data/:
  sft_train.jsonl   (~130 rows, chat-formatted)
  sft_test.jsonl    (~32  rows, held out)
  dpo_train.jsonl   (~hundreds of pairs, depending on # rejected we have)
  dpo_test.jsonl    (held out)

Train/test split is ENTRY-LEVEL (not row-level) to prevent leakage between
the SFT and DPO splits.
"""

import json
import random
import os
from pathlib import Path
from collections import Counter

random.seed(42)  # reproducible 80/20 split

# ─── Load the canonical dataset (verified triplets) ─────────
with open("dataset.jsonl") as f:
    entries = [json.loads(line) for line in f]
print(f"Loaded {len(entries)} verified triplets from dataset.jsonl")

# ─── Load eval results to harvest "rejected" patches ────────
# Rules for what counts as a usable rejected patch:
#   • The model produced output (raw_response is not empty)
#   • The eval marked it not-passed (it failed gate3 or gate4)
#   • Specifically interested in `exploit_still_works` and `spec_broken`
#     — these are "the model tried but missed"
rejected_by_entry: dict = {}
if os.path.exists("eval_results.jsonl"):
    with open("eval_results.jsonl") as f:
        for line in f:
            r = json.loads(line)
            if r.get("passed"):
                continue
            stage = r.get("stage", "")
            # Only use "tried-but-failed" patches as rejection signal
            if stage not in ("exploit_still_works", "spec_broken"):
                continue
            raw = r.get("raw_response", "")
            if not raw or len(raw) < 100:
                continue
            rejected_by_entry.setdefault(r["entry_id"], []).append({
                "model": r["model"],
                "stage": stage,
                "patch_text": raw[:6000],  # truncate very long ones
            })

print(f"Found rejected patches for {len(rejected_by_entry)} of {len(entries)} entries")

# ─── Build the prompt format (same as eval) ─────────────────
PATCH_PROMPT = """Below is a Python FastAPI app that has a security vulnerability. Write a fixed version.

Output your patched files in this EXACT format:

<file path="main.py">
... patched code ...
</file>
<file path="requirements.txt">
... same deps as original ...
</file>

Critical rules:
- Output the FULL patched files — do not truncate
- The fix must close the security vulnerability AND preserve all normal behavior
- Do not change the API shape
- Do not include markdown fences inside the file blocks

APP CODE:
{app_code}"""


def format_patch_response(patched_files: dict) -> str:
    """Format the known-good patch in the same multi-file format as the eval expects."""
    parts = []
    for path, content in patched_files.items():
        parts.append(f'<file path="{path}">\n{content}\n</file>')
    return "\n".join(parts)


# ─── Build SFT rows and DPO rows ────────────────────────────
sft_rows = []
dpo_rows = []

for e in entries:
    app_code = "\n\n".join(f"# {p}\n{c}" for p, c in e["app_files"].items())
    prompt = PATCH_PROMPT.format(app_code=app_code)
    chosen = format_patch_response(e["patched_files"])

    # SFT — one good example per entry
    sft_rows.append({
        "entry_id": e["id"],
        "vuln_class": e["vuln_class"],
        "messages": [
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": chosen},
        ],
    })

    # DPO — one row per (entry, rejected_attempt) combination
    for rej in rejected_by_entry.get(e["id"], []):
        dpo_rows.append({
            "entry_id": e["id"],
            "vuln_class": e["vuln_class"],
            "rejected_from_model": rej["model"],
            "rejected_stage": rej["stage"],
            "prompt": prompt,
            "chosen": chosen,
            "rejected": rej["patch_text"],
        })

# ─── Entry-level train/test split (prevent leakage) ─────────
all_entry_ids = sorted({e["id"] for e in entries})
random.shuffle(all_entry_ids)
n_test = max(20, len(all_entry_ids) // 5)  # 20% test, min 20 entries
test_entry_ids = set(all_entry_ids[:n_test])
train_entry_ids = set(all_entry_ids[n_test:])
print(f"\nSplit: {len(train_entry_ids)} train entries, {len(test_entry_ids)} test entries")

sft_train = [r for r in sft_rows if r["entry_id"] in train_entry_ids]
sft_test = [r for r in sft_rows if r["entry_id"] in test_entry_ids]
dpo_train = [r for r in dpo_rows if r["entry_id"] in train_entry_ids]
dpo_test = [r for r in dpo_rows if r["entry_id"] in test_entry_ids]

# ─── Write outputs ─────────────────────────────────────────
out_dir = Path("training_data")
out_dir.mkdir(exist_ok=True)

for name, rows in [
    ("sft_train", sft_train),
    ("sft_test", sft_test),
    ("dpo_train", dpo_train),
    ("dpo_test", dpo_test),
]:
    path = out_dir / f"{name}.jsonl"
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"  {path}: {len(rows)} rows")

# ─── Stats ──────────────────────────────────────────────────
print(f"\nDPO rejection breakdown (rejected patches per entry):")
counts = Counter(len(v) for v in rejected_by_entry.values())
for n_rej, n_entries in sorted(counts.items()):
    print(f"  {n_rej} rejections × {n_entries} entries = {n_rej * n_entries} DPO rows")

# Save the test entry IDs separately — we'll use these to filter eval
with open(out_dir / "test_entry_ids.json", "w") as f:
    json.dump(sorted(test_entry_ids), f, indent=2)
print(f"\nSaved test_entry_ids.json for held-out evaluation.")
