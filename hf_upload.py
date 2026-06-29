"""
Upload the VibeSec dataset to the Hugging Face Hub.

Hosting the dataset on HF gives you free download counts + discoverability with
the ML/security audience, and a working dataset viewer for `dataset.jsonl`.

Prereqs:
  pip install huggingface_hub
  huggingface-cli login          # or: export HF_TOKEN=hf_...

Usage:
  python hf_upload.py                              # -> jenishk20/vibesec (public)
  python hf_upload.py --repo your-name/vibesec     # custom repo id
  python hf_upload.py --private                    # create as private first
  python hf_upload.py --dry-run                    # show what would be uploaded

What it uploads:
  dataset.jsonl       -> dataset.jsonl   (the 172 verified triplets)
  hf_dataset_card.md  -> README.md       (the dataset card shown on the Hub)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

DEFAULT_REPO = os.environ.get("HF_REPO", "jenishk20/vibesec")
DATASET_FILE = Path("dataset.jsonl")
CARD_FILE = Path("hf_dataset_card.md")


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload VibeSec to the Hugging Face Hub.")
    parser.add_argument("--repo", default=DEFAULT_REPO,
                        help=f"HF dataset repo id (default: {DEFAULT_REPO})")
    parser.add_argument("--private", action="store_true",
                        help="Create the repo as private (default: public).")
    parser.add_argument("--token", default=os.environ.get("HF_TOKEN"),
                        help="HF token (default: HF_TOKEN env var or cached login).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the planned actions without uploading.")
    args = parser.parse_args()

    # Fail fast on missing inputs before importing/hitting the network.
    if not DATASET_FILE.exists():
        print(f"ERROR: {DATASET_FILE} not found. Run `python aggregate.py` first.")
        return 1
    if not CARD_FILE.exists():
        print(f"ERROR: {CARD_FILE} not found.")
        return 1

    n_rows = sum(1 for line in DATASET_FILE.open() if line.strip())
    visibility = "private" if args.private else "public"

    print(f"Repo:        {args.repo}  (dataset, {visibility})")
    print(f"Dataset:     {DATASET_FILE}  ({n_rows} rows)")
    print(f"Card:        {CARD_FILE} -> README.md")

    if args.dry_run:
        print("\n[dry-run] No changes made.")
        return 0

    try:
        from huggingface_hub import HfApi
    except ImportError:
        print("\nERROR: huggingface_hub is not installed. Run `pip install huggingface_hub`.")
        return 1

    api = HfApi(token=args.token)

    print("\nCreating repo (idempotent)...")
    api.create_repo(
        repo_id=args.repo,
        repo_type="dataset",
        private=args.private,
        exist_ok=True,
    )

    print("Uploading dataset.jsonl...")
    api.upload_file(
        path_or_fileobj=str(DATASET_FILE),
        path_in_repo="dataset.jsonl",
        repo_id=args.repo,
        repo_type="dataset",
    )

    print("Uploading dataset card (README.md)...")
    api.upload_file(
        path_or_fileobj=str(CARD_FILE),
        path_in_repo="README.md",
        repo_id=args.repo,
        repo_type="dataset",
    )

    print(f"\nDone. View it at: https://huggingface.co/datasets/{args.repo}")
    print("Download counts appear on that page once people start pulling it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
