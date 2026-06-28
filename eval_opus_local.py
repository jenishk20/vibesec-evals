"""
Local eval of Claude Opus on VibeSec dataset — no Modal required.

Uses the Anthropic API directly with your OPUS_API_KEY.
Runs vulnerable apps locally via subprocess, then verifies patches.

Usage:
  python eval_opus_local.py              # eval 5 entries (default)
  python eval_opus_local.py --n 10       # eval 10 entries
  python eval_opus_local.py --n 5 --model claude-opus-4  # specify model
"""

import os
import re
import sys
import json
import time
import signal
import socket
import argparse
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

from dotenv import load_dotenv

load_dotenv()

MULTIFILE_RE = re.compile(r'<file path="([^"]+)">(.*?)</file>', re.DOTALL)

PATCH_PROMPT = """Below is a Python FastAPI app that has a security vulnerability. Write a fixed version.

Output your patched files in this EXACT format:

<file path="main.py">
... patched code ...
</file>
<file path="requirements.txt">
... same deps as original ...
</file>

Critical rules:
- Output the FULL patched files — do not truncate, do not write "rest unchanged"
- The fix must close the security vulnerability AND preserve all normal behavior
- Do not change the API shape (endpoints, paths, request/response format)
- Do not include markdown fences inside the file blocks

APP CODE:
{app_code}
"""


def parse_multifile(text: str) -> dict:
    return {p.strip(): c.strip() for p, c in MULTIFILE_RE.findall(text)}


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_in_local_sandbox(app_files: dict, script_content: str, script_name: str, timeout: int = 60) -> str:
    """Spin up a FastAPI app locally, run a test script against it, return stdout."""
    with tempfile.TemporaryDirectory() as tmpdir:
        for path, content in app_files.items():
            filepath = Path(tmpdir) / path
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.write_text(content, encoding="utf-8")

        script_path = Path(tmpdir) / script_name
        script_path.write_text(script_content, encoding="utf-8")

        if "requirements.txt" in app_files:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-q", "-r", str(Path(tmpdir) / "requirements.txt")],
                capture_output=True, timeout=60
            )

        port = find_free_port()

        patched_script = script_content.replace(
            "http://127.0.0.1:8000", f"http://127.0.0.1:{port}"
        )
        script_path.write_text(patched_script, encoding="utf-8")

        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        server_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "main:app",
             "--host", "127.0.0.1", "--port", str(port)],
            cwd=tmpdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
        )

        try:
            time.sleep(4)

            if server_proc.poll() is not None:
                stderr = server_proc.stderr.read().decode(errors="replace")
                return f"SERVER_CRASH: {stderr[:500]}"

            test_result = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                timeout=timeout,
                cwd=tmpdir,
                env=env,
            )
            return test_result.stdout.decode(errors="replace")
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        finally:
            if sys.platform == "win32":
                server_proc.kill()
            else:
                os.killpg(os.getpgid(server_proc.pid), signal.SIGTERM)
            server_proc.wait(timeout=5)


AVAILABLE_MODELS = [
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
]


def detect_model(api_key: str, requested: str) -> str:
    """Try the requested model; if 404, probe available models."""
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)

    candidates = [requested] + [m for m in AVAILABLE_MODELS if m != requested]
    for model_id in candidates:
        try:
            resp = client.messages.create(
                model=model_id,
                max_tokens=32,
                messages=[{"role": "user", "content": "Say OK"}],
            )
            if resp.content:
                print(f"  Model verified: {model_id}")
                return model_id
        except anthropic.NotFoundError:
            print(f"  Model not available: {model_id}")
            continue
        except Exception as e:
            print(f"  Probe error for {model_id}: {e}")
            continue

    print("  ERROR: No accessible model found on your API key.")
    sys.exit(1)


def call_opus(api_key: str, model: str, prompt: str) -> str | None:
    """Call Claude via the Anthropic API."""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)

    for attempt in range(3):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text
            if text:
                return text
        except anthropic.RateLimitError:
            wait = (2 ** attempt) + 1
            print(f"    Rate limited, waiting {wait}s...")
            time.sleep(wait)
        except Exception as e:
            print(f"    API error: {e}")
            return None
    return None


def score_one(entry: dict, api_key: str, model: str) -> dict:
    """Score a single dataset entry."""
    result = {
        "model": f"anthropic/{model}",
        "entry_id": entry["id"],
        "vuln_class": entry["vuln_class"],
        "passed": False,
        "stage": "start",
    }

    app_code = "\n\n".join(f"# {p}\n{c}" for p, c in entry["app_files"].items())
    prompt = PATCH_PROMPT.format(app_code=app_code)

    print(f"  [{entry['id'][:8]}] Calling {model}...")
    patch_text = call_opus(api_key, model, prompt)

    if not patch_text:
        result["stage"] = "no_response"
        return result

    result["raw_response"] = patch_text[:4000]

    patched = parse_multifile(patch_text)
    if not patched or "main.py" not in patched:
        result["stage"] = "parse_failed"
        print(f"  [{entry['id'][:8]}] Parse failed — model didn't produce <file> blocks")
        return result

    result["patched_files"] = patched

    print(f"  [{entry['id'][:8]}] Running exploit against patched app...")
    try:
        out = run_in_local_sandbox(patched, entry["exploit"], "exploit.py")
        if "PWNED" in out:
            result["stage"] = "exploit_still_works"
            print(f"  [{entry['id'][:8]}] FAIL — exploit still works (PWNED)")
            return result
    except Exception as e:
        result["stage"] = f"exploit_check_error: {str(e)[:100]}"
        return result

    print(f"  [{entry['id'][:8]}] Running spec test against patched app...")
    try:
        out = run_in_local_sandbox(patched, entry["spec_test"], "spec_test.py")
        if "SPEC_PASS" not in out:
            result["stage"] = "spec_broken"
            print(f"  [{entry['id'][:8]}] FAIL — spec broken (SPEC_PASS not found)")
            return result
    except Exception as e:
        result["stage"] = f"spec_check_error: {str(e)[:100]}"
        return result

    result["passed"] = True
    result["stage"] = "passed"
    print(f"  [{entry['id'][:8]}] PASS!")
    return result


def main():
    parser = argparse.ArgumentParser(description="Local VibeSec eval with Claude Opus")
    parser.add_argument("--n", type=int, default=5, help="Number of dataset entries to evaluate (default: 5)")
    parser.add_argument("--model", type=str, default="claude-opus-4-8", help="Anthropic model ID (default: claude-opus-4-8)")
    parser.add_argument("--offset", type=int, default=0, help="Skip first N entries")
    args = parser.parse_args()

    api_key = os.environ.get("OPUS_API_KEY")
    if not api_key:
        print("ERROR: Set OPUS_API_KEY in your .env file")
        sys.exit(1)

    dataset_path = Path(__file__).parent / "dataset.jsonl"
    if not dataset_path.exists():
        print(f"ERROR: {dataset_path} not found")
        sys.exit(1)

    with open(dataset_path) as f:
        dataset = [json.loads(line) for line in f]

    subset = dataset[args.offset : args.offset + args.n]

    print(f"\nDetecting available model on your API key...")
    model = detect_model(api_key, args.model)

    print(f"\n{'='*60}")
    print(f"VibeSec Local Eval")
    print(f"  Model:   {model}")
    print(f"  Entries: {len(subset)} (of {len(dataset)} total)")
    print(f"  Offset:  {args.offset}")
    print(f"{'='*60}\n")

    results = []
    for i, entry in enumerate(subset):
        print(f"\n--- Entry {i+1}/{len(subset)}: {entry['vuln_class']} ---")
        print(f"  Prompt: {entry['seed_prompt'][:80]}...")
        r = score_one(entry, api_key, model)
        results.append(r)

    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    pct = 100 * passed / total if total else 0

    print(f"\n{'='*60}")
    print(f"RESULTS: {args.model}")
    print(f"{'='*60}")
    print(f"  Passed: {passed}/{total} ({pct:.1f}%)\n")

    by_class = Counter()
    fail_reasons = Counter()
    for r in results:
        if r["passed"]:
            by_class[r["vuln_class"]] += 1
        else:
            fail_reasons[r["stage"]] += 1

    if by_class:
        print("  Passes by vuln class:")
        for cls, count in by_class.most_common():
            print(f"    {cls}: {count}")

    if fail_reasons:
        print("\n  Failure reasons:")
        for reason, count in fail_reasons.most_common():
            print(f"    {reason}: {count}")

    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  {status}  {r['entry_id'][:12]}  {r['vuln_class']:20s}  {r['stage']}")

    os.makedirs("eval_runs", exist_ok=True)
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_path = f"eval_runs/eval_opus_{run_id}.jsonl"
    with open(run_path, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    print(f"\nResults saved to: {run_path}")


if __name__ == "__main__":
    main()
