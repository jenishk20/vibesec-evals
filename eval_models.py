"""
Evaluate frontier models on the VulnBench-AI dataset via OpenRouter + Modal sandboxes.

For each (model, entry) pair:
  1. Ask the model to patch the vulnerable app
  2. Run the original exploit against the patched app → must NOT print PWNED
  3. Run the spec test against the patched app → must still print SPEC_PASS
  4. Pass = both gates pass

Usage:
  modal run eval_models.py --sanity-check               # 1 model × 5 entries (~$0.10)
  modal run eval_models.py                              # all models × all entries
  modal run eval_models.py --model "openai/gpt-5.1"     # one model only
  modal run eval_models.py --n 20                       # limit to first 20 entries
"""

import os
import re
import time
import json
import modal


# ─── Modal app ─────────────────────────────────────────────
modal_app = modal.App("vulnbench-eval")

sandbox_image = modal.Image.debian_slim().pip_install(
    "fastapi", "uvicorn", "requests", "pydantic", "pyjwt",
    "passlib[bcrypt]", "python-multipart", "python-jose[cryptography]",
    "httpx",
)

worker_image = modal.Image.debian_slim().pip_install("openai", "requests")

# Secrets — create with:
#   modal secret create openrouter-key OPENROUTER_API_KEY=sk-or-v1-...
#   modal secret create anthropic-key  ANTHROPIC_API_KEY=sk-ant-...
#   modal secret create wandb-key      WANDB_API_KEY=...   (already exists from factory)
openrouter_secret = modal.Secret.from_name("openrouter-key")
anthropic_secret = modal.Secret.from_name("anthropic-key")
wandb_secret = modal.Secret.from_name("wandb-key")


# ─── Models to evaluate (3 providers) ───────────────────────
# Direct Anthropic → uses ANTHROPIC_API_KEY. Cheaper than OpenRouter markup.
ANTHROPIC_DIRECT_MODELS = {
    "anthropic/claude-opus-4-8":   "claude-opus-4-8",
    "anthropic/claude-sonnet-4.6": "claude-sonnet-4-6",
}

# W&B Inference → uses WANDB_API_KEY. Cheap open-source frontier coverage.
# Slugs confirmed via curl https://api.inference.wandb.ai/v1/models
WANDB_DIRECT_MODELS = {
    "wandb/nemotron-3-ultra":     "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B",
    "wandb/qwen3-coder-480b":     "Qwen/Qwen3-Coder-480B-A35B-Instruct",
    "wandb/kimi-k2.7-code":       "moonshotai/Kimi-K2.7-Code",
    "wandb/glm-5.2":              "zai-org/GLM-5.2",
    "wandb/llama-3.3-70b":        "meta-llama/Llama-3.3-70B-Instruct",
    "wandb/gpt-oss-120b":         "openai/gpt-oss-120b",
}

# Everything else falls through to OpenRouter.
MODELS_TO_EVAL = [
    # Frontier closed (via Anthropic direct + OpenRouter)
    "anthropic/claude-opus-4-8",
    "anthropic/claude-sonnet-4.6",
    "openai/gpt-5.1",
    "google/gemini-2.5-pro",
    # Frontier open (via W&B Inference — cheap)
    "wandb/nemotron-3-ultra",
    "wandb/qwen3-coder-480b",
    "wandb/kimi-k2.7-code",
    "wandb/glm-5.2",
    "wandb/llama-3.3-70b",
    "wandb/gpt-oss-120b",
]


# ─── Helpers ───────────────────────────────────────────────
MULTIFILE_RE = re.compile(r'<file path="([^"]+)">(.*?)</file>', re.DOTALL)


def parse_multifile(text: str) -> dict:
    return {p.strip(): c.strip() for p, c in MULTIFILE_RE.findall(text)}


# ─── The patch prompt — same for every model ───────────────
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


def run_in_sandbox(app_files: dict, extra_files: dict, run_script: str) -> str:
    sb = modal.Sandbox.create(app=modal_app, image=sandbox_image, timeout=180)
    try:
        for path, content in app_files.items():
            sb.filesystem.write_text(content, f"/root/{path}")
        for path, content in extra_files.items():
            sb.filesystem.write_text(content, f"/root/{path}")
        if "requirements.txt" in app_files:
            sb.exec("pip", "install", "-r", "/root/requirements.txt").wait()
        sb.exec("uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000",
                workdir="/root")
        time.sleep(15)
        result = sb.exec("python", f"/root/{run_script}")
        result.wait()
        return result.stdout.read()
    finally:
        sb.terminate()


# ─── Score one (model, entry) pair ─────────────────────────
@modal_app.function(
    image=worker_image,
    secrets=[openrouter_secret, anthropic_secret, wandb_secret],
    timeout=600,
    max_containers=6,
)
def score_one(args: tuple) -> dict:
    from openai import OpenAI
    import time as _time
    import random as _random

    model, entry = args

    # Provider routing
    if model in ANTHROPIC_DIRECT_MODELS:
        llm = OpenAI(
            base_url="https://api.anthropic.com/v1/",
            api_key=os.environ["ANTHROPIC_API_KEY"],
        )
        api_model = ANTHROPIC_DIRECT_MODELS[model]
    elif model in WANDB_DIRECT_MODELS:
        llm = OpenAI(
            base_url="https://api.inference.wandb.ai/v1",
            api_key=os.environ["WANDB_API_KEY"],
        )
        api_model = WANDB_DIRECT_MODELS[model]
    else:
        # Default: OpenRouter
        llm = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.environ["OPENROUTER_API_KEY"],
            default_headers={
                "HTTP-Referer": "https://github.com/jenishk20/vulnbench-ai",
                "X-Title": "VulnBench-AI Eval",
            },
        )
        api_model = model

    result = {
        "model": model,
        "entry_id": entry["id"],
        "vuln_class": entry["vuln_class"],
        "passed": False,
        "stage": "start",
    }

    app_code = "\n\n".join(f"# {p}\n{c}" for p, c in entry["app_files"].items())

    # 1. Ask model to patch (with retry on transient errors)
    patch_text = None
    for attempt in range(3):
        try:
            # Opus 4.8 and other newer Claude models deprecated `temperature`
            call_kwargs = {
                "model": api_model,
                "messages": [{"role": "user", "content": PATCH_PROMPT.format(app_code=app_code)}],
                "max_tokens": 4000,
            }
            if model not in ANTHROPIC_DIRECT_MODELS:
                call_kwargs["temperature"] = 0.2
            resp = llm.chat.completions.create(**call_kwargs)
            patch_text = resp.choices[0].message.content
            if patch_text:
                break
        except Exception as e:
            msg = str(e).lower()
            if "429" in msg or "rate" in msg or "timeout" in msg:
                _time.sleep((2 ** attempt) + _random.uniform(0, 1))
                continue
            result["stage"] = f"llm_error: {str(e)[:120]}"
            return result

    if not patch_text:
        result["stage"] = "no_response_after_retries"
        return result

    # Always save the raw response so we can debug what the model produced
    result["raw_response"] = patch_text[:8000]

    patched = parse_multifile(patch_text)
    if not patched or "main.py" not in patched:
        result["stage"] = "parse_failed"
        return result
    result["patched_files"] = patched

    # 2. Verify original exploit no longer works
    try:
        out = run_in_sandbox(patched, {"exploit.py": entry["exploit"]}, "exploit.py")
        if "PWNED" in out:
            result["stage"] = "exploit_still_works"
            return result
    except Exception as e:
        result["stage"] = f"exploit_check_error: {str(e)[:100]}"
        return result

    # 3. Verify spec tests still pass
    try:
        out = run_in_sandbox(patched, {"spec_test.py": entry["spec_test"]}, "spec_test.py")
        if "SPEC_PASS" not in out:
            result["stage"] = "spec_broken"
            return result
    except Exception as e:
        result["stage"] = f"spec_check_error: {str(e)[:100]}"
        return result

    result["passed"] = True
    result["stage"] = "passed"
    return result


# ─── Local entrypoint ──────────────────────────────────────
@modal_app.local_entrypoint()
def main(sanity_check: bool = False, model: str = None, n: int = None):
    with open("dataset.jsonl") as f:
        dataset = [json.loads(line) for line in f]

    if sanity_check:
        dataset = dataset[:5]
        models = [MODELS_TO_EVAL[0]]
        print(f"SANITY CHECK: {models[0]} × {len(dataset)} entries (~$0.10)\n")
    else:
        if n:
            dataset = dataset[:n]
        models = [model] if model else MODELS_TO_EVAL
        print(f"FULL EVAL: {len(models)} models × {len(dataset)} entries = "
              f"{len(models) * len(dataset)} tasks\n")

    tasks = [(m, e) for m in models for e in dataset]

    # CRITICAL: open the timestamped per-run file BEFORE the loop and write
    # each result as it arrives. This way a mid-run crash doesn't lose data.
    from datetime import datetime as _dt
    import os as _os
    _os.makedirs("eval_runs", exist_ok=True)
    run_id = _dt.now().strftime("%Y%m%d_%H%M%S")
    run_path = f"eval_runs/eval_{run_id}.jsonl"
    print(f"Streaming results to {run_path}\n")

    results = []
    run_fh = open(run_path, "w", buffering=1)  # line-buffered = flush per line
    try:
        for r in score_one.map(tasks, order_outputs=False):
            results.append(r)
            # Write each result immediately so crashes don't lose data
            run_fh.write(json.dumps(r) + "\n")
            run_fh.flush()
            status = "✓" if r["passed"] else "✗"
            m_short = r["model"].split("/")[-1][:30]
            print(f"  {status} {m_short:30s} {r['entry_id']} {r['stage']}")
    except Exception as e:
        print(f"\n⚠️  Loop interrupted: {type(e).__name__}: {str(e)[:100]}")
        print(f"Partial results ({len(results)} so far) already saved to {run_path}")
        print(f"Continuing to merge what we have...\n")
    finally:
        run_fh.close()

    # Aggregate
    from collections import Counter, defaultdict
    by_model = defaultdict(lambda: {"passed": 0, "total": 0, "by_class": Counter(),
                                     "fail_reasons": Counter()})
    for r in results:
        m = r["model"]
        by_model[m]["total"] += 1
        if r["passed"]:
            by_model[m]["passed"] += 1
            by_model[m]["by_class"][r["vuln_class"]] += 1
        else:
            by_model[m]["fail_reasons"][r["stage"]] += 1

    print("\n" + "=" * 70)
    print("LEADERBOARD")
    print("=" * 70)
    for m, s in sorted(by_model.items(), key=lambda x: -x[1]["passed"] / max(x[1]["total"], 1)):
        pct = 100 * s["passed"] / s["total"] if s["total"] else 0
        bar = "█" * int(40 * pct / 100)
        print(f"  {m:45s}  {s['passed']:3d}/{s['total']:3d}  {pct:5.1f}%  {bar}")

    # APPEND to the rolling eval_results.jsonl (dedupe by model+entry, latest wins)
    existing: dict = {}
    if _os.path.exists("eval_results.jsonl"):
        with open("eval_results.jsonl") as f:
            for line in f:
                r = json.loads(line)
                existing[(r["model"], r["entry_id"])] = r
    for r in results:
        existing[(r["model"], r["entry_id"])] = r

    with open("eval_results.jsonl", "w") as f:
        for r in existing.values():
            f.write(json.dumps(r) + "\n")

    # Summary — rebuilt from the FULL merged set, not just this run
    merged_results = list(existing.values())
    merged_by_model: dict = {}
    for r in merged_results:
        m = r["model"]
        if m not in merged_by_model:
            merged_by_model[m] = {"passed": 0, "total": 0, "by_class": Counter(),
                                  "fail_reasons": Counter()}
        merged_by_model[m]["total"] += 1
        if r["passed"]:
            merged_by_model[m]["passed"] += 1
            merged_by_model[m]["by_class"][r["vuln_class"]] += 1
        else:
            merged_by_model[m]["fail_reasons"][r["stage"]] += 1

    summary = {m: {"passed": s["passed"], "total": s["total"],
                   "by_class": dict(s["by_class"]),
                   "fail_reasons": dict(s["fail_reasons"])}
               for m, s in merged_by_model.items()}
    with open("eval_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nSaved this run to:        {run_path}")
    print(f"Merged eval_results.jsonl now has {len(existing)} unique (model,entry) rows")
    print(f"Updated eval_summary.json with the FULL leaderboard:")
    for m, s in sorted(merged_by_model.items(), key=lambda x: -x[1]["passed"] / max(x[1]["total"], 1)):
        pct = 100 * s["passed"] / s["total"] if s["total"] else 0
        print(f"  {m:50s}  {s['passed']:3d}/{s['total']:3d}  {pct:.1f}%")
