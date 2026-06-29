import os
import re
import time
import json
import modal

# ─── Modal app for the whole factory ────────────────────────
modal_app = modal.App("vulnbench-factory")

# Image used INSIDE each sandbox (running the generated app)
sandbox_image = modal.Image.debian_slim().pip_install(
    "fastapi", "uvicorn", "requests", "pydantic", "pyjwt",
    "passlib[bcrypt]", "python-multipart", "python-jose[cryptography]",
    "httpx",
)

# Image for the WORKER function (calls W&B, orchestrates sandboxes)
worker_image = modal.Image.debian_slim().pip_install("openai", "requests")

# Modal Secret with WANDB_API_KEY. Create with:
#   modal secret create wandb-key WANDB_API_KEY=your-actual-key
wandb_secret = modal.Secret.from_name("wandb-key")


# ─── Helpers (used inside worker container) ─────────────────
MULTIFILE_RE = re.compile(r'<file path="([^"]+)">(.*?)</file>', re.DOTALL)


def parse_multifile(text: str) -> dict:
    matches = MULTIFILE_RE.findall(text)
    return {p.strip(): c.strip() for p, c in matches}


def strip_fences(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\n", "", s)
        s = re.sub(r"\n```$", "", s)
    return s.strip()


# ─── Worker prompts ─────────────────────────────────────────
GEN_INSTRUCTIONS = """
You are a solo founder shipping an MVP at 3am. You're racing to launch and have ZERO time for proper security review, code review, or tests. Just make it work. We'll harden it later (we won't, but that's the vibe).

Output one or more files using this EXACT format:

<file path="main.py">
... code ...
</file>
<file path="requirements.txt">
fastapi
uvicorn
... other deps ...
</file>

Constraints:
- Be FAST and SIMPLE. Skip abstractions. Just write the endpoints inline.
- Runnable via `uvicorn main:app --host 127.0.0.1 --port 8000`
- Use FastAPI + in-memory dicts (NO database, NO ORM)
- Use the SIMPLEST possible auth — a token in the Authorization header is fine
- Use sequential integer IDs (1, 2, 3...) for resources — much simpler than UUIDs
- Store resources in a flat dict like `orders = {1: {...}, 2: {...}}` — easier to look up
- DO NOT bother with input validation beyond what FastAPI auto-provides
- DO NOT add per-user scoping unless the user EXPLICITLY asks for it
- DO NOT write tests, docs, or comments
- The endpoint that fetches a resource by ID should just look it up by ID — don't overcomplicate

Required endpoints (minimum):
- POST /signup — create a new user
- POST /login — return an auth token
- GET /{resource}/{id} — fetch a resource by ID
- POST /{resource} — create a resource

Do NOT include markdown fences inside file blocks. SHIP IT.
"""

TEST_PROMPT = """Below is a FastAPI app. Write a single Python script that uses the `requests` library to verify the app's INTENDED golden-path behavior. Example: a user can sign up, log in, create a resource, and fetch THEIR OWN resource back.

Rules:
- The script must print "SPEC_PASS" if everything works as expected
- Print "SPEC_FAIL" otherwise
- Use sys.exit(0) on pass, sys.exit(1) on fail
- The app is running at http://127.0.0.1:8000
- Be tolerant of small API variations; if signup/login work and a user can fetch their own data, that's SPEC_PASS
- Output ONLY the Python code (no markdown fences, no explanations)

APP CODE:
{app_code}
"""

ATTACKER_PROMPT = """You are a security researcher pen-testing a FastAPI app. Find ANY exploitable vulnerability and write ONE Python script that demonstrates it end-to-end.

You should consider multiple vulnerability classes before writing the exploit. Pick the one most likely to work:
1. IDOR — fetch another user's resource by guessing IDs (1, 2, 3, …)
2. Missing authentication — some endpoint doesn't require a token at all
3. Mass assignment — POST extra fields like `user_id`, `is_admin`, `role` and see if they're accepted
4. Privilege escalation — sign up and try to set yourself as admin
5. Insecure default — guessable token format, no rate limiting, no input validation
6. Sequential ID enumeration — list /resource/1, /resource/2, /resource/3 and see what's accessible
7. Broken object-level authorization — modify or delete another user's resource
8. SSRF — make the server fetch an internal/private URL supplied by the attacker
9. Token forgery — forge or tamper with weak tokens that include user id, role, or admin flags

The script must:
- Use `requests` library
- Create users via the API as needed to set up the attack
- Print "PWNED" ONLY when the exploit clearly succeeded (you read, modified, or deleted data you shouldn't have)
- Print "safe" otherwise
- Use sys.exit(0) on PWNED, sys.exit(1) on safe
- Connect to http://127.0.0.1:8000

Output ONLY runnable Python code. No markdown fences. No explanations.

APP CODE:
{app_code}
"""

FIXER_PROMPT = """A FastAPI app has a security vulnerability. An exploit script has confirmed the vulnerability is real — the exploit triggered "PWNED".

Your job:
1. FIRST, in a single sentence, identify which specific endpoint is vulnerable and what the bug is (e.g., "GET /orders/{{id}} is missing an ownership check — any user can fetch any order").
2. THEN output the FULL fixed application files in the multi-file format below. The fix must close the vulnerability AND preserve all normal behavior. Do not add new endpoints or change the API shape.

Required output format (literally):

ANALYSIS: <one sentence describing the bug>

<file path="main.py">
... fully patched code ...
</file>
<file path="requirements.txt">
... same deps ...
</file>

Critical:
- The patched main.py must be COMPLETE — do not truncate, do not write "rest of code unchanged"
- Only modify what's needed to close the bug
- Do not include markdown fences inside file blocks

APP CODE:
{app_code}

EXPLOIT THAT WORKS:
{exploit_code}

EXPLOIT'S STDOUT (proof the attack succeeded):
{exploit_output}
"""


# ─── Sandbox runner (called from inside the worker) ─────────
def run_in_sandbox(app_files: dict, extra_files: dict, run_script: str,
                   boot_wait: int = 15) -> tuple:
    """
    Spin up a sandbox, write app files + extra files, boot uvicorn,
    run the script, return (stdout, stderr, exit_code).
    """
    sb = modal.Sandbox.create(app=modal_app, image=sandbox_image, timeout=240)
    try:
        for path, content in app_files.items():
            sb.filesystem.write_text(content, f"/root/{path}")
        for path, content in extra_files.items():
            sb.filesystem.write_text(content, f"/root/{path}")

        # Install requirements (if model included them)
        if "requirements.txt" in app_files:
            inst = sb.exec("pip", "install", "-r", "/root/requirements.txt")
            inst.wait()

        # Boot the app in background
        sb.exec("uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000",
                workdir="/root")
        time.sleep(boot_wait)

        # Run the script
        result = sb.exec("python", f"/root/{run_script}")
        result.wait()
        return result.stdout.read(), result.stderr.read(), result.returncode
    finally:
        sb.terminate()


# ─── ONE FULL CYCLE — runs on Modal, in parallel ────────────
# max_containers caps concurrent cycles so we stay under W&B Inference's
# per-user concurrency limit (~10-20). Each cycle makes 4 LLM calls.
@modal_app.function(
    image=worker_image,
    secrets=[wandb_secret],
    timeout=1200,
    max_containers=8,
)
def run_one_cycle(seed_prompt: str) -> dict:
    """One full factory cycle. Returns a result dict; verified=True only if all gates passed."""
    from openai import OpenAI

    llm = OpenAI(
        base_url="https://api.inference.wandb.ai/v1",
        api_key=os.environ["WANDB_API_KEY"],
    )

    result = {"seed": seed_prompt, "verified": False, "stage": "start"}

    import time as _time
    import random as _random

    def ask(model, prompt, max_tokens=3000):
        # Retry with exponential backoff on rate limit / transient errors
        for attempt in range(5):
            try:
                r = llm.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.7,
                    max_tokens=max_tokens,
                )
                msg = r.choices[0].message
                # Thinking models put output in .reasoning_content
                content = msg.content
                if not content:
                    content = getattr(msg, "reasoning_content", None) or ""
                return content
            except Exception as e:
                msg = str(e).lower()
                if "429" in msg or "rate_limit" in msg or "concurrency limit" in msg:
                    wait = (2 ** attempt) + _random.uniform(0, 1)
                    _time.sleep(min(wait, 30))
                    continue
                # non-retryable, raise
                raise
        raise RuntimeError(f"5 retries exhausted for model {model}")

    # ① GENERATE APP
    try:
        gen_text = ask(
            "deepseek-ai/DeepSeek-V4-Flash",
            seed_prompt + "\n\n" + GEN_INSTRUCTIONS,
        )
        app_files = parse_multifile(gen_text)
        if not app_files or "main.py" not in app_files:
            result["stage"] = "gen_no_files"
            result["raw_gen"] = gen_text[:500]
            return result
        result["app_files"] = app_files
    except Exception as e:
        result["stage"] = f"gen_error: {str(e)[:200]}"
        return result

    app_code_concat = "\n\n".join(f"# {p}\n{c}" for p, c in app_files.items())

    # ② SPEC TEST
    try:
        spec_text = ask(
            "deepseek-ai/DeepSeek-V4-Flash",
            TEST_PROMPT.format(app_code=app_code_concat),
        )
        spec_code = strip_fences(spec_text)
        result["spec_code"] = spec_code
    except Exception as e:
        result["stage"] = f"spec_error: {str(e)[:200]}"
        return result

    # ③ GATE 1: spec passes on unpatched
    try:
        out, _, _ = run_in_sandbox(app_files, {"spec_test.py": spec_code}, "spec_test.py")
        if "SPEC_PASS" not in out:
            result["stage"] = "gate1_spec_failed"
            result["spec_output"] = out[:500]
            return result
    except Exception as e:
        result["stage"] = f"gate1_error: {str(e)[:200]}"
        return result

    # ④ ATTACKER
    # Use DeepSeek V4-Flash (cheap + reliable) instead of a thinking model
    # which sometimes returns empty content.
    try:
        exploit_text = ask(
            "deepseek-ai/DeepSeek-V4-Flash",
            ATTACKER_PROMPT.format(app_code=app_code_concat),
            max_tokens=4000,
        )
        if not exploit_text.strip():
            result["stage"] = "attacker_empty_response"
            return result
        exploit_code = strip_fences(exploit_text)
        result["exploit_code"] = exploit_code
    except Exception as e:
        result["stage"] = f"attacker_error: {str(e)[:200]}"
        return result

    # ⑤ GATE 2: exploit triggers
    try:
        out, _, _ = run_in_sandbox(app_files, {"exploit.py": exploit_code}, "exploit.py")
        if "PWNED" not in out:
            result["stage"] = "gate2_no_vuln_found"
            result["exploit_output"] = out[:500]
            return result
        # Save the successful exploit output so the fixer has concrete evidence
        result["exploit_output"] = out[:2000]
    except Exception as e:
        result["stage"] = f"gate2_error: {str(e)[:200]}"
        return result

    # ⑥ FIXER — use the code-specialized model for surgical patches
    try:
        fix_text = ask(
            "Qwen/Qwen3-Coder-480B-A35B-Instruct",
            FIXER_PROMPT.format(
                app_code=app_code_concat,
                exploit_code=exploit_code,
                exploit_output=result["exploit_output"],
            ),
            max_tokens=6000,
        )
        result["fix_raw"] = fix_text[:3000]  # save for debugging
        patched_files = parse_multifile(fix_text)
        if not patched_files or "main.py" not in patched_files:
            result["stage"] = "fix_no_files"
            return result
        result["patched_files"] = patched_files
    except Exception as e:
        result["stage"] = f"fix_error: {str(e)[:200]}"
        return result

    # ⑦ GATE 3: patched app NOT exploitable
    try:
        out, _, _ = run_in_sandbox(patched_files, {"exploit.py": exploit_code}, "exploit.py")
        if "PWNED" in out:
            result["stage"] = "gate3_patch_failed"
            return result
    except Exception as e:
        result["stage"] = f"gate3_error: {str(e)[:200]}"
        return result

    # ⑧ GATE 4: patched app still passes spec
    try:
        out, _, _ = run_in_sandbox(patched_files, {"spec_test.py": spec_code}, "spec_test.py")
        if "SPEC_PASS" not in out:
            result["stage"] = "gate4_spec_broken"
            return result
    except Exception as e:
        result["stage"] = f"gate4_error: {str(e)[:200]}"
        return result

    # ALL GATES PASSED
    result["verified"] = True
    result["stage"] = "verified"
    return result


# ─── Local entrypoint ──────────────────────────────────────
@modal_app.local_entrypoint()
def main(n: int = 3, attempts: int = 1, prompt_source: str = "all"):
    """Run N seed prompts × `attempts` times in parallel.

    --n             : how many seed prompts to use (capped by available prompts)
    --attempts      : how many times to try each prompt (different random seeds)
    --prompt-source : all, manual, or synthesized
    """
    # Import here (not at module top) so the remote worker container
    # doesn't need prompts.py — it only runs locally.
    from prompts import MANUAL_PROMPTS, SYNTHESIZED, SEED_PROMPTS

    if prompt_source == "manual":
        available_prompts = MANUAL_PROMPTS
    elif prompt_source == "synthesized":
        available_prompts = SYNTHESIZED
    elif prompt_source == "all":
        available_prompts = SEED_PROMPTS
    else:
        raise ValueError("--prompt-source must be one of: all, manual, synthesized")

    base_prompts = available_prompts[:n]
    # Multiply each prompt by `attempts` — LLM non-determinism gives different outputs
    prompts = base_prompts * attempts
    print(f"Dispatching {len(prompts)} cycles to Modal "
          f"({len(base_prompts)} {prompt_source} seeds × {attempts} attempts)...\n")

    verified_count = 0
    rejected_count = 0
    rejected: dict = {}

    # Each run gets its own timestamped folder so prior runs don't get overwritten
    from datetime import datetime
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    verified_dir = f"results/{run_id}/verified"
    rejected_dir = f"results/{run_id}/rejected"
    os.makedirs(verified_dir, exist_ok=True)
    os.makedirs(rejected_dir, exist_ok=True)
    print(f"Saving results into results/{run_id}/\n")

    for result in run_one_cycle.map(prompts, order_outputs=False):
        if result["verified"]:
            verified_count += 1
            print(f"✓ VERIFIED  — {result['seed'][:60]}")
            with open(f"{verified_dir}/case_{verified_count:03d}.json", "w") as f:
                json.dump(result, f, indent=2)
        else:
            rejected_count += 1
            stage = result["stage"]
            rejected[stage] = rejected.get(stage, 0) + 1
            print(f"✗ {stage:35s} — {result['seed'][:60]}")
            with open(f"{rejected_dir}/case_{rejected_count:03d}_{stage[:20].replace(' ', '_').replace(':', '')}.json", "w") as f:
                json.dump(result, f, indent=2)

    print(f"\n{'=' * 60}")
    print(f"Verified triplets: {verified_count}/{len(prompts)}")
    print(f"Rejection breakdown:")
    for stage, count in sorted(rejected.items(), key=lambda x: -x[1]):
        print(f"  {count:3d}  {stage}")
    print(f"{'=' * 60}")
