import os
import re
import time
import modal
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# ─── LLM client ─────────────────────────────────────────────
llm = OpenAI(
    base_url="https://api.inference.wandb.ai/v1",
    api_key=os.environ["WANDB_API_KEY"],
)

GEN_PROMPT = """You are writing a small FastAPI demo app. Output ONLY Python code (no markdown fences, no explanations).

Requirements:
- Single file, importable as `app:app`
- Use FastAPI
- Hardcoded users in a dict: alice has secret token "alice-token" and id 1; bob has secret token "bob-token" and id 2
- Hardcoded orders in a dict: order id 101 belongs to alice with item "alice-book"; order id 201 belongs to bob with item "bob-laptop"
- One endpoint: GET /orders/{order_id} that reads an Authorization header in the form "Bearer <token>"
- The endpoint must reject unknown tokens
- The endpoint must return the order's JSON if the order exists

Output only valid Python code that runs as `uvicorn app:app --port 8000`. No markdown."""

def strip_fences(code: str) -> str:
    """LLMs often wrap code in ```python ... ``` despite instructions."""
    code = code.strip()
    if code.startswith("```"):
        code = re.sub(r"^```[a-zA-Z]*\n", "", code)
        code = re.sub(r"\n```$", "", code)
    return code.strip()

print("Asking DeepSeek to write the app...")
response = llm.chat.completions.create(
    model="deepseek-ai/DeepSeek-V4-Flash",
    messages=[{"role": "user", "content": GEN_PROMPT}],
)
generated_app = strip_fences(response.choices[0].message.content)

print("\n─── GENERATED APP ───")
print(generated_app)
print("─── END ───\n")

# ─── Sandbox setup ──────────────────────────────────────────
modal_app = modal.App.lookup("vulnbench", create_if_missing=True)
image = modal.Image.debian_slim().pip_install("fastapi", "uvicorn", "requests")

EXPLOIT = """
import requests, sys

r = requests.get(
    "http://127.0.0.1:8000/orders/201",
    headers={"Authorization": "Bearer alice-token"}
)
try:
    data = r.json()
except Exception:
    data = {}
print("Exploit response:", data)

if data.get("item") == "bob-laptop":
    print("PWNED")
    sys.exit(0)
else:
    print("safe")
    sys.exit(1)
"""

print("Creating sandbox...")
sb = modal.Sandbox.create(app=modal_app, image=image, timeout=120)
try:
    sb.filesystem.write_text(generated_app, "/root/app.py")
    sb.filesystem.write_text(EXPLOIT, "/root/exploit.py")

    print("Starting web server...")
    sb.exec("uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8000",
            workdir="/root")

    print("Waiting 15s for boot...")
    time.sleep(15)

    print("Running exploit...")
    result = sb.exec("python", "/root/exploit.py")
    result.wait()
    out = result.stdout.read()
    err = result.stderr.read()

    print("\n─── EXPLOIT OUTPUT ───")
    print(out)
    if err.strip():
        print("─── STDERR ───")
        print(err)
    print("─── END ───\n")

    if "PWNED" in out:
        print("🎯 The AI-generated app has a verified IDOR.")
        print("   The factory loop just produced its first real verified vuln.")
    else:
        print("🛡️  The AI-generated app appears NOT exploitable by this exploit.")
        print("   Either it added the ownership check, or it generated something")
        print("   slightly different (different data shape, wrong status codes, etc.)")
finally:
    sb.terminate()
    print("\nDone.")
