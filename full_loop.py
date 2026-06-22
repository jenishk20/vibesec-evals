import modal
import time

app = modal.App.lookup("vulnbench", create_if_missing=True)
image = modal.Image.debian_slim().pip_install("fastapi", "uvicorn", "requests")

# ───────────────────────────────────────────────────────
# Vulnerable app (IDOR)
# ───────────────────────────────────────────────────────
VULN_APP = """
from fastapi import FastAPI, Header

app = FastAPI()

USERS = {
    1: {"name": "alice", "secret": "alice-token"},
    2: {"name": "bob",   "secret": "bob-token"},
}
ORDERS = {
    101: {"user_id": 1, "item": "alice-book"},
    201: {"user_id": 2, "item": "bob-laptop"},
}

def get_uid(token):
    for uid, u in USERS.items():
        if u["secret"] == token:
            return uid
    return None

@app.get("/orders/{order_id}")
def get_order(order_id: int, authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "")
    uid = get_uid(token)
    if uid is None:
        return {"error": "unauth"}
    # BUG: no ownership check
    if order_id in ORDERS:
        return ORDERS[order_id]
    return {"error": "not found"}
"""

# ───────────────────────────────────────────────────────
# Patched app — same, but with the ownership check
# ───────────────────────────────────────────────────────
PATCHED_APP = """
from fastapi import FastAPI, Header

app = FastAPI()

USERS = {
    1: {"name": "alice", "secret": "alice-token"},
    2: {"name": "bob",   "secret": "bob-token"},
}
ORDERS = {
    101: {"user_id": 1, "item": "alice-book"},
    201: {"user_id": 2, "item": "bob-laptop"},
}

def get_uid(token):
    for uid, u in USERS.items():
        if u["secret"] == token:
            return uid
    return None

@app.get("/orders/{order_id}")
def get_order(order_id: int, authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "")
    uid = get_uid(token)
    if uid is None:
        return {"error": "unauth"}
    # FIX: check ownership
    if order_id in ORDERS and ORDERS[order_id]["user_id"] == uid:
        return ORDERS[order_id]
    return {"error": "not found"}
"""

# ───────────────────────────────────────────────────────
# Exploit — Alice tries to read Bob's order
# ───────────────────────────────────────────────────────
EXPLOIT = """
import requests, sys

r = requests.get(
    "http://127.0.0.1:8000/orders/201",
    headers={"Authorization": "Bearer alice-token"}
)
data = r.json()
print("Exploit response:", data)

if data.get("item") == "bob-laptop":
    print("PWNED")
    sys.exit(0)
else:
    print("safe")
    sys.exit(1)
"""

# ───────────────────────────────────────────────────────
# Spec test — Alice fetching her own order should succeed
# ───────────────────────────────────────────────────────
SPEC_TEST = """
import requests, sys

r = requests.get(
    "http://127.0.0.1:8000/orders/101",
    headers={"Authorization": "Bearer alice-token"}
)
data = r.json()
print("Spec response:", data)

if data.get("item") == "alice-book":
    print("SPEC_PASS")
    sys.exit(0)
else:
    print("SPEC_FAIL")
    sys.exit(1)
"""

# ───────────────────────────────────────────────────────
# One reusable runner: boot an app, run a script, return stdout
# ───────────────────────────────────────────────────────
def run_case(label: str, app_code: str, script_code: str, script_name: str) -> str:
    print(f"\n{'=' * 55}")
    print(f"  {label}")
    print(f"{'=' * 55}")
    sb = modal.Sandbox.create(app=app, image=image, timeout=120)
    try:
        sb.filesystem.write_text(app_code, "/root/app.py")
        sb.filesystem.write_text(script_code, f"/root/{script_name}")
        sb.exec("uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8000",
                workdir="/root")
        time.sleep(15)
        result = sb.exec("python", f"/root/{script_name}")
        result.wait()
        out = result.stdout.read()
        print(out)
        return out
    finally:
        sb.terminate()


# ───────────────────────────────────────────────────────
# The three gates
# ───────────────────────────────────────────────────────
pass1 = run_case("PASS 1: Unpatched + exploit → expect PWNED",
                 VULN_APP, EXPLOIT, "exploit.py")
assert "PWNED" in pass1, "Pass 1 failed: vuln did not trigger on unpatched app"
print("✓ Vuln verified on unpatched app\n")

pass2 = run_case("PASS 2: Patched + exploit → expect NO PWNED",
                 PATCHED_APP, EXPLOIT, "exploit.py")
assert "PWNED" not in pass2, "Pass 2 failed: patch did NOT close the vuln"
print("✓ Patch closes the vuln\n")

pass3 = run_case("PASS 3: Patched + spec test → expect SPEC_PASS",
                 PATCHED_APP, SPEC_TEST, "spec.py")
assert "SPEC_PASS" in pass3, "Pass 3 failed: patch broke normal behavior"
print("✓ Patch preserves intended behavior\n")

print("=" * 55)
print("  🎉 VERIFIED TRIPLET")
print("  (vulnerable_app, exploit, patch) — all gates passed.")
print("=" * 55)
