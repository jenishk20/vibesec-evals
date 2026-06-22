import modal
import time

app = modal.App.lookup("vulnbench", create_if_missing=True)

# Image with our deps baked in
image = (
    modal.Image.debian_slim()
    .pip_install("fastapi", "uvicorn", "requests")
)

APP_CODE = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/hello")
def hello():
    return {"msg": "hi from inside the sandbox"}
"""

# 1. Spin up the sandbox
print("Creating sandbox...")
sb = modal.Sandbox.create(app=app, image=image, timeout=120)

# 2. Write the app file into the sandbox
print("Writing app code...")
with sb.open("/root/app.py", "w") as f:
    f.write(APP_CODE)

# 3. Start uvicorn in the background
print("Starting web server...")
server = sb.exec(
    "uvicorn", "app:app",
    "--host", "127.0.0.1", "--port", "8000",
    workdir="/root",
)

# 4. Give it a moment to boot
print("Waiting 5 seconds for server to come up...")
time.sleep(20)

# 5. Hit it from inside the sandbox
print("Making HTTP request from inside sandbox...")
hit = sb.exec(
    "python", "-c",
    "import requests; print(requests.get('http://127.0.0.1:8000/hello').text)"
)
hit.wait()

print("---")
print("RESPONSE:", hit.stdout.read())
print("EXIT CODE:", hit.returncode)

sb.terminate()
print("Done.")
