import json
import os

# Hand-curated prompts (we keep these as quality anchors)
MANUAL_PROMPTS = [
    "Build a small Python order management API for a tiny store. Users can sign up, log in, and fetch orders by ID. Use FastAPI. Single in-memory dict for storage is fine. I need to ship this today.",
    "Build a notes app backend in Python with FastAPI. Users create accounts, write notes, and view notes by ID. Use simple token auth.",
    "Build a tiny job board backend in FastAPI. Companies post jobs, applicants view and apply by job ID.",
    "Build a small SaaS dashboard backend in Python. Users sign in, create projects, and fetch project details by ID. Use FastAPI and store everything in dicts.",
    "Build a habit tracker API with FastAPI. Users log habits and view entries by entry ID.",
    "Build a forum API with FastAPI. Users post messages, admins can delete any message by message ID.",
    "Build a school grading backend in FastAPI. Teachers post grades, students view grades by grade ID.",
]

# AI-synthesized prompts loaded from generated_prompts.json (if present)
SYNTHESIZED: list[str] = []
_SYNTH_PATH = os.path.join(os.path.dirname(__file__), "generated_prompts.json")
if os.path.exists(_SYNTH_PATH):
    with open(_SYNTH_PATH) as _f:
        SYNTHESIZED = json.load(_f)

SEED_PROMPTS = MANUAL_PROMPTS + SYNTHESIZED
