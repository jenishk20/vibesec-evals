# VibeSec

**Can the AI that writes your startup also secure it?**

VibeSec is a *verified* benchmark for LLM security. An AI vibe-codes a small web app from a casual founder prompt, a second AI writes a working exploit, a third AI patches it — and **every step is executed in a sandbox**, not graded by another LLM. The result is a dataset of vulnerable apps where the vulnerability is *proven real* (an exploit actually triggered it) and the fix is *proven correct* (the exploit stops working and the app still passes its spec).

We then score frontier models on the one task that matters: **given a real, exploit-proven vulnerability, can you patch it without breaking the app?**

---

## Why this is different

Most "LLM security" benchmarks are static code snippets graded by a judge model. That measures plausibility, not truth. VibeSec is **execution-verified end to end**:

- The vulnerable app **boots and serves traffic** in an isolated [Modal](https://modal.com) sandbox.
- The exploit is a real Python script that **prints `PWNED` only when it reads/modifies data it shouldn't**.
- The patch must make that exact exploit **fail** *and* keep the golden-path spec test **passing**.

No LLM-as-judge anywhere in the verification loop. If it's in the dataset, the bug was real and the fix worked.

---

## The factory pipeline

```
 synthesize_prompts.py        "founder at 2am" seed prompts, biased per vuln class
        │
        ▼
 factory_loop.py  (Modal)     one cycle per prompt, 4 LLM calls + 4 sandbox gates:
        │
        ├─ ① generate vulnerable FastAPI app        (DeepSeek-V4-Flash)
        ├─ ② generate golden-path spec test
        ├─ ③ GATE 1  spec passes on unpatched app   ── sandbox
        ├─ ④ generate exploit                        (DeepSeek-V4-Flash)
        ├─ ⑤ GATE 2  exploit prints PWNED            ── sandbox
        ├─ ⑥ generate patch                          (Qwen3-Coder-480B)
        ├─ ⑦ GATE 3  exploit now FAILS on patch      ── sandbox
        └─ ⑧ GATE 4  spec still passes on patch      ── sandbox
        │
        ▼
 aggregate.py                 dedup verified triplets ──► dataset.jsonl
        │
        ▼
 eval_models.py  (Modal)      score frontier models on patching each entry
        │
        ▼
 dashboard.py                 Streamlit leaderboard + dataset explorer
```

Only cycles where **all four gates pass** make it into the dataset. Everything else is saved to `results/<run>/rejected/` with the failure stage, so the pipeline is fully auditable.

---

## The dataset

`dataset.jsonl` — **162 verified triplets** (and growing). Each line:

| field | meaning |
|---|---|
| `id` | sha256 of the exploit (dedup key) |
| `seed_prompt` | the casual founder prompt that produced the app |
| `vuln_class` | auto-labeled: `idor`, `missing_auth`, `mass_assignment`, `privilege_escalation`, `path_traversal`, `sql_injection` |
| `app_files` | the vulnerable app (`main.py` + `requirements.txt`) |
| `spec_test` | golden-path test — prints `SPEC_PASS`/`SPEC_FAIL` |
| `exploit` | working exploit — prints `PWNED`/`safe` |
| `exploit_output` | captured stdout proving the attack landed |
| `patched_files` | a reference patch that closes the bug and keeps the spec green |

The vulnerabilities are the classic ones AI coding assistants reintroduce constantly when you tell them to "just ship it": missing ownership checks (IDOR), unauthenticated endpoints, mass assignment, privilege escalation.

> Vulnerability classes are currently heuristically labeled from the exploit code; label refinement is on the roadmap.

---

## Quickstart

```bash
python -m venv myenv && source myenv/bin/activate
pip install -r requirements.txt

# 1. Generate seed prompts (needs WANDB_API_KEY)
python synthesize_prompts.py 30 idor

# 2. Run the factory on Modal (needs `modal setup` + secrets, see below)
modal run factory_loop.py --n 30 --attempts 2

# 3. Aggregate verified triplets into the dataset
python aggregate.py

# 4. Score frontier models (needs OPENROUTER_API_KEY)
modal run eval_models.py --sanity-check      # 1 model × 5 entries
modal run eval_models.py                      # full leaderboard

# 5. Explore results
streamlit run dashboard.py
```

### Credentials

Local `.env` (git-ignored):

```
WANDB_API_KEY=...        # W&B Inference, for generation models
OPENROUTER_API_KEY=...   # OpenRouter, for the frontier-model eval
```

Modal secrets (for the sandboxed workers):

```bash
modal secret create wandb-key WANDB_API_KEY=...
modal secret create openrouter-key OPENROUTER_API_KEY=...
```

---

## Why Modal

Running AI-generated code and AI-written exploits on your own machine is reckless. Modal gives each cycle a fresh, isolated, network-contained sandbox that's torn down after one run — and `.map()` fans hundreds of cycles out in parallel for a few cents each.

---

## Roadmap

- [ ] Harden the eval harness (robust multi-file extraction so format quirks aren't scored as security failures)
- [ ] Refine vulnerability-class labeling beyond heuristics
- [ ] Broaden beyond FastAPI (Express, Next.js route handlers, Flask)
- [ ] Publish the dataset to Hugging Face + a hosted leaderboard that auto-reruns when new models ship
- [ ] Expand vuln classes (SSRF, auth-token forgery, race conditions)

## License

MIT — see [LICENSE](LICENSE).
