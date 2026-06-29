---
license: mit
pretty_name: VibeSec
language:
- en
task_categories:
- text-generation
tags:
- security
- code
- benchmark
- llm-evaluation
- vulnerability
- fastapi
size_categories:
- n<1K
configs:
- config_name: default
  data_files:
  - split: train
    path: dataset.jsonl
---

# VibeSec

**Execution-verified security evals for AI coding agents.**

VibeSec measures whether a model can patch a real, exploit-proven vulnerability
without breaking the app. Each task starts from a casual founder-style prompt,
generates a small FastAPI app, proves a vulnerability with a runnable exploit,
and verifies the patch in a sandbox.

- 📊 **Code & leaderboard:** https://github.com/jenishk20/vibesec-evals
- 🧪 **Verification:** every triplet passes four executable gates — no LLM-as-judge.

## What makes it different

Most LLM security benchmarks use static snippets or judge-model grading. VibeSec
uses executable gates. A task only enters this dataset if all four pass:

1. The generated app boots and passes a golden-path spec test.
2. A real exploit script prints `PWNED`.
3. A reference patch makes that exact exploit fail.
4. The patched app still passes the original spec.

## Dataset summary

- **172 verified triplets.**
- Each is a vulnerable app, a passing spec test, a working exploit, and a
  known-good reference patch.
- Vulnerabilities are the ones AI coding assistants reintroduce when told to
  "just ship it": missing ownership checks (IDOR), unauthenticated endpoints,
  mass assignment, and privilege escalation.

### Vulnerability class distribution

| class | tasks | share |
|---|---:|---:|
| `idor` (broken object-level authorization) | 145 | 84% |
| `missing_auth` | 13 | 8% |
| `mass_assignment` | 9 | 5% |
| `privilege_escalation` | 3 | 2% |
| `other` | 2 | 1% |

> IDOR = Insecure Direct Object Reference; in current OWASP API terms, Broken
> Object Level Authorization — a user can access an object by ID even though
> they do not own it.

## Fields

Each row in `dataset.jsonl`:

| field | meaning |
|---|---|
| `id` | sha256 prefix of the exploit (dedup key) |
| `seed_prompt` | the casual founder prompt that produced the app |
| `vuln_class` | heuristic label from the exploit code |
| `app_files` | the vulnerable app (`main.py` + `requirements.txt`) |
| `spec_test` | golden-path test — prints `SPEC_PASS` / `SPEC_FAIL` |
| `exploit` | working exploit — prints `PWNED` / `safe` |
| `exploit_output` | captured stdout proving the attack landed |
| `patched_files` | a reference patch that closes the bug and keeps the spec green |
| `source_file` | provenance path inside the factory run |

## Usage

```python
from datasets import load_dataset

ds = load_dataset("muence/vibesec", split="train")
ex = ds[0]
print(ex["vuln_class"])
print(ex["app_files"]["main.py"])
print(ex["exploit"])
```

## Leaderboard snapshot (V0)

Six models scored on patching all 172 tasks (pass = exploit blocked **and** spec
still passes):

| model | pass rate |
|---|---:|
| Claude Opus 4.8 | 127 / 172 (73.8%) |
| Claude Sonnet 4.6 | 73 / 172 (42.4%) |
| Kimi K2.7 Code | 64 / 172 (37.2%) |
| GLM 5.2 | 56 / 172 (32.6%) |
| Nemotron 3 Ultra | 52 / 172 (30.2%) |
| GPT-OSS 120B | 18 / 172 (10.5%) |

## Limitations

- The dataset is synthetic and FastAPI-focused.
- It is currently IDOR-heavy (84%); other classes are under-represented.
- Vulnerability labels are heuristic and should be refined before larger use.
- Tasks are public and inspectable, so a serious leaderboard should add a
  private held-out split for official scoring.

## License

MIT.

## Citation

```bibtex
@misc{vibesec2026,
  title  = {VibeSec: Execution-Verified Security Evals for AI Coding Agents},
  author = {Kothari, Jenish},
  year   = {2026},
  url    = {https://github.com/jenishk20/vibesec-evals}
}
```
