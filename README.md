# VibeSec

**Execution-verified security evals for AI coding agents.**

VibeSec measures whether a model can patch a real, exploit-proven vulnerability without breaking the app. Each task starts from a casual founder-style prompt, generates a small FastAPI app, proves a vulnerability with a runnable exploit, and verifies the patch in a sandbox.

Suggested GitHub repo description:

> Execution-verified benchmark for AI coding security: generated apps, working exploits, sandbox-verified patches, and model leaderboards.

## What Makes It Different

Most LLM security benchmarks use static snippets or judge-model grading. VibeSec uses executable gates:

1. The generated app boots and passes a golden-path spec test.
2. A real exploit script prints `PWNED`.
3. A patch makes that exact exploit fail.
4. The patched app still passes the original spec.

Only candidates that pass all four gates enter `dataset.jsonl`.

## Current Dataset

`dataset.jsonl` currently contains **172 verified triplets**. A verified triplet is:

- `app_files`: the vulnerable generated app.
- `spec_test`: the normal-behavior test.
- `exploit`: the working exploit.
- `patched_files`: a known-good reference patch.

The dataset is also published on Hugging Face: **[muence/vibesec](https://huggingface.co/datasets/muence/vibesec)** — load it with `load_dataset("muence/vibesec")`.

IDOR means **Insecure Direct Object Reference**. In current OWASP API terminology, this is usually described as **Broken Object Level Authorization**: a user can access an object by ID even though they do not own or control it.

The current dataset is intentionally public for inspection. For a serious leaderboard, use:

- **Public inspect set:** examples people can browse and trust.
- **Private held-out set:** unseen tasks used for official model ranking.

## Dashboard

Run the benchmark UI:

```bash
pip install -r requirements.txt
streamlit run dashboard.py
```

The dashboard includes:

- model leaderboard and failure breakdowns;
- task explorer for prompt, app, spec, exploit, exploit output, patch, and diff;
- raw model response inspection;
- upvote, useful, needs-review, comment, share, star, fork, and issue actions;
- methodology and submission guidance.

Community feedback is stored locally in `community_feedback.jsonl`. For a hosted deployment, replace that file with GitHub issues, Supabase, Postgres, or another persistent backend.

## Generate More Tasks

Example: generate targeted prompts, run the factory, then aggregate.

```bash
python synthesize_prompts.py 20 missing_auth
modal run factory_loop.py --n 20 --attempts 2 --prompt-source synthesized

python aggregate.py
streamlit run dashboard.py
```

To move from 172 toward 200 tasks, prioritize non-IDOR classes:

| class | target new verified tasks |
|---|---:|
| `missing_auth` | 6 |
| `mass_assignment` | 6 |
| `privilege_escalation` | 5 |
| `path_traversal` | 5 |
| `sql_injection` | 4 |
| `ssrf` | 2 |
| `token_forgery` | 2 |

The factory rejects many candidates. Generate more candidates than you need, then stop once the aggregate dataset is balanced enough for launch.

## Evaluate Models

Run a small sanity check:

```bash
modal run eval_models.py --sanity-check
```

Run the configured model set:

```bash
modal run eval_models.py
```

The V0 public leaderboard uses six models:

- Claude Opus 4.8
- Claude Sonnet 4.6
- Nemotron 3 Ultra
- Kimi K2.7 Code
- GLM 5.2
- GPT-OSS 120B

To score only tasks missing from the saved leaderboard:

```bash
modal run eval_models.py --missing-only
```

Gemini 2.5 Pro is excluded from the public dashboard and future default evals because the saved run mostly measured output-format parsing rather than security patching ability.

## Repository Hygiene

Recommended public repo contents:

- source code for the factory, aggregation, eval harness, and dashboard;
- `dataset.jsonl` public inspect set;
- `eval_results.jsonl` and `eval_summary.json` for published leaderboard runs;
- a small number of representative `results/.../verified/*.json` examples if useful;
- no secrets, `.env`, virtualenvs, caches, or large internal scratch runs.

Avoid publishing every rejected/test run unless you are intentionally releasing an audit archive. Rejected runs are useful internally, but they make the repo noisy for readers.

## Hosting

For V0, Streamlit Community Cloud is the fastest path if the repo can be public and the app only reads local data files. Other good options are Hugging Face Spaces, Modal, Render, or Fly.io.

Do not add public arbitrary exploit execution until you have authentication, queueing, spend limits, sandbox controls, request logs, and moderation.

## License

MIT — see [LICENSE](LICENSE).
