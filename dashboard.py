"""
VulnBench-AI Dashboard — visualize dataset + eval results.

Run:
  pip install streamlit pandas
  streamlit run dashboard.py
"""

import json
import glob
import os
from collections import Counter, defaultdict
from pathlib import Path

import streamlit as st
import pandas as pd

st.set_page_config(page_title="VulnBench-AI", layout="wide")


# ─── Data loaders ──────────────────────────────────────────
@st.cache_data
def load_dataset():
    if not os.path.exists("dataset.jsonl"):
        return []
    with open("dataset.jsonl") as f:
        return [json.loads(line) for line in f]


@st.cache_data
def load_eval_results():
    if not os.path.exists("eval_results.jsonl"):
        return []
    with open("eval_results.jsonl") as f:
        return [json.loads(line) for line in f]


def vuln_color(cls):
    return {
        "idor": "#ff6b6b",
        "mass_assignment": "#feca57",
        "missing_auth": "#48dbfb",
        "privilege_escalation": "#ff9ff3",
        "path_traversal": "#1dd1a1",
        "sql_injection": "#a55eea",
        "other": "#c8d6e5",
    }.get(cls, "#c8d6e5")


def status_emoji(stage):
    return {
        "passed": "✅",
        "exploit_still_works": "🔴",
        "spec_broken": "🟠",
        "parse_failed": "📝",
        "no_response_after_retries": "⏱️",
    }.get(stage, "❓")


# ─── Header + sidebar nav ──────────────────────────────────
st.title("VulnBench-AI")
st.caption("Execution-verified vulnerability dataset for AI-generated Python web APIs")

dataset = load_dataset()
results = load_eval_results()

if not dataset:
    st.error("dataset.jsonl not found. Run `python aggregate.py` first.")
    st.stop()

page = st.sidebar.radio(
    "View",
    ["Overview", "Browse Dataset", "Browse Eval Results", "Debug Failure", "Compare Models"],
)


# ═════════════════════════════════════════════════════════
# PAGE: OVERVIEW
# ═════════════════════════════════════════════════════════
if page == "Overview":
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total triplets", len(dataset))
    col2.metric("Distinct seed prompts", len({e["seed_prompt"][:60] for e in dataset}))
    col3.metric("Vuln classes", len({e["vuln_class"] for e in dataset}))
    col4.metric("Models evaluated", len({r["model"] for r in results}) if results else 0)

    st.subheader("Vulnerability class distribution")
    vuln_dist = Counter(e["vuln_class"] for e in dataset)
    df = pd.DataFrame(vuln_dist.most_common(), columns=["Class", "Count"])
    df["%"] = (100 * df["Count"] / df["Count"].sum()).round(1)
    st.dataframe(df, hide_index=True, use_container_width=True)

    if results:
        st.subheader("Leaderboard")
        by_model = defaultdict(lambda: {"passed": 0, "total": 0, "stages": Counter()})
        for r in results:
            by_model[r["model"]]["total"] += 1
            by_model[r["model"]]["stages"][r["stage"]] += 1
            if r["passed"]:
                by_model[r["model"]]["passed"] += 1

        rows = []
        for m, s in sorted(by_model.items(), key=lambda x: -x[1]["passed"] / max(x[1]["total"], 1)):
            pct = 100 * s["passed"] / s["total"] if s["total"] else 0
            rows.append({
                "Model": m,
                "Passed": s["passed"],
                "Total": s["total"],
                "Pass %": round(pct, 1),
                "parse_failed": s["stages"].get("parse_failed", 0),
                "exploit_still_works": s["stages"].get("exploit_still_works", 0),
                "spec_broken": s["stages"].get("spec_broken", 0),
            })
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

        st.caption("📝 = parse_failed (model didn't follow output format) — "
                   "🔴 = exploit_still_works (patch didn't close the hole) — "
                   "🟠 = spec_broken (patch broke normal behavior)")


# ═════════════════════════════════════════════════════════
# PAGE: BROWSE DATASET
# ═════════════════════════════════════════════════════════
elif page == "Browse Dataset":
    st.sidebar.subheader("Filter")
    classes = sorted({e["vuln_class"] for e in dataset})
    selected_classes = st.sidebar.multiselect("Vuln class", classes, default=classes)
    search = st.sidebar.text_input("Search seed prompt", "")

    filtered = [e for e in dataset
                if e["vuln_class"] in selected_classes
                and search.lower() in e["seed_prompt"].lower()]
    st.caption(f"{len(filtered)} / {len(dataset)} entries match filter")

    selected_id = st.selectbox(
        "Entry",
        options=[e["id"] for e in filtered],
        format_func=lambda eid: f"{eid[:8]} · {next(e for e in filtered if e['id']==eid)['vuln_class']:20s} · {next(e for e in filtered if e['id']==eid)['seed_prompt']}",
    )
    if not selected_id:
        st.stop()

    entry = next(e for e in dataset if e["id"] == selected_id)

    st.markdown(f"### `{entry['id']}` — {entry['vuln_class']}")
    st.write(f"**Seed prompt:** {entry['seed_prompt']}")

    tab1, tab2, tab3, tab4 = st.tabs(["🐛 Vulnerable App", "✅ Spec Test", "💥 Exploit", "🔧 Known Patch"])

    with tab1:
        for path, content in entry["app_files"].items():
            st.markdown(f"**`{path}`**")
            st.code(content, language="python" if path.endswith(".py") else "text")

    with tab2:
        st.code(entry["spec_test"], language="python")
        st.caption("Run against the vulnerable app → expects SPEC_PASS (proves app works normally)")

    with tab3:
        st.code(entry["exploit"], language="python")
        if entry.get("exploit_output"):
            st.markdown("**Exploit's actual stdout (proof of compromise):**")
            st.code(entry["exploit_output"], language="text")

    with tab4:
        for path, content in entry["patched_files"].items():
            st.markdown(f"**`{path}`**")
            st.code(content, language="python" if path.endswith(".py") else "text")


# ═════════════════════════════════════════════════════════
# PAGE: BROWSE EVAL RESULTS
# ═════════════════════════════════════════════════════════
elif page == "Browse Eval Results":
    if not results:
        st.warning("No eval_results.jsonl found. Run the eval first.")
        st.stop()

    st.sidebar.subheader("Filter")
    all_models = sorted({r["model"] for r in results})
    all_stages = sorted({r["stage"] for r in results})

    selected_models = st.sidebar.multiselect("Model", all_models, default=all_models)
    selected_stages = st.sidebar.multiselect("Stage", all_stages, default=all_stages)
    selected_classes = st.sidebar.multiselect("Vuln class", classes := sorted({r["vuln_class"] for r in results}), default=classes)

    filtered = [r for r in results
                if r["model"] in selected_models
                and r["stage"] in selected_stages
                and r["vuln_class"] in selected_classes]

    rows = [{
        "": status_emoji(r["stage"]),
        "Model": r["model"].split("/")[-1],
        "Entry": r["entry_id"][:10],
        "Class": r["vuln_class"],
        "Stage": r["stage"],
    } for r in filtered]
    st.caption(f"{len(filtered)} / {len(results)} results match filter")
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True, height=600)


# ═════════════════════════════════════════════════════════
# PAGE: DEBUG FAILURE
# ═════════════════════════════════════════════════════════
elif page == "Debug Failure":
    if not results:
        st.warning("No eval_results.jsonl found.")
        st.stop()

    st.markdown("### Pick a (model, entry) pair to inspect what went wrong")

    col1, col2 = st.columns(2)
    all_models = sorted({r["model"] for r in results})
    sel_model = col1.selectbox("Model", all_models)

    failure_results = [r for r in results if r["model"] == sel_model and not r["passed"]]
    if not failure_results:
        st.success(f"No failures for {sel_model} — try Browse Eval Results instead")
        st.stop()

    failure_stages = Counter(r["stage"] for r in failure_results)
    sel_stage = col2.selectbox(
        "Failure stage",
        options=list(failure_stages.keys()),
        format_func=lambda s: f"{s} ({failure_stages[s]} cases)",
    )

    matching = [r for r in failure_results if r["stage"] == sel_stage]
    sel_id = st.selectbox(
        f"Pick one of {len(matching)} {sel_stage} cases",
        options=[r["entry_id"] for r in matching],
        format_func=lambda eid: f"{eid[:10]} — {next((e['seed_prompt'] for e in dataset if e['id']==eid), '?')}",
    )

    entry = next((e for e in dataset if e["id"] == sel_id), None)
    eval_result = next(r for r in matching if r["entry_id"] == sel_id)

    if entry is None:
        st.warning("Entry not found in dataset")
        st.stop()

    st.markdown("---")
    st.markdown(f"### Inspecting `{sel_id}` — {sel_model} — {sel_stage}")
    st.caption(f"Seed: {entry['seed_prompt']}")

    tab1, tab2, tab3, tab4 = st.tabs(["🐛 Original Vulnerable App", "🤖 Raw Model Response", "🔧 Parsed Patch", "💥 Exploit + Spec"])

    with tab1:
        st.code(entry["app_files"].get("main.py", ""), language="python")

    with tab2:
        raw = eval_result.get("raw_response")
        if raw:
            st.markdown(f"**What `{sel_model}` actually output** ({len(raw)} chars):")
            st.code(raw, language="text")
        else:
            st.info("No raw response saved for this eval result. "
                    "Re-run the eval with the latest eval_models.py to capture raw responses.")

    with tab3:
        patched = eval_result.get("patched_files", {})
        if patched:
            for path, content in patched.items():
                st.markdown(f"**`{path}`**")
                st.code(content, language="python")
        else:
            st.info("No parsed patch — model output couldn't be parsed into <file> blocks.")

    with tab4:
        st.markdown("**Exploit** (the same one the factory recorded for this entry):")
        st.code(entry["exploit"], language="python")
        st.markdown("**Spec test:**")
        st.code(entry["spec_test"], language="python")

    st.markdown("---")
    if sel_stage == "parse_failed":
        st.error("**Diagnosis:** The model's response didn't contain `<file path=\"...\">...</file>` blocks. "
                 "Look at the raw response tab — the model probably output markdown code fences or plain code instead.")
    elif sel_stage == "exploit_still_works":
        st.error("**Diagnosis:** The model wrote a patch, but the original exploit STILL printed PWNED against it. "
                 "The patch didn't actually close the security hole. Compare the model's parsed patch vs the known patch in Browse Dataset.")
    elif sel_stage == "spec_broken":
        st.error("**Diagnosis:** The model's patch DID block the exploit — but it broke normal behavior. "
                 "The spec test (which proves a legitimate user can use the app) no longer passes. Patch was too aggressive.")


# ═════════════════════════════════════════════════════════
# PAGE: COMPARE MODELS
# ═════════════════════════════════════════════════════════
elif page == "Compare Models":
    if not results:
        st.warning("No eval_results.jsonl found.")
        st.stop()

    st.markdown("### Per-class pass rates")
    by_model_class = defaultdict(lambda: defaultdict(lambda: {"pass": 0, "total": 0}))
    for r in results:
        cell = by_model_class[r["model"]][r["vuln_class"]]
        cell["total"] += 1
        if r["passed"]:
            cell["pass"] += 1

    models = sorted(by_model_class.keys())
    classes = sorted({c for m in by_model_class.values() for c in m.keys()})

    rows = []
    for m in models:
        row = {"Model": m.split("/")[-1]}
        for c in classes:
            cell = by_model_class[m].get(c, {"pass": 0, "total": 0})
            if cell["total"]:
                row[c] = f"{cell['pass']}/{cell['total']} ({100*cell['pass']/cell['total']:.0f}%)"
            else:
                row[c] = "—"
        rows.append(row)
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

    st.markdown("### Failure mode breakdown")
    rows = []
    for m in models:
        m_results = [r for r in results if r["model"] == m]
        stages = Counter(r["stage"] for r in m_results)
        total = len(m_results)
        rows.append({
            "Model": m.split("/")[-1],
            "passed": f"{stages.get('passed',0)} ({100*stages.get('passed',0)/total:.0f}%)",
            "parse_failed": f"{stages.get('parse_failed',0)} ({100*stages.get('parse_failed',0)/total:.0f}%)",
            "exploit_still_works": f"{stages.get('exploit_still_works',0)} ({100*stages.get('exploit_still_works',0)/total:.0f}%)",
            "spec_broken": f"{stages.get('spec_broken',0)} ({100*stages.get('spec_broken',0)/total:.0f}%)",
        })
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
