"""Agent run traces: every step of every deep analysis.

This is the demo screen for agent mode. The point is that the loop is fully inspectable — which
tool was called, with what arguments, what came back, and where the budget went.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from config import get_settings
from llm.pricing import format_cost
from storage.factory import get_store
from storage.local import LocalGraphStore

st.set_page_config(page_title="Agent runs — IOC Graph", layout="wide")

settings = get_settings()

STATUS_HELP = {
    "submitted": "The agent called submit_findings and its output was validated.",
    "no_submission": (
        "The agent never called submit_findings, so the pipeline result was kept unchanged. "
        "This is a defined outcome, not a failure of the app."
    ),
    "error": "The model call failed; the pipeline result was kept unchanged.",
}


def main() -> None:
    st.title("Agent runs")
    st.caption(
        f"Budgets: {settings.agent_max_tool_calls} tool calls, "
        f"{settings.agent_max_input_tokens:,} input tokens, {settings.agent_max_seconds}s wall "
        "clock. Whichever is reached first ends the run."
    )

    store = get_store(settings)
    if not isinstance(store, LocalGraphStore):
        st.caption("Run traces are stored locally. This view needs the local backend.")
        return

    runs = store.list_runs()
    if not runs:
        st.info("No agent runs yet. Run a deep analysis from the Ingest page.")
        st.page_link("pages/1_Ingest.py", label="Ingest a report", icon=":material/upload:")
        return

    st.dataframe(
        pd.DataFrame(
            [
                {
                    "run": run.get("run_id", ""),
                    "status": run.get("status", ""),
                    "tool calls": run.get("tool_calls", 0),
                    "new items": (run.get("diff", {}) or {}).get("new_entities", []).__len__()
                    + (run.get("diff", {}) or {}).get("new_relationships", []).__len__()
                    + (run.get("diff", {}) or {}).get("new_attack_patterns", []).__len__(),
                    "tokens": run.get("input_tokens", 0) + run.get("output_tokens", 0),
                    "cost": format_cost(run.get("cost_usd", 0.0)),
                    "seconds": round(run.get("duration_ms", 0) / 1000, 1),
                    "ATT&CK": run.get("attack_version", ""),
                }
                for run in runs
            ]
        ),
        use_container_width=True,
        hide_index=True,
    )

    st.divider()
    chosen = st.selectbox("Inspect a run", options=[run["run_id"] for run in runs])
    run = next(item for item in runs if item["run_id"] == chosen)

    status = run.get("status", "")
    note = STATUS_HELP.get(status, "")
    if status == "submitted":
        st.success(f"Status: {status}. {note}")
    elif status == "no_submission":
        st.warning(f"Status: {status}. {note}")
    else:
        st.error(f"Status: {status}. {note}")
    if run.get("stop_note"):
        st.caption(run["stop_note"])

    columns = st.columns(5)
    columns[0].metric("Tool calls", run.get("tool_calls", 0))
    columns[1].metric("Input tokens", f"{run.get('input_tokens', 0):,}")
    columns[2].metric("Output tokens", f"{run.get('output_tokens', 0):,}")
    columns[3].metric("Cost", format_cost(run.get("cost_usd", 0.0)))
    columns[4].metric("Duration", f"{run.get('duration_ms', 0) / 1000:.1f}s")

    st.subheader("Step timeline")
    steps = run.get("steps", [])
    if not steps:
        st.caption("No tool calls were made.")
    for step in steps:
        label = f"{step['index'] + 1}. {step['tool']}"
        if step.get("withheld"):
            label += "  — result withheld"
        elif step.get("error"):
            label += "  — error"
        with st.expander(label, expanded=False):
            st.caption("Arguments (model-authored)")
            st.text(
                "\n".join(f"{key}: {value}" for key, value in (step.get("arguments") or {}).items())
                or "(none)"
            )
            st.caption("Result")
            if step.get("withheld"):
                st.error(
                    "This tool result contained high-severity injection patterns and was "
                    "replaced before the model saw it."
                )
            # st.text: tool results are untrusted report content.
            st.text(step.get("result_preview", "") or "(empty)")

    diff = run.get("diff", {}) or {}
    st.subheader("What the agent added over the pipeline")
    for title, key in (
        ("New entities", "new_entities"),
        ("New relationships", "new_relationships"),
        ("New ATT&CK mappings", "new_attack_patterns"),
        ("Pipeline items the agent did not resubmit", "dropped_vs_pipeline"),
    ):
        items = diff.get(key, [])
        st.caption(f"{title} ({len(items)})")
        if items:
            for item in items:
                st.text(item)

    if run.get("attack_patterns"):
        st.subheader("Validated ATT&CK mappings")
        st.caption(
            "Technique ids were checked against the local ATT&CK dataset and the names come "
            "from it, not from the model."
        )
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "technique": pattern["technique_id"],
                        "name": pattern["name"],
                        "tactics": pattern.get("tactics", ""),
                        "entity": pattern.get("entity", ""),
                    }
                    for pattern in run["attack_patterns"]
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )
        with st.expander("Evidence for each mapping"):
            for pattern in run["attack_patterns"]:
                st.caption(f"{pattern['technique_id']} {pattern['name']}")
                st.text(pattern.get("evidence", ""))

    validation = run.get("validation", {}) or {}
    dropped = validation.get("dropped", [])
    with st.expander(f"Validation — {len(dropped)} item(s) dropped"):
        st.caption(
            "The agent's output went through the same validator as the pipeline, against the "
            "full report text, plus a check that every ATT&CK id exists locally."
        )
        if dropped:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "kind": item.get("kind", ""),
                            "reason": item.get("reason", ""),
                            "value": item.get("value", ""),
                            "detail": item.get("detail", ""),
                        }
                        for item in dropped
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.text("Nothing was dropped.")


main()
