"""Output folder: saved results, one folder per analysed report.

Deliberately plain files. The graph is the product of the whole app, but it is a single merged
artifact; these folders are what you hand to someone else, open in a spreadsheet, or attach to a
ticket.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from auth import require_access
from config import get_settings
from storage.output import build_zip, delete_output, list_outputs, output_root

st.set_page_config(page_title="Output — IOC Graph", layout="wide")

settings = get_settings()

# Files small enough to preview inline without making the page unusable.
PREVIEW_LIMIT_BYTES = 200_000


def main() -> None:
    require_access()

    st.title("Output")
    st.caption(f"Saved results live in `{output_root(settings)}`, one folder per report.")

    outputs = list_outputs(settings)
    if not outputs:
        st.info(
            "Nothing saved yet. Ingest a report and use \"Save results to output folder\"."
        )
        st.page_link("pages/1_Ingest.py", label="Ingest a report", icon=":material/upload:")
        return

    st.warning(
        "These files contain REAL indicator values, not the defanged form shown elsewhere in "
        "the app. Opening a URL or resolving a domain from them may contact attacker "
        "infrastructure."
    )

    st.dataframe(
        pd.DataFrame(
            [
                {
                    "report": item.filename,
                    "saved": item.generated[:19].replace("T", " "),
                    "indicators": item.ioc_count,
                    "entities": item.entity_count,
                    "relationships": item.relationship_count,
                    "folder": item.name,
                }
                for item in outputs
            ]
        ),
        use_container_width=True,
        hide_index=True,
    )

    st.divider()
    labels = {f"{item.filename}  ({item.generated[:10]})": item for item in outputs}
    chosen = st.selectbox("Open a saved result", options=list(labels))
    output = labels[chosen]

    columns = st.columns(4)
    columns[0].metric("Indicators", output.ioc_count)
    columns[1].metric("Entities", output.entity_count)
    columns[2].metric("Relationships", output.relationship_count)
    columns[3].download_button(
        "Download all (.zip)",
        data=build_zip(output),
        file_name=f"{output.name}.zip",
        mime="application/zip",
    )

    st.caption(f"Folder: `{output.path}`")

    for path in output.files:
        size = path.stat().st_size
        with st.expander(f"{path.name}  ({size:,} bytes)"):
            st.download_button(
                f"Download {path.name}",
                data=path.read_bytes(),
                file_name=path.name,
                key=f"dl_{output.name}_{path.name}",
            )
            if size > PREVIEW_LIMIT_BYTES:
                st.caption("Too large to preview here; use the download button.")
                continue
            if path.suffix == ".csv":
                try:
                    # Everything stays a string: these are report-derived values and must not be
                    # coerced into dates or numbers.
                    st.dataframe(
                        pd.read_csv(path, dtype=str).fillna(""),
                        use_container_width=True,
                        hide_index=True,
                    )
                except Exception as exc:  # noqa: BLE001
                    st.caption(f"Could not parse as CSV: {exc}")
            else:
                # st.text, never st.markdown: this is report-derived content.
                st.text(path.read_text(encoding="utf-8", errors="replace")[:20000])

    st.divider()
    confirmed = st.checkbox(f"Yes, delete the saved result for '{output.filename}'")
    if st.button("Delete this result", disabled=not confirmed):
        try:
            delete_output(output)
        except OSError as exc:
            st.error(f"Could not delete: {exc}")
            return
        st.success("Deleted.")
        st.rerun()


main()
