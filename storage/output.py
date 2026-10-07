"""Saved results: one folder per analysed report.

The graph is the product, but it is a single merged artifact and not something you can hand to
someone. This writes a per-report folder of plain files — CSV and JSON — so a result can be
opened in a spreadsheet, diffed, attached to a ticket, or kept after the graph moves on.

Indicator values are written in their REAL refanged form, because these files exist to be used by
other tools. That is the opposite of the UI rule, where values are always defanged so nothing is
clickable. Each folder carries a README saying so, since a CSV of live indicators can easily be
opened by someone who did not know what they were getting.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import Settings, get_settings
from extract.llm_extract import ReportAnalysis
from extract.models import IOCExtraction
from ingest.models import Document

README = """\
Extracted results for: {filename}
Generated: {generated}
SHA-256 of the source report: {sha256}

WARNING: iocs.csv and analysis.json contain REAL indicator values, not the defanged forms the
app displays. Opening a URL or resolving a domain from these files may contact attacker
infrastructure. They are written this way deliberately so the files can feed other tools.

Files:
  iocs.csv           every indicator, with type, page, flags and original spelling
  entities.csv       threat entities the model proposed and validation kept
  relationships.csv  relationships between those entities
  analysis.json      the complete result, including what validation dropped and why
  summary.txt        a short human-readable overview
"""


@dataclass
class SavedOutput:
    """One saved result folder."""

    name: str
    path: Path
    filename: str
    sha256: str
    generated: str
    ioc_count: int
    entity_count: int
    relationship_count: int

    @property
    def files(self) -> list[Path]:
        return sorted(p for p in self.path.iterdir() if p.is_file())


def output_root(settings: Settings | None = None) -> Path:
    settings = settings or get_settings()
    return Path(settings.data_dir) / "output"


def _safe_name(filename: str, sha256: str) -> str:
    """A folder name that is readable and cannot escape the output directory."""
    stem = Path(filename).stem[:50]
    safe = "".join(c if (c.isalnum() or c in "-_") else "-" for c in stem).strip("-")
    return f"{safe or 'report'}_{sha256[:12]}"


def save_results(
    doc: Document,
    ioc_extraction: IOCExtraction,
    analysis: ReportAnalysis | None = None,
    settings: Settings | None = None,
) -> SavedOutput:
    """Write a result folder and return a handle to it. Overwrites a previous run of the same report."""
    settings = settings or get_settings()
    folder = output_root(settings) / _safe_name(doc.filename, doc.sha256)
    folder.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # --- indicators -------------------------------------------------------
    with (folder / "iocs.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["type", "value", "occurrences", "pages", "in_ioc_section", "flags", "original_forms"]
        )
        for ioc in ioc_extraction.iocs:
            writer.writerow(
                [
                    ioc.type,
                    ioc.value,
                    ioc.occurrences,
                    " ".join(str(p) for p in ioc.pages),
                    ioc.in_ioc_section,
                    " ".join(ioc.flags),
                    " ".join(ioc.original_forms),
                ]
            )

    entities = analysis.entities if analysis else []
    relationships = analysis.relationships if analysis else []

    with (folder / "entities.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["type", "name", "aliases", "description", "evidence_count", "evidence"])
        for entity in entities:
            writer.writerow(
                [
                    entity.type,
                    entity.name,
                    " | ".join(entity.aliases),
                    " ".join(entity.descriptions)[:500],
                    len(entity.evidence),
                    " | ".join(entity.evidence)[:1000],
                ]
            )

    with (folder / "relationships.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source", "relation", "target", "evidence"])
        for rel in relationships:
            writer.writerow(
                [rel.source, rel.relation, rel.target, " | ".join(rel.evidence)[:1000]]
            )

    # --- the complete record ---------------------------------------------
    payload: dict[str, Any] = {
        "report": {
            "filename": doc.filename,
            "sha256": doc.sha256,
            "pages": doc.page_count,
            "characters": doc.char_count,
            "tables": doc.table_count,
        },
        "generated": generated,
        "indicators": [ioc.model_dump() for ioc in ioc_extraction.iocs],
        "ioc_section_pages": ioc_extraction.ioc_section_pages,
        "counts_by_type": ioc_extraction.counts_by_type,
    }
    security = getattr(doc, "security", None)
    if security is not None:
        payload["security"] = security.to_dict()
    if analysis is not None:
        payload["analysis"] = analysis.to_dict()
    (folder / "analysis.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # --- human-readable ----------------------------------------------------
    lines = [
        f"Report:     {doc.filename}",
        f"SHA-256:    {doc.sha256}",
        f"Generated:  {generated}",
        f"Pages:      {doc.page_count}",
        "",
        f"Indicators: {ioc_extraction.total} ({ioc_extraction.flagged_count} flagged as likely "
        "false positives)",
    ]
    for ioc_type, count in sorted(ioc_extraction.counts_by_type.items()):
        lines.append(f"  {ioc_type:10} {count}")
    if analysis is not None:
        lines += [
            "",
            f"Entities:      {len(analysis.entities)}",
            f"Relationships: {len(analysis.relationships)}",
            f"Dropped by validation: {analysis.validation.dropped_count} "
            f"{analysis.validation.counts_by_reason()}",
            f"Model:  {analysis.model}",
            f"Tokens: {analysis.total_tokens}",
            f"Cost:   ${analysis.cost_usd:.4f}",
        ]
    else:
        lines += ["", "No LLM analysis was run for this report (indicators only)."]
    (folder / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    (folder / "README.txt").write_text(
        README.format(filename=doc.filename, generated=generated, sha256=doc.sha256),
        encoding="utf-8",
    )

    return SavedOutput(
        name=folder.name,
        path=folder,
        filename=doc.filename,
        sha256=doc.sha256,
        generated=generated,
        ioc_count=ioc_extraction.total,
        entity_count=len(entities),
        relationship_count=len(relationships),
    )


def list_outputs(settings: Settings | None = None) -> list[SavedOutput]:
    """Every saved result, newest first."""
    root = output_root(settings)
    if not root.exists():
        return []

    outputs: list[SavedOutput] = []
    for folder in root.iterdir():
        if not folder.is_dir():
            continue
        meta = folder / "analysis.json"
        if not meta.exists():
            continue
        try:
            payload = json.loads(meta.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        report = payload.get("report", {})
        analysis = payload.get("analysis") or {}
        outputs.append(
            SavedOutput(
                name=folder.name,
                path=folder,
                filename=report.get("filename", folder.name),
                sha256=report.get("sha256", ""),
                generated=payload.get("generated", ""),
                ioc_count=len(payload.get("indicators", [])),
                entity_count=len(analysis.get("entities", [])),
                relationship_count=len(analysis.get("relationships", [])),
            )
        )

    outputs.sort(key=lambda item: item.generated, reverse=True)
    return outputs


def build_zip(output: SavedOutput) -> bytes:
    """Zip one result folder, for a single download button."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in output.files:
            archive.write(path, arcname=f"{output.name}/{path.name}")
    return buffer.getvalue()


def delete_output(output: SavedOutput) -> None:
    """Remove one saved result folder."""
    for path in output.path.iterdir():
        if path.is_file():
            path.unlink()
    output.path.rmdir()
