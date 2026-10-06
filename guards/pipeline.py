"""Where the guardrail layers meet the pipeline.

One place that answers "what is safe to extract from, and what is safe to send to the model",
so no caller has to remember the order of the layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from extract.chunking import Chunk

from .injection import SEVERITY_HIGH, InjectionScan, scan_for_injection
from .sanitize_html import SanitizationReport
from .sanitize_pdf import PdfSanitizationReport


@dataclass
class SecurityReport:
    """Everything the guardrails found for one report, for the UI and for storage."""

    quarantine_counts: dict[str, int] = field(default_factory=dict)
    quarantined_items: list[dict[str, Any]] = field(default_factory=list)
    document_risks: dict[str, int] = field(default_factory=dict)
    injection_findings: list[dict[str, Any]] = field(default_factory=list)
    excluded_chunks: list[dict[str, Any]] = field(default_factory=list)
    suspicious_chunks: list[int] = field(default_factory=list)
    render_mode_available: bool = False

    @property
    def quarantined_count(self) -> int:
        return sum(self.quarantine_counts.values())

    @property
    def high_findings(self) -> list[dict[str, Any]]:
        return [f for f in self.injection_findings if f["severity"] == SEVERITY_HIGH]

    @property
    def had_hidden_content(self) -> bool:
        structural_only = {"structural_element"}
        return any(
            count for reason, count in self.quarantine_counts.items()
            if reason not in structural_only
        )

    @property
    def status(self) -> str:
        """One of clean / warnings / suspicious, for the Reports page badge."""
        if self.high_findings or self.suspicious_chunks:
            return "suspicious"
        if self.quarantined_count or self.injection_findings or self.document_risks:
            return "warnings"
        return "clean"

    def to_dict(self) -> dict[str, Any]:
        return {
            "quarantine_counts": self.quarantine_counts,
            "quarantined_items": self.quarantined_items,
            "document_risks": self.document_risks,
            "injection_findings": self.injection_findings,
            "excluded_chunks": self.excluded_chunks,
            "suspicious_chunks": self.suspicious_chunks,
            "status": self.status,
        }


def from_html_report(report: SanitizationReport) -> SecurityReport:
    return SecurityReport(
        quarantine_counts=dict(report.counts),
        quarantined_items=[
            {"reason": item.reason, "where": item.tag, "preview": item.preview}
            for item in report.items
        ],
    )


def from_pdf_report(report: PdfSanitizationReport) -> SecurityReport:
    return SecurityReport(
        quarantine_counts=dict(report.counts),
        quarantined_items=[
            {
                "reason": span.reason,
                "where": f"page {span.page}",
                "preview": span.text,
                "detail": span.detail,
            }
            for span in report.spans
        ],
        document_risks=dict(report.document_risks),
        render_mode_available=report.render_mode_available,
    )


def screen_chunks(
    chunks: list[Chunk], security: SecurityReport, block_on: str = SEVERITY_HIGH
) -> list[Chunk]:
    """Scan each chunk and return only those allowed to reach the model.

    HIGH-severity findings exclude the chunk: the cheapest way to defeat an injection is not to
    send it. MEDIUM findings are recorded and the chunk is sent, because the patterns are weak
    enough that blocking on them would discard legitimate advisory prose.
    """
    allowed: list[Chunk] = []

    for chunk in chunks:
        scan = scan_for_injection(chunk.text)
        for finding in scan.findings:
            security.injection_findings.append(
                {
                    "severity": finding.severity,
                    "pattern": finding.pattern_name,
                    "snippet": finding.snippet,
                    "chunk": chunk.index,
                    "pages": chunk.page_label,
                }
            )

        should_exclude = (
            scan.has_high
            if block_on == SEVERITY_HIGH
            else (scan.has_any if block_on == "medium" else False)
        )

        if should_exclude:
            security.excluded_chunks.append(
                {
                    "chunk": chunk.index,
                    "pages": chunk.page_label,
                    "reasons": sorted({f.pattern_name for f in scan.high}),
                }
            )
            continue

        allowed.append(chunk)

    return allowed


def scan_tool_result(text: str, nonce: str) -> tuple[str, InjectionScan]:
    """Wrap and screen an agent tool result (Phase 6).

    Tool output is untrusted for the same reason report text is: a `search_report` result is
    report text, and a `query_graph` result contains text another report put there. A HIGH
    finding replaces the content entirely rather than passing it through.
    """
    scan = scan_for_injection(text)
    if scan.has_high:
        body = "[result withheld: suspicious content detected]"
    else:
        body = text
    return f"<tool-result-{nonce}>\n{body}\n</tool-result-{nonce}>", scan
