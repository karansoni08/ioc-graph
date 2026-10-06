"""Guardrail layer 1b: find and quarantine hidden text in PDFs.

The PDF equivalent of `display:none`. A span of 1 pt white text is invisible to the analyst who
decided the advisory was safe, and plain text to everything downstream. PyMuPDF's
`page.get_text("dict")` exposes per-span font size, colour and position, which is enough to
catch the common tricks.

Limits of the colour heuristic, stated plainly because they matter: it compares span colour
against *white* rather than against the actual background, because determining the real
background means rendering the page and sampling pixels under every span. So white-on-white is
caught, but white text over a dark image is also flagged (a false positive, which is safe: the
text is quarantined for review, not deleted), and black text on a black rectangle is missed
entirely. Phase 5 accepts that trade; rendering-based detection would be the real fix.

Document-level risks (embedded files, JavaScript, /OpenAction, /Launch, annotations) are
reported and never acted on. Nothing in this project opens, executes or fetches anything found
in a PDF.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import pymupdf

MIN_FONT_SIZE_PT = 4.0

# Each RGB channel at or above this is "near white".
NEAR_WHITE_CHANNEL = 0xF0

PREVIEW_CHARS = 500

REASON_TINY_FONT = "tiny_font"
REASON_NEAR_WHITE = "near_white_text"
REASON_OFF_PAGE = "outside_page_bounds"
REASON_INVISIBLE_RENDER = "invisible_render_mode"

# PDF text render mode 3 means "neither fill nor stroke": invisible, used legitimately by OCR
# layers and illegitimately to hide text.
INVISIBLE_RENDER_MODE = 3

_RISK_PATTERN = re.compile(rb"/(JavaScript|JS|OpenAction|Launch|AA|EmbeddedFile|RichMedia)\b")


@dataclass
class QuarantinedSpan:
    reason: str
    page: int
    text: str
    detail: str = ""


@dataclass
class PdfSanitizationReport:
    counts: dict[str, int] = field(default_factory=dict)
    spans: list[QuarantinedSpan] = field(default_factory=list)
    document_risks: dict[str, int] = field(default_factory=dict)
    render_mode_available: bool = False

    def record(self, reason: str, page: int, text: str, detail: str = "") -> None:
        self.counts[reason] = self.counts.get(reason, 0) + 1
        cleaned = re.sub(r"\s+", " ", text).strip()
        if cleaned:
            self.spans.append(
                QuarantinedSpan(reason=reason, page=page, text=cleaned[:PREVIEW_CHARS], detail=detail)
            )

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def quarantined_text(self) -> str:
        return "\n\n".join(span.text for span in self.spans)

    @property
    def had_hidden_content(self) -> bool:
        return self.total > 0

    @property
    def has_document_risks(self) -> bool:
        return bool(self.document_risks)


def _is_near_white(color_int: int) -> bool:
    """PyMuPDF gives span colour as a packed 24-bit integer."""
    red = (color_int >> 16) & 0xFF
    green = (color_int >> 8) & 0xFF
    blue = color_int & 0xFF
    return red >= NEAR_WHITE_CHANNEL and green >= NEAR_WHITE_CHANNEL and blue >= NEAR_WHITE_CHANNEL


def _scan_document_risks(doc: pymupdf.Document, data: bytes) -> dict[str, int]:
    """Report risky PDF features. Nothing here is executed or opened."""
    risks: dict[str, int] = {}

    try:
        embedded = doc.embfile_count()
        if embedded:
            risks["embedded_files"] = embedded
    except Exception:
        pass

    annotation_count = 0
    for page in doc:
        try:
            for annotation in page.annots():
                info = annotation.info or {}
                if info.get("content") or info.get("title"):
                    annotation_count += 1
        except Exception:
            continue
    if annotation_count:
        risks["annotations_with_text"] = annotation_count

    # Raw scan of the file bytes for action keywords. Cheaper and more robust than walking the
    # xref, and we only need to report their presence.
    found: dict[str, int] = {}
    for match in _RISK_PATTERN.finditer(data):
        key = match.group(1).decode("ascii").lower()
        found[key] = found.get(key, 0) + 1
    for key, count in found.items():
        if key in ("javascript", "js"):
            risks["javascript"] = risks.get("javascript", 0) + count
        elif key == "openaction":
            risks["open_action"] = count
        elif key == "launch":
            risks["launch_action"] = count
        elif key == "aa":
            risks["additional_actions"] = count
        elif key == "embeddedfile":
            risks.setdefault("embedded_files", count)
        elif key == "richmedia":
            risks["rich_media"] = count

    return risks


def sanitize_pdf(data: bytes, max_pages: int = 200) -> tuple[list[str], PdfSanitizationReport]:
    """Return (visible text per page, report), rebuilt from non-quarantined spans only."""
    report = PdfSanitizationReport()
    doc = pymupdf.open(stream=data, filetype="pdf")

    try:
        report.document_risks = _scan_document_risks(doc, data)

        pages: list[str] = []
        for page_number, page in enumerate(doc, start=1):
            if page_number > max_pages:
                break

            page_rect = page.rect
            try:
                layout = page.get_text("dict")
            except Exception:
                # If the structured extraction fails, fall back to plain text rather than
                # losing the page entirely. Hidden-span detection is skipped for it.
                pages.append(page.get_text("text"))
                continue

            kept_lines: list[str] = []
            for block in layout.get("blocks", []):
                if block.get("type") != 0:  # 0 == text block
                    continue
                for line in block.get("lines", []):
                    kept_spans: list[str] = []
                    for span in line.get("spans", []):
                        text = span.get("text", "")
                        if not text.strip():
                            continue

                        size = float(span.get("size", 12.0))
                        if size < MIN_FONT_SIZE_PT:
                            report.record(
                                REASON_TINY_FONT, page_number, text, f"{size:.2f} pt"
                            )
                            continue

                        if _is_near_white(int(span.get("color", 0))):
                            report.record(
                                REASON_NEAR_WHITE,
                                page_number,
                                text,
                                f"color #{int(span.get('color', 0)):06x}",
                            )
                            continue

                        # Some PyMuPDF builds expose the text render mode; use it when present.
                        render_mode = span.get("render_mode")
                        if render_mode is not None:
                            report.render_mode_available = True
                            if int(render_mode) == INVISIBLE_RENDER_MODE:
                                report.record(
                                    REASON_INVISIBLE_RENDER, page_number, text, "render mode 3"
                                )
                                continue

                        bbox = span.get("bbox")
                        if bbox and _is_off_page(bbox, page_rect):
                            report.record(
                                REASON_OFF_PAGE, page_number, text, f"bbox {bbox}"
                            )
                            continue

                        kept_spans.append(text)

                    if kept_spans:
                        kept_lines.append("".join(kept_spans))

            pages.append("\n".join(kept_lines))

        return pages, report
    finally:
        doc.close()


def _is_off_page(bbox, page_rect) -> bool:
    """True if the span lies wholly outside the visible page rectangle.

    Requires the span to be *entirely* outside, with a small tolerance, so text that merely
    straddles the margin is not quarantined.
    """
    x0, y0, x1, y1 = bbox
    tolerance = 2.0
    return (
        x1 < page_rect.x0 - tolerance
        or x0 > page_rect.x1 + tolerance
        or y1 < page_rect.y0 - tolerance
        or y0 > page_rect.y1 + tolerance
    )
