"""Guardrail layer 1a: strip hidden content from HTML before anything reads it.

Hidden text is the classic prompt-injection carrier in a web-sourced report. A paragraph styled
`display:none` is invisible to the human who decided the report was safe to upload, but it is
plain text to the extractor and to the model. So anything hidden is *quarantined*: removed from
the text that regex extraction and the LLM ever see, kept separately so a human can inspect it,
and counted so the UI can say what was removed.

Quarantined text is excluded from regex extraction too, not just the LLM. Hidden text can plant
a fake IOC just as easily as a fake instruction, and an attacker-chosen IP appearing in the graph
is its own problem.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment

# Elements whose content is never report prose, or which can execute or fetch.
STRUCTURAL_TAGS = (
    "script",
    "style",
    "noscript",
    "template",
    "iframe",
    "object",
    "embed",
    "svg",
    "meta",
    "link",
)

# Class names conventionally used to hide text from sighted users.
HIDING_CLASSES = frozenset(
    {
        "sr-only",
        "sr_only",
        "visually-hidden",
        "visuallyhidden",
        "screen-reader-only",
        "screen-reader-text",
        "hidden",
        "is-hidden",
        "hide",
        "offscreen",
        "off-screen",
        "clip",
        "a11y-hidden",
    }
)

# Inline styles that hide an element. Whitespace is tolerated because CSS allows it.
_HIDING_STYLES = (
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"font-size\s*:\s*0(?:\.0*)?(?:px|pt|em|rem|%)?\b", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.IGNORECASE),
    re.compile(r"(?:left|top|right|bottom)\s*:\s*-\s*\d{3,}", re.IGNORECASE),
    re.compile(r"text-indent\s*:\s*-\s*\d{3,}", re.IGNORECASE),
    re.compile(r"clip\s*:\s*rect\(\s*0", re.IGNORECASE),
    re.compile(r"max-height\s*:\s*0\b", re.IGNORECASE),
    re.compile(r"width\s*:\s*0(?:px)?\s*;?.*height\s*:\s*0", re.IGNORECASE | re.DOTALL),
)

_COLOR = re.compile(r"(?<!-)\bcolor\s*:\s*([^;]+)", re.IGNORECASE)
_BACKGROUND = re.compile(r"background(?:-color)?\s*:\s*([^;]+)", re.IGNORECASE)

QUARANTINE_PREVIEW_CHARS = 500

REASON_STRUCTURAL = "structural_element"
REASON_COMMENT = "html_comment"
REASON_HIDDEN_ATTR = "hidden_attribute"
REASON_ARIA_HIDDEN = "aria_hidden"
REASON_HIDDEN_STYLE = "hidden_by_style"
REASON_COLOR_MATCH = "text_color_matches_background"
REASON_HIDING_CLASS = "hiding_class"


@dataclass
class QuarantinedItem:
    reason: str
    tag: str
    preview: str


@dataclass
class SanitizationReport:
    """What was removed, why, and a preview of each piece."""

    counts: dict[str, int] = field(default_factory=dict)
    items: list[QuarantinedItem] = field(default_factory=list)

    def record(self, reason: str, tag: str, text: str) -> None:
        self.counts[reason] = self.counts.get(reason, 0) + 1
        cleaned = re.sub(r"\s+", " ", text).strip()
        if cleaned:
            self.items.append(
                QuarantinedItem(reason=reason, tag=tag, preview=cleaned[:QUARANTINE_PREVIEW_CHARS])
            )

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def quarantined_text(self) -> str:
        """Everything removed, for the injection scanner and for display."""
        return "\n\n".join(item.preview for item in self.items)

    @property
    def had_hidden_content(self) -> bool:
        """True if something was hidden rather than merely structural.

        A page with a `<script>` tag is ordinary. A page with text hidden behind
        `display:none` is suspicious, and the two deserve different treatment in the UI.
        """
        suspicious = {
            REASON_HIDDEN_ATTR,
            REASON_ARIA_HIDDEN,
            REASON_HIDDEN_STYLE,
            REASON_COLOR_MATCH,
            REASON_HIDING_CLASS,
            REASON_COMMENT,
        }
        return any(self.counts.get(reason) for reason in suspicious)


def _normalize_color(value: str) -> str | None:
    """Reduce a CSS colour to a comparable token.

    Deliberately simple: named colours, 3- and 6-digit hex, and rgb(). Anything else returns
    None and is not compared, because a wrong guess here would delete visible text.
    """
    value = value.strip().lower().rstrip(";").strip()
    named = {
        "white": "#ffffff",
        "#fff": "#ffffff",
        "black": "#000000",
        "#000": "#000000",
        "transparent": None,
    }
    if value in named:
        return named[value]
    if re.fullmatch(r"#[0-9a-f]{6}", value):
        return value
    if re.fullmatch(r"#[0-9a-f]{3}", value):
        return "#" + "".join(channel * 2 for channel in value[1:])
    match = re.fullmatch(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,[^)]+)?\)", value)
    if match:
        return "#{:02x}{:02x}{:02x}".format(*(int(group) for group in match.groups()))
    return None


def _style_hides(style: str) -> bool:
    return any(pattern.search(style) for pattern in _HIDING_STYLES)


def _color_matches_background(style: str) -> bool:
    """True when inline text colour equals inline background colour.

    Only when BOTH are inline on the same element: comparing against a stylesheet or an
    inherited background would need a CSS engine, and guessing risks deleting visible text.
    """
    color_match = _COLOR.search(style)
    background_match = _BACKGROUND.search(style)
    if not color_match or not background_match:
        return False
    color = _normalize_color(color_match.group(1))
    background = _normalize_color(background_match.group(1))
    return color is not None and color == background


def _has_hiding_class(element) -> bool:
    classes = element.get("class") or []
    if isinstance(classes, str):
        classes = classes.split()
    return any(name.strip().lower() in HIDING_CLASSES for name in classes)


def sanitize_html(markup: str) -> tuple[str, SanitizationReport]:
    """Return (visible text, report).

    The returned text is what regex extraction and the LLM may see. Everything removed is in
    the report and goes nowhere near either.
    """
    report = SanitizationReport()
    soup = BeautifulSoup(markup, "lxml")

    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        report.record(REASON_COMMENT, "comment", str(comment))
        comment.extract()

    for tag_name in STRUCTURAL_TAGS:
        for element in soup.find_all(tag_name):
            report.record(REASON_STRUCTURAL, tag_name, element.get_text(" ", strip=True))
            element.decompose()

    # Walk a snapshot: decomposing during iteration would invalidate the generator.
    for element in list(soup.find_all(True)):
        if element.decomposed:
            continue

        name = element.name

        if element.has_attr("hidden"):
            report.record(REASON_HIDDEN_ATTR, name, element.get_text(" ", strip=True))
            element.decompose()
            continue

        if str(element.get("aria-hidden", "")).lower() == "true":
            report.record(REASON_ARIA_HIDDEN, name, element.get_text(" ", strip=True))
            element.decompose()
            continue

        if _has_hiding_class(element):
            report.record(REASON_HIDING_CLASS, name, element.get_text(" ", strip=True))
            element.decompose()
            continue

        style = element.get("style") or ""
        if style:
            if _style_hides(style):
                report.record(REASON_HIDDEN_STYLE, name, element.get_text(" ", strip=True))
                element.decompose()
                continue
            if _color_matches_background(style):
                report.record(REASON_COLOR_MATCH, name, element.get_text(" ", strip=True))
                element.decompose()
                continue

    text = soup.get_text(separator="\n")
    lines = [line.strip() for line in text.split("\n")]
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()

    return text, report
