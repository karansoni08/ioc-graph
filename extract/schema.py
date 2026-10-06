"""The schema the LLM must return, and the single source of truth for it.

The Pydantic models here are used for three things at once: generating the JSON schema sent
to the API, validating what comes back, and typing the rest of the pipeline. Nothing else in
the codebase may define these shapes.

Type allowlists follow STIX 2.1 naming, per CLAUDE.md. A type or relation outside these
Literals is rejected by Pydantic before any of our own checks run.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

EntityType = Literal[
    "threat-actor",
    "malware",
    "tool",
    "vulnerability",
    "indicator",
    "attack-pattern",
    "campaign",
    "infrastructure",
]

RelationType = Literal[
    "uses",
    "exploits",
    "indicates",
    "targets",
    "attributed-to",
    "communicates-with",
    "related-to",
]

ENTITY_TYPES: tuple[str, ...] = (
    "threat-actor",
    "malware",
    "tool",
    "vulnerability",
    "indicator",
    "attack-pattern",
    "campaign",
    "infrastructure",
)

RELATION_TYPES: tuple[str, ...] = (
    "uses",
    "exploits",
    "indicates",
    "targets",
    "attributed-to",
    "communicates-with",
    "related-to",
)

# Caps keep one bad chunk from producing an unbounded response, and bound the cost of
# max_tokens. They are enforced by the schema so the model is told about them, and again by
# the validator so a non-compliant response is still truncated safely.
MAX_ENTITIES = 40
MAX_RELATIONSHIPS = 60
MAX_ALIASES = 5
MAX_NAME_CHARS = 100
MAX_DESCRIPTION_CHARS = 300
MIN_EVIDENCE_CHARS = 10
MAX_EVIDENCE_CHARS = 500


class Entity(BaseModel):
    """One threat entity, as proposed by the model and before validation."""

    name: str = Field(min_length=1, max_length=MAX_NAME_CHARS)
    type: EntityType
    aliases: list[str] = Field(
        default_factory=list,
        max_length=MAX_ALIASES,
        description="Other names for this entity used in the report.",
    )
    description: str = Field(
        default="",
        max_length=MAX_DESCRIPTION_CHARS,
        description="Plain text, drawn only from the report.",
    )
    evidence: str = Field(
        min_length=MIN_EVIDENCE_CHARS,
        max_length=MAX_EVIDENCE_CHARS,
        description="An exact quote copied from the report.",
    )


class Relationship(BaseModel):
    """A directed relationship between two entities."""

    source: str = Field(min_length=1, max_length=MAX_NAME_CHARS)
    relation: RelationType
    target: str = Field(min_length=1, max_length=MAX_NAME_CHARS)
    evidence: str = Field(min_length=MIN_EVIDENCE_CHARS, max_length=MAX_EVIDENCE_CHARS)


class ExtractionResult(BaseModel):
    """What one LLM call is expected to return."""

    entities: list[Entity] = Field(default_factory=list, max_length=MAX_ENTITIES)
    relationships: list[Relationship] = Field(
        default_factory=list, max_length=MAX_RELATIONSHIPS
    )


def _inline_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Resolve `$ref`/`$defs` into an inline schema.

    Pydantic emits `$defs` plus `$ref` pointers. Inlining them keeps the schema we send
    self-contained, which avoids depending on how a given API or model build resolves
    references.
    """
    definitions = schema.pop("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                ref = node["$ref"]
                key = ref.rsplit("/", 1)[-1]
                target = definitions.get(key, {})
                merged = {k: v for k, v in node.items() if k != "$ref"}
                return {**resolve(target), **merged}
            return {key: resolve(value) for key, value in node.items()}
        if isinstance(node, list):
            return [resolve(item) for item in node]
        return node

    return resolve(schema)


# Keywords the structured-outputs endpoint rejects on arrays. Verified against the live API on
# 2026-10-06: sending either returns 400 "For 'array' type, property 'X' is not supported".
# `minItems`, and all the string keywords (maxLength, minLength, pattern, format), are accepted.
UNSUPPORTED_ARRAY_KEYWORDS = ("maxItems", "uniqueItems")


def _strip_unsupported(node: Any) -> Any:
    """Remove schema keywords the API rejects, folding any cap into the description instead.

    Dropping `maxItems` does not weaken anything: the caps are enforced independently by
    `extract/validate.py`, which truncates over-long lists with a `limit` reason. Moving the
    number into the description keeps the model informed, which is the only thing the schema
    keyword was buying.
    """
    if isinstance(node, dict):
        node = {key: _strip_unsupported(value) for key, value in node.items()}
        if node.get("type") == "array":
            cap = node.pop("maxItems", None)
            node.pop("uniqueItems", None)
            if cap is not None:
                existing = node.get("description", "")
                note = f"At most {cap} items."
                node["description"] = f"{existing} {note}".strip() if existing else note
        return node
    if isinstance(node, list):
        return [_strip_unsupported(item) for item in node]
    return node


def _make_strict(node: Any) -> Any:
    """Require every property and forbid extras, recursively.

    Structured outputs are strictest, and most reliable, when every object declares all of
    its properties as required and sets `additionalProperties: false`. Defaults stay in the
    schema as documentation for the model; our Pydantic models still supply them when a field
    is genuinely absent.
    """
    if isinstance(node, dict):
        node = {key: _make_strict(value) for key, value in node.items()}
        if node.get("type") == "object" and "properties" in node:
            node["additionalProperties"] = False
            node["required"] = list(node["properties"].keys())
        return node
    if isinstance(node, list):
        return [_make_strict(item) for item in node]
    return node


def extraction_json_schema() -> dict[str, Any]:
    """The JSON schema sent to the API, derived from `ExtractionResult`.

    Generated rather than hand-written so the schema and the validator can never drift.
    """
    schema = ExtractionResult.model_json_schema()
    schema = _inline_refs(schema)
    schema = _strip_unsupported(schema)
    schema = _make_strict(schema)
    schema.pop("title", None)
    return schema


def summary_json_schema() -> dict[str, Any]:
    """Schema for the Phase 4 node-summary call, kept here with the other schemas."""
    return {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "maxLength": 1200,
                "description": "Plain text summary, at most 120 words.",
            }
        },
        "required": ["summary"],
        "additionalProperties": False,
    }
