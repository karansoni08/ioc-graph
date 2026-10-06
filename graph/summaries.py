"""Grounded node summaries, generated on demand and cached.

Summaries cost money, so they are only ever produced when someone clicks the button, and are
cached on the node. The cache key is a hash of the exact evidence the summary was written from:
if a later report adds evidence, the hash changes and the UI can say the summary is outdated
rather than presenting a summary of material it did not see.

The model gets only the node's own quotes and descriptions, inside nonce delimiters, with the
same untrusted-data instructions as extraction. It is told not to use outside knowledge.
"""

from __future__ import annotations

import hashlib
from typing import Any

import networkx as nx

from extract.prompts import build_summary_messages
from extract.schema import summary_json_schema
from extract.validate import strip_unsafe_text
from llm.base import LLMError, LLMProvider
from llm.pricing import estimate_cost

MAX_SUMMARY_WORDS = 120
MAX_EVIDENCE_FOR_SUMMARY = 10


def evidence_hash(evidence: list[str], descriptions: list[str]) -> str:
    """Stable hash of the inputs a summary was generated from."""
    digest = hashlib.sha256()
    for item in [*descriptions, *evidence]:
        digest.update(item.encode("utf-8", errors="replace"))
        digest.update(b"\x00")
    return digest.hexdigest()[:16]


def node_summary_inputs(attributes: dict[str, Any]) -> tuple[list[str], list[str]]:
    """The quotes and descriptions a summary may use."""
    evidence = [
        entry.get("quote", "")
        for entry in attributes.get("evidence", [])[:MAX_EVIDENCE_FOR_SUMMARY]
        if entry.get("quote")
    ]
    descriptions = [
        entry.get("text", "") for entry in attributes.get("descriptions", []) if entry.get("text")
    ]
    return evidence, descriptions


def summary_is_current(attributes: dict[str, Any]) -> bool:
    """True if a cached summary still matches the node's evidence."""
    if not attributes.get("summary"):
        return False
    evidence, descriptions = node_summary_inputs(attributes)
    return attributes.get("summary_evidence_hash") == evidence_hash(evidence, descriptions)


def _truncate_words(text: str, limit: int = MAX_SUMMARY_WORDS) -> str:
    words = text.split()
    if len(words) <= limit:
        return text
    return " ".join(words[:limit]) + "…"


def generate_summary(
    graph: nx.MultiDiGraph,
    node_id: str,
    provider: LLMProvider,
    model: str,
) -> tuple[str, float]:
    """Generate and store a summary for one node. Returns (summary, cost)."""
    if node_id not in graph:
        raise KeyError(node_id)

    attributes = graph.nodes[node_id]
    evidence, descriptions = node_summary_inputs(attributes)

    if not evidence and not descriptions:
        summary = "No evidence has been recorded for this node yet."
        attributes["summary"] = summary
        attributes["summary_evidence_hash"] = evidence_hash(evidence, descriptions)
        return summary, 0.0

    system, user = build_summary_messages(
        attributes.get("name", node_id), attributes.get("type", ""), evidence, descriptions
    )

    response = provider.extract_structured(
        system=system,
        user=user,
        schema=summary_json_schema(),
        model=model,
        max_tokens=600,
    )

    raw = response.data.get("summary", "")
    if not isinstance(raw, str):
        raise LLMError("Summary response did not contain a string.")

    # Same output hygiene as extraction: the summary is derived from untrusted text.
    summary = _truncate_words(strip_unsafe_text(raw))

    attributes["summary"] = summary
    attributes["summary_evidence_hash"] = evidence_hash(evidence, descriptions)

    cost = estimate_cost(model, response.input_tokens, response.output_tokens)
    return summary, cost
