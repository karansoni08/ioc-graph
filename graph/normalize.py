"""Turning entity names into stable node keys.

Deduplication across reports lives or dies here. One advisory writes "APT 21", another
"APT-21", a third "apt21"; all three must become one node, or the graph is a pile of
near-duplicates and the whole point is lost.

The rules are deliberately conservative. Normalization only collapses differences that are
*mechanical* — spacing, punctuation, case, a technique id written two ways. It never merges two
names because they look similar: that is what `find_possible_duplicates` is for, and a human
decides. Automatic fuzzy merging would eventually merge two genuinely different actors, and in
threat intelligence that is a worse failure than a duplicate node.
"""

from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

ALIASES_PATH = Path(__file__).with_name("aliases.json")

# Threat-actor naming conventions: a prefix of letters followed by digits, written with any
# amount of space or punctuation between. APT 21 / APT-21 / apt21 -> apt21.
_ACTOR_PREFIXES = ("apt", "unc", "ta", "fin", "g", "utg", "temp", "dev")
_ACTOR_PATTERN = re.compile(
    r"^(" + "|".join(_ACTOR_PREFIXES) + r")[\s\-_.]*0*(\d+)$",
    re.IGNORECASE,
)

_CVE_ID = re.compile(r"CVE[\s\-_]?(\d{4})[\s\-_]?(\d{4,7})", re.IGNORECASE)
_TECHNIQUE_ID = re.compile(r"\bT(\d{4})(?:[.\s]?(\d{3}))?\b", re.IGNORECASE)


def _base_normalize(name: str) -> str:
    """Trim, collapse whitespace, NFKC, casefold."""
    text = unicodedata.normalize("NFKC", name)
    text = re.sub(r"\s+", " ", text).strip()
    return text.casefold()


@lru_cache(maxsize=1)
def load_alias_map() -> dict[str, str]:
    """Manual alias map: normalized alias key -> canonical key.

    Only a human edits `graph/aliases.json`. It exists so that a real merge decision
    ("Volt Typhoon" and "BRONZE SILHOUETTE" are the same group) can be recorded once and
    applied consistently, without the code ever guessing.
    """
    if not ALIASES_PATH.exists():
        return {}
    try:
        raw = json.loads(ALIASES_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return {str(k).casefold(): str(v).casefold() for k, v in raw.items() if k and v}


def normalize_key(entity_type: str, name: str, ioc_type: str | None = None) -> str:
    """Return the stable key for an entity of this type.

    The key is what makes two mentions the same node. It is not shown to the user; the
    first-seen spelling is kept as the display name.
    """
    text = _base_normalize(name)
    if not text:
        return ""

    if entity_type == "indicator":
        # Phase 2 already normalized the value; the IOC type disambiguates, so that a domain
        # and a URL with the same text are not the same node.
        return f"{ioc_type or 'unknown'}--{text}"

    if entity_type == "vulnerability":
        match = _CVE_ID.search(name)
        if match:
            return f"cve-{match.group(1)}-{match.group(2)}"

    if entity_type == "attack-pattern":
        # A technique id is the canonical identity when present: "Scheduled Task/Job: Cron"
        # and "T1053.003" are the same technique.
        match = _TECHNIQUE_ID.search(name)
        if match:
            technique = f"t{match.group(1)}"
            if match.group(2):
                technique += f".{match.group(2)}"
            return technique

    if entity_type == "threat-actor":
        match = _ACTOR_PATTERN.match(text)
        if match:
            return f"{match.group(1).lower()}{int(match.group(2))}"

    # Strip punctuation that carries no meaning, so "Akira." and "Akira" agree.
    text = re.sub(r"[\s\-_.]+", " ", text).strip()

    alias_map = load_alias_map()
    return alias_map.get(text, text)


def node_id(entity_type: str, key: str) -> str:
    """STIX-like node id: `threat-actor--apt21`, `indicator--ipv4--203.0.113.5`."""
    return f"{entity_type}--{key}"


def report_node_id(sha256: str) -> str:
    return f"report--{sha256[:12]}"


def find_possible_duplicates(
    graph, threshold: int = 90, limit: int = 100
) -> list[tuple[str, str, float]]:
    """Same-type node pairs whose names are similar enough to be worth a human look.

    Reported, never merged. `rapidfuzz` gives the similarity; the decision is recorded by
    editing `graph/aliases.json`.
    """
    from rapidfuzz import fuzz

    by_type: dict[str, list[tuple[str, str]]] = {}
    for identifier, attributes in graph.nodes(data=True):
        node_type = attributes.get("type")
        # Indicators are excluded deliberately. Their values are already canonically
        # normalized in Phase 2, so similar text means a genuinely different indicator:
        # http://host/x and https://host/x score 99 but are two different URLs, and a domain
        # and a URL sharing a hostname are different IOCs. Including them buried the real
        # findings under hundreds of false pairs. Fuzzy matching is only meaningful for names
        # humans write inconsistently — actors, malware, tools, campaigns.
        if node_type in (None, "report", "indicator"):
            continue
        by_type.setdefault(node_type, []).append((identifier, attributes.get("name", "")))

    pairs: list[tuple[str, str, float]] = []
    for nodes in by_type.values():
        for index, (left_id, left_name) in enumerate(nodes):
            for right_id, right_name in nodes[index + 1 :]:
                if not left_name or not right_name:
                    continue
                left_text, right_text = left_name.casefold(), right_name.casefold()
                # Two scorers, because the duplicate patterns differ. token_set catches one
                # name containing the other ("Akira" / "Akira Ransomware"), which token_sort
                # scores far too low because of the length difference. token_sort catches
                # reordered words ("APT21 Group" / "Group APT21"). The higher of the two wins,
                # since this list is only a prompt for human review and a miss is worse than
                # an extra row.
                score = max(
                    fuzz.token_set_ratio(left_text, right_text),
                    fuzz.token_sort_ratio(left_text, right_text),
                )
                if score >= threshold:
                    pairs.append((left_id, right_id, float(score)))

    pairs.sort(key=lambda item: item[2], reverse=True)
    return pairs[:limit]
