"""Load MITRE ATT&CK techniques and make them searchable.

The agent may only map a behaviour to a technique that exists in this local dataset. That is the
point: a technique id the model invents is dropped, and the technique's *name* comes from here
rather than from the model, so the graph cannot contain a plausible-looking but fictional
technique.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

ATTACK_DIR = Path("data/attack")
BUNDLE_PATH = ATTACK_DIR / "enterprise-attack.json"
VERSION_PATH = ATTACK_DIR / "VERSION"

DESCRIPTION_CHARS = 400

TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# ATT&CK descriptions are markdown with citation markers like "(Citation: Foo 2020)" and
# relative links. Stripped so a snippet shown to the model is clean prose.
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MARKDOWN_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_CODE_TICKS = re.compile(r"`+")


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique or sub-technique."""

    id: str
    name: str
    tactics: tuple[str, ...]
    description: str

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.id

    def summary(self) -> str:
        tactics = ", ".join(self.tactics) if self.tactics else "unknown tactic"
        return f"{self.id} — {self.name} (tactics: {tactics})\n{self.description}"


def _clean_description(text: str) -> str:
    text = _CITATION.sub("", text)
    text = _MARKDOWN_LINK.sub(r"\1", text)
    text = _CODE_TICKS.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:DESCRIPTION_CHARS]


def ensure_available() -> bool:
    """Download the ATT&CK bundle if it is missing. Returns True if it is usable afterwards.

    Called on first start in the deployed app, where the container disk is wiped on every
    restart, so the ~38 MB bundle cannot simply be left on disk between deploys. Caching this
    with `st.cache_resource` at the call site means it runs once per container, not per rerun.
    """
    if BUNDLE_PATH.exists():
        return True
    try:
        from scripts.fetch_attack import fetch

        return fetch(force=False) == 0
    except Exception:
        # Agent mode degrades to unavailable rather than taking the app down with it.
        return False


def attack_version() -> str:
    if VERSION_PATH.exists():
        return VERSION_PATH.read_text(encoding="utf-8").strip()
    return "unknown"


def is_available() -> bool:
    return BUNDLE_PATH.exists()


@lru_cache(maxsize=1)
def load_techniques() -> tuple[Technique, ...]:
    """Parse the bundle into techniques, skipping revoked and deprecated ones.

    Cached because the bundle is ~38 MB of JSON and parsing it is not free.
    """
    if not BUNDLE_PATH.exists():
        return ()

    bundle = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))

    techniques: list[Technique] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        # A revoked or deprecated technique would be a wrong mapping, not a useful one.
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None
        for reference in obj.get("external_references", []):
            if reference.get("source_name") == "mitre-attack":
                technique_id = reference.get("external_id")
                break
        if not technique_id:
            continue

        tactics = tuple(
            phase.get("phase_name", "")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        )

        techniques.append(
            Technique(
                id=technique_id,
                name=obj.get("name", ""),
                tactics=tactics,
                description=_clean_description(obj.get("description", "")),
            )
        )

    techniques.sort(key=lambda technique: technique.id)
    return tuple(techniques)


@lru_cache(maxsize=1)
def technique_index() -> dict[str, Technique]:
    """Exact-id lookup, uppercased keys."""
    return {technique.id.upper(): technique for technique in load_techniques()}


def get_technique(technique_id: str) -> Technique | None:
    return technique_index().get(technique_id.strip().upper())


def technique_exists(technique_id: str) -> bool:
    return get_technique(technique_id) is not None


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


@lru_cache(maxsize=1)
def _bm25():
    """BM25 index over name plus description.

    BM25 rather than embeddings because it needs no model, no API call and no vector store,
    and keyword overlap is a good match for the task: advisories describe behaviour in close to
    ATT&CK's own vocabulary.
    """
    from rank_bm25 import BM25Okapi

    techniques = load_techniques()
    if not techniques:
        return None, ()
    corpus = [
        _tokenize(f"{technique.name} {' '.join(technique.tactics)} {technique.description}")
        for technique in techniques
    ]
    return BM25Okapi(corpus), techniques


def search_techniques(text: str, max_results: int = 3) -> list[Technique]:
    """Find techniques matching free text, or return the exact technique if an id is present.

    An explicit id in the query wins: when an advisory says "T1053.005", that is not a search.
    """
    text = (text or "").strip()
    if not text:
        return []

    match = TECHNIQUE_ID.search(text)
    if match:
        technique = get_technique(match.group(0))
        if technique is not None:
            return [technique]

    index, techniques = _bm25()
    if index is None:
        return []

    tokens = _tokenize(text)
    if not tokens:
        return []

    scores = index.get_scores(tokens)
    ranked = sorted(zip(scores, techniques), key=lambda pair: pair[0], reverse=True)
    return [technique for score, technique in ranked[:max_results] if score > 0]
