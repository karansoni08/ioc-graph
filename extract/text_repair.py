"""Repair PDF layout artifacts that hide IOCs from the extractors.

Advisories print hashes in narrow table columns, so a 64-character SHA-256 is routinely wrapped
across two or three lines:

    c0f706ff43936c1bb19db4f39b11129c3fc8ddafbd1
    59852475ef99a246b2f79

No regex can find that, and on the Akira advisory it hid 29 of 42 published SHA-256 hashes.
This module rejoins such fragments before extraction runs.

The opposite error is worse: gluing values together invents a hash that was never in the
report. Two stacked SHA-256 hashes are 128 hex characters, which looks exactly like a SHA-512,
and an early version of this module did produce one. So the rules are deliberately strict:

1. If any fragment is already a complete hash length, the fragments are separate values, not
   one wrapped value, and the run is left completely alone.
2. Otherwise the run is segmented greedily at fragment boundaries, cutting wherever the
   accumulated length reaches a valid hash length. The repair is only applied when the
   segmentation consumes every fragment exactly, leaving no remainder.

Rule 2 is what distinguishes a column of wrapped SHA-256 hashes (fragments 40+24, 41+23, …,
each pair summing to 64) from one wrapped SHA-512 (fragments 43+43+42, reaching a valid length
only at 128). A run that cannot be segmented cleanly is left as it is rather than guessed at.
"""

from __future__ import annotations

import re

# Valid hash lengths, in hex characters: MD5, SHA-1, SHA-256, SHA-512.
HASH_LENGTHS = frozenset({32, 40, 64, 128})

# A maximal run of two or more whitespace-separated hex fragments. Fragments of one character
# are excluded; they are far more often table artifacts or list markers than hash pieces.
_HEX_RUN = re.compile(r"(?:\b[0-9a-fA-F]{2,}\b[ \t\r\n]+)+\b[0-9a-fA-F]{2,}\b")

_WHITESPACE = re.compile(r"\s+")


def _fragments(text: str) -> list[str]:
    return [fragment for fragment in _WHITESPACE.split(text) if fragment]


def segment_hex_fragments(fragments: list[str]) -> list[str] | None:
    """Split hex fragments into whole hashes, or None if they do not divide cleanly.

    Every fragment must be consumed: a partition is only valid if each group sums to a valid
    hash length with nothing left over. That requirement is what resolves the ambiguous cases,
    because a wrong reading almost always leaves an orphan fragment.

    A greedy left-to-right scan is not enough. The run `[40, 24]` is one wrapped SHA-256, but
    greedy cuts at 40 because that is a valid SHA-1 length and then strands the 24-character
    tail — which is how an earlier version invented SHA-1 hashes out of the first lines of
    wrapped SHA-256 hashes. So all partitions are considered and the one with the MOST pieces
    wins, since preferring more pieces means joining as little as possible: `[64, 64]` is read
    as two stacked SHA-256 hashes rather than one invented SHA-512, while `[43, 43, 42]` has no
    other reading than a single wrapped SHA-512.

    Returns None when no complete partition exists, or when the only partition is the fragments
    exactly as they already are (nothing to repair).
    """
    if len(fragments) < 2:
        return None

    lengths = [len(fragment) for fragment in fragments]
    if sum(lengths) > max(HASH_LENGTHS) * 64:  # pragma: no cover - runaway input guard
        return None

    count = len(fragments)
    # best[i] = partition of fragments[i:] with the most pieces, or None if it cannot be split.
    best: list[list[int]] | None
    table: list[list[int] | None] = [None] * (count + 1)
    table[count] = []

    for start in range(count - 1, -1, -1):
        running = 0
        candidate: list[int] | None = None
        for end in range(start, count):
            running += lengths[end]
            if running > max(HASH_LENGTHS):
                break
            if running in HASH_LENGTHS:
                tail = table[end + 1]
                if tail is None:
                    continue
                option = [end + 1] + tail
                if candidate is None or len(option) > len(candidate):
                    candidate = option
        table[start] = candidate

    best = table[0]
    if best is None:
        return None

    # Rebuild the hashes from the chosen cut points.
    hashes: list[str] = []
    position = 0
    for cut in best:
        hashes.append("".join(fragments[position:cut]))
        position = cut

    if hashes == fragments:
        # Already whole hashes on separate lines; leave the text alone.
        return None
    return hashes


def rejoin_wrapped_hashes(text: str) -> str:
    """Rejoin hex fragments in page text that together form whole hashes.

    Rewrites only runs that segment cleanly; anything ambiguous is left untouched.
    """

    def replace(match: re.Match[str]) -> str:
        run = match.group(0)
        hashes = segment_hex_fragments(_fragments(run))
        if hashes is None:
            return run
        # Space-separated so each hash keeps its word boundaries for the extractors.
        return " ".join(hashes)

    return _HEX_RUN.sub(replace, text)


def compact_hex_cell(cell: str) -> str:
    """Rejoin a wrapped hash inside a single table cell.

    A cell normally holds one value, which makes this safer than the page-text version, but the
    same guard applies: a cell holding two complete hashes on separate lines is left alone so
    they are never merged into one.
    """
    stripped = cell.strip()
    if not stripped:
        return cell
    fragments = _fragments(stripped)
    if not all(re.fullmatch(r"[0-9a-fA-F]+", fragment) for fragment in fragments):
        return cell
    hashes = segment_hex_fragments(fragments)
    if hashes is None:
        return cell
    return " ".join(hashes)
