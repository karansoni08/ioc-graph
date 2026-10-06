"""Guardrail layer 1c: heuristic prompt-injection scanner.

Honest framing first: **this is a heuristic and it can be evaded.** A determined attacker who
knows these patterns can rephrase around them. It is one layer among four, and it is not the
one doing the heavy lifting — output validation is, because a successful injection still has to
produce entities whose evidence appears verbatim in the report and whose indicators were already
found by regex. The scanner's job is to catch the obvious attempts cheaply and to make the
attempt visible to a human.

Policy: HIGH excludes the chunk from the LLM entirely and flags the report; MEDIUM sends the
chunk and shows the finding. Both are configurable, because an installation that would rather
see everything can lower the bar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"

SNIPPET_CHARS = 160

# `\s+` everywhere a space could appear, so "ignore   all previous   instructions" and a
# line-broken version both match. Patterns are grouped so a finding names what it matched.
HIGH_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "override_instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override|skip)\s+(all\s+|any\s+|the\s+|your\s+)*"
            r"(previous|prior|above|earlier|preceding|system|original)\s+"
            r"(instruction|instructions|prompt|prompts|rule|rules|direction|directions)",
            re.IGNORECASE,
        ),
    ),
    (
        "role_reassignment",
        re.compile(
            r"\b(you\s+are\s+now|you\s+must\s+now|from\s+now\s+on\s+you|act\s+as|"
            r"pretend\s+to\s+be|roleplay\s+as|assume\s+the\s+role)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "new_instructions",
        re.compile(
            r"\b(new|updated|revised|additional|real|actual)\s+"
            r"(instruction|instructions|task|directive|directives|prompt)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system_prompt_reference",
        re.compile(r"\b(system\s+prompt|your\s+(system\s+)?instructions|developer\s+message)\b", re.IGNORECASE),
    ),
    (
        "suppress_extraction",
        re.compile(
            r"\b(do\s+not|don'?t|never)\s+(extract|report|include|mention|list|output)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "output_control",
        re.compile(
            r"\b(respond|reply|answer|output)\s+only\s+with\b|\breturn\s+only\s+the\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role_marker",
        re.compile(
            r"(^|\n)\s*(assistant|system|user|human)\s*:|<\|im_(start|end)\|>|\[/?INST\]|"
            r"<\|(system|user|assistant|endoftext)\|>",
            re.IGNORECASE,
        ),
    ),
    (
        "delimiter_escape",
        re.compile(r"<\s*/?\s*report", re.IGNORECASE),
    ),
    (
        "instruction_to_model",
        re.compile(
            r"\b(important|attention|note\s+to|message\s+to|hey)\s+"
            r"(ai|assistant|model|claude|chatgpt|gpt|llm)\b",
            re.IGNORECASE,
        ),
    ),
)

MEDIUM_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "add_indicator_request",
        re.compile(
            r"\b(add|include|append|insert)\s+(the\s+)?(following\s+)?"
            r"(indicator|indicators|ioc|iocs|ip|domain|hash|url)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "output_the_following",
        re.compile(r"\b(output|print|emit|write|echo)\s+the\s+following\b", re.IGNORECASE),
    ),
    (
        "image_or_url_output",
        re.compile(r"!\[[^\]]*\]\(|\bmarkdown\s+image\b|\binclude\s+(an?\s+)?(image|link)\b", re.IGNORECASE),
    ),
    (
        "long_base64_blob",
        # 200+ characters of base64 alphabet with no spaces: a payload, not prose.
        re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"),
    ),
    (
        "attribution_steer",
        re.compile(
            r"\b(attribute|blame|credit)\s+(this|the\s+attack|it)\s+to\b", re.IGNORECASE
        ),
    ),
)


@dataclass
class InjectionFinding:
    severity: str
    pattern_name: str
    snippet: str
    position: int = 0


@dataclass
class InjectionScan:
    findings: list[InjectionFinding] = field(default_factory=list)

    @property
    def high(self) -> list[InjectionFinding]:
        return [finding for finding in self.findings if finding.severity == SEVERITY_HIGH]

    @property
    def medium(self) -> list[InjectionFinding]:
        return [finding for finding in self.findings if finding.severity == SEVERITY_MEDIUM]

    @property
    def has_high(self) -> bool:
        return bool(self.high)

    @property
    def has_any(self) -> bool:
        return bool(self.findings)

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts


def _snippet(text: str, start: int, end: int) -> str:
    left = max(0, start - 40)
    right = min(len(text), end + 40)
    fragment = re.sub(r"\s+", " ", text[left:right]).strip()
    return fragment[:SNIPPET_CHARS]


def scan_for_injection(text: str) -> InjectionScan:
    """Scan one chunk (or one tool result) for injection attempts."""
    scan = InjectionScan()
    if not text:
        return scan

    seen: set[tuple[str, int]] = set()

    for severity, patterns in (
        (SEVERITY_HIGH, HIGH_PATTERNS),
        (SEVERITY_MEDIUM, MEDIUM_PATTERNS),
    ):
        for name, pattern in patterns:
            for match in pattern.finditer(text):
                key = (name, match.start())
                if key in seen:
                    continue
                seen.add(key)
                scan.findings.append(
                    InjectionFinding(
                        severity=severity,
                        pattern_name=name,
                        snippet=_snippet(text, match.start(), match.end()),
                        position=match.start(),
                    )
                )

    return scan


class InjectionClassifier:
    """Hook for a model-based classifier, so one can be added without touching callers.

    `INJECTION_CLASSIFIER=none` is the default and the only implementation for now. A classifier
    such as Meta Prompt Guard would slot in here; deliberately no torch or transformers
    dependency is added at this stage, because that would multiply the install size and the
    deployment cold-start time for a layer that is not carrying the security argument.
    """

    def __init__(self, name: str = "none") -> None:
        self.name = name

    @property
    def enabled(self) -> bool:
        return self.name != "none"

    def classify(self, text: str) -> float | None:
        """Return a 0-1 injection probability, or None when no classifier is configured."""
        if not self.enabled:
            return None
        raise NotImplementedError(
            f"Injection classifier '{self.name}' is not implemented. "
            "Set INJECTION_CLASSIFIER=none."
        )


def scan_with_policy(
    text: str, block_on: str = SEVERITY_HIGH
) -> tuple[InjectionScan, bool]:
    """Scan and apply policy. Returns (scan, should_exclude_from_llm)."""
    scan = scan_for_injection(text)
    if block_on == SEVERITY_HIGH:
        return scan, scan.has_high
    if block_on == SEVERITY_MEDIUM:
        return scan, scan.has_any
    # block_on == "none": report everything, exclude nothing.
    return scan, False
