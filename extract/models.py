"""Models for deterministic (regex) IOC extraction."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

IOCType = Literal[
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "email",
    "cve",
]

IOC_TYPES: tuple[str, ...] = (
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "email",
    "cve",
)

# Flags mark a value as a likely false positive. Nothing is ever dropped because of a flag:
# a flagged IOC is still extracted and still shown, just separated in the UI and reported
# separately in the evaluation.
FLAG_PRIVATE_IP = "private_ip"
FLAG_LOOPBACK = "loopback"
FLAG_RESERVED_IP = "reserved_ip"
FLAG_DOCUMENTATION_IP = "documentation_ip"
FLAG_VERSION_NUMBER = "possible_version_number"
FLAG_BENIGN_DOMAIN = "benign_domain"
FLAG_FILENAME_LIKE_DOMAIN = "filename_like_domain"
FLAG_HASH_WITHOUT_CONTEXT = "hash_without_context"

ALL_FLAGS: tuple[str, ...] = (
    FLAG_PRIVATE_IP,
    FLAG_LOOPBACK,
    FLAG_RESERVED_IP,
    FLAG_DOCUMENTATION_IP,
    FLAG_VERSION_NUMBER,
    FLAG_BENIGN_DOMAIN,
    FLAG_FILENAME_LIKE_DOMAIN,
    FLAG_HASH_WITHOUT_CONTEXT,
)

MAX_CONTEXTS = 3
CONTEXT_RADIUS = 150


class IOC(BaseModel):
    """One indicator, deduplicated across the whole document."""

    type: IOCType
    value: str = Field(description="Normalized and refanged value. The canonical form.")
    original_forms: list[str] = Field(
        default_factory=list,
        description="Every distinct form found in the report, e.g. 'evil[.]com'.",
    )
    occurrences: int = 0
    pages: list[int] = Field(default_factory=list)
    in_ioc_section: bool = False
    contexts: list[str] = Field(
        default_factory=list,
        description=f"Up to {MAX_CONTEXTS} snippets of ~{CONTEXT_RADIUS} characters each side.",
    )
    flags: list[str] = Field(
        default_factory=list, description="Empty means no false-positive suspicion."
    )

    @property
    def is_flagged(self) -> bool:
        return bool(self.flags)

    @property
    def was_defanged(self) -> bool:
        """True if any form in the report differed from the normalized value."""
        return any(form != self.value for form in self.original_forms)


class IOCExtraction(BaseModel):
    """The full deterministic extraction result for one document."""

    document_sha256: str
    iocs: list[IOC] = Field(default_factory=list)
    ioc_section_found: bool = False
    ioc_section_pages: list[int] = Field(default_factory=list)
    counts_by_type: dict[str, int] = Field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.iocs)

    @property
    def flagged_count(self) -> int:
        return sum(1 for ioc in self.iocs if ioc.is_flagged)

    def by_type(self, ioc_type: str) -> list[IOC]:
        return [ioc for ioc in self.iocs if ioc.type == ioc_type]

    def clean(self) -> list[IOC]:
        """IOCs with no false-positive flags."""
        return [ioc for ioc in self.iocs if not ioc.is_flagged]
