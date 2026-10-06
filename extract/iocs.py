"""Deterministic IOC extraction. No LLM is involved anywhere in this module.

Library decision (Phase 2 spike)
--------------------------------
`ioc-finder` 9.4.x is the primary extractor. It was chosen over `iocextract` because it
covers everything we need in one call with a typed result dict — ipv4s, ipv6s, domains, urls,
email_addresses, cves, md5s, sha1s, sha256s — and because it refangs defanged input natively
via its `ioc-fanger` dependency, so `hxxp://evil[.]com`, `bad(.)org`, `evil[dot]net` and
`user[at]evil[.]com` are all handled without custom code. `iocextract` has no CVE and no
domain extractor at all, which rules it out as the primary.

`iocextract` is kept for exactly one gap: `ioc-finder` 9.4.1 has no `sha512s` key and does not
detect 128-hex hashes, so `iocextract.extract_sha512_hashes` supplies that one type.

Both libraries anchor hash patterns on word boundaries, which was verified in the spike: a
64-hex SHA-256 embedded inside a longer unbroken hex run (for example inside a 96-character
blob) is correctly NOT reported, and an 80-character hex run is not reported as any hash type.
That is the behaviour we want, so no extra guarding is needed.

Domains that are only URL hosts
-------------------------------
`ioc-finder` reports the host of every URL as a domain as well. Reporting both would double
count: `http://evil.com/a` would yield the URL and the bare domain `evil.com`, even though the
report never mentioned the domain on its own. So a domain is dropped when every one of its
occurrences falls inside the span of an extracted URL. A domain that also appears on its own,
or as an email host, is kept as a separate IOC. See `_drop_url_only_domains`.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import ioc_fanger
import iocextract
from ioc_finder import find_iocs

from ingest.models import Document

from .models import (
    ALL_FLAGS,
    CONTEXT_RADIUS,
    FLAG_BENIGN_DOMAIN,
    FLAG_DOCUMENTATION_IP,
    FLAG_FILENAME_LIKE_DOMAIN,
    FLAG_HASH_WITHOUT_CONTEXT,
    FLAG_LOOPBACK,
    FLAG_PRIVATE_IP,
    FLAG_RESERVED_IP,
    FLAG_VERSION_NUMBER,
    IOC,
    MAX_CONTEXTS,
    IOCExtraction,
)
from .sections import find_ioc_section
from .text_repair import compact_hex_cell, rejoin_wrapped_hashes

ALLOWLIST_PATH = Path(__file__).with_name("allowlist.txt")

# RFC 5737 ranges reserved for documentation and examples.
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

# TLDs that are also common file extensions. A domain using one is often a filename.
_FILENAME_TLDS = {"zip", "mov", "py", "sh", "exe", "com"}

# `.com` is far too common to flag on the TLD alone, so a filename-ish context is required.
_FILE_CONTEXT = re.compile(
    r"\b(file|filename|file name|attachment|archive|executable|binary|script|payload|"
    r"dropped|downloads?|saved|extracted|named)\b",
    re.IGNORECASE,
)

_VERSION_CONTEXT = re.compile(r"(version|v\.|build|release)", re.IGNORECASE)

_HASH_CONTEXT = re.compile(
    r"\b(malware|sample|file|payload|hash|hashes|sha-?\d*|md5|ransomware|binary|executable|"
    r"dropper|loader|signature|indicator)\b",
    re.IGNORECASE,
)

_HASH_TYPES = {"md5", "sha1", "sha256", "sha512"}

# Separator alternatives used when a value is written in defanged form. Used to rebuild a
# pattern that finds every original spelling of an already-normalized value.
_DOT_ALTERNATIVES = r"(?:\.|\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\))"
_AT_ALTERNATIVES = r"(?:@|\[\s*@\s*\]|\(\s*@\s*\)|\[\s*at\s*\]|\(\s*at\s*\))"
_COLON_ALTERNATIVES = r"(?::|\[\s*:\s*\]|\(\s*:\s*\))"
_SCHEME_ALTERNATIVES = {
    "http": r"(?:http|hxxp|hXXp)",
    "https": r"(?:https|hxxps|hXXps)",
    "ftp": r"(?:ftp|fxp)",
}


@lru_cache(maxsize=1)
def load_allowlist() -> frozenset[str]:
    """Domains considered benign. Cached: the file does not change at runtime."""
    if not ALLOWLIST_PATH.exists():  # pragma: no cover - file ships with the package
        return frozenset()
    entries = set()
    for line in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            entries.add(line)
    return frozenset(entries)


def refang(text: str) -> str:
    """Turn defanged IOCs back into real ones.

    Delegates to ioc-fanger, which handles hxxp/fxp, [.] (.) {.} [dot], [at], [:] and [://].
    """
    return ioc_fanger.fang(text)


# --------------------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------------------


def normalize_domain(value: str) -> str | None:
    value = value.strip().lower().rstrip(".")
    return value or None


def normalize_hash(value: str) -> str | None:
    value = value.strip().lower()
    return value or None


def normalize_cve(value: str) -> str | None:
    value = value.strip().upper()
    return value or None


def normalize_email(value: str) -> str | None:
    value = value.strip().lower()
    return value or None


def normalize_ip(value: str) -> str | None:
    """Return the canonical IP string, or None when the value is not a valid address.

    Using `ipaddress` both validates and canonicalizes, so 2001:0db8::0001 and 2001:db8::1
    become the same IOC.
    """
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def normalize_url(value: str) -> str | None:
    """Lowercase the scheme and host but preserve the path, which is case-sensitive."""
    value = value.strip().rstrip(".,;)\"'")
    if not value:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment)
    )


_NORMALIZERS = {
    "ipv4": normalize_ip,
    "ipv6": normalize_ip,
    "domain": normalize_domain,
    "url": normalize_url,
    "md5": normalize_hash,
    "sha1": normalize_hash,
    "sha256": normalize_hash,
    "sha512": normalize_hash,
    "email": normalize_email,
    "cve": normalize_cve,
}


# --------------------------------------------------------------------------------------
# Finding the original (possibly defanged) spellings of a normalized value
# --------------------------------------------------------------------------------------


def _defanged_pattern(value: str, ioc_type: str) -> re.Pattern[str] | None:
    """Build a regex matching any defanged spelling of an already-normalized value.

    This is how `original_forms`, `occurrences` and `contexts` are recovered: extraction runs
    on refanged text, but the report is searched in its original form so the user sees what
    the document actually said.
    """
    if ioc_type == "url":
        try:
            parts = urlsplit(value)
        except ValueError:
            return None
        scheme_pattern = _SCHEME_ALTERNATIVES.get(parts.scheme, re.escape(parts.scheme))
        host_pattern = _DOT_ALTERNATIVES.join(re.escape(p) for p in parts.netloc.split("."))
        rest = value.split(parts.netloc, 1)[-1]
        body = rf"{scheme_pattern}{_COLON_ALTERNATIVES}(?://|\[//\]){host_pattern}{re.escape(rest)}"
        try:
            return re.compile(body, re.IGNORECASE)
        except re.error:  # pragma: no cover - defensive
            return None

    if ioc_type == "email":
        local, _, domain = value.partition("@")
        domain_pattern = _DOT_ALTERNATIVES.join(re.escape(p) for p in domain.split("."))
        body = rf"{re.escape(local)}{_AT_ALTERNATIVES}{domain_pattern}"
        return re.compile(body, re.IGNORECASE)

    if ioc_type in ("domain", "ipv4"):
        # Both are dot-separated, so the same alternation applies.
        parts_pattern = _DOT_ALTERNATIVES.join(re.escape(p) for p in value.split("."))
        return re.compile(rf"(?<![\w.-]){parts_pattern}(?![\w-])", re.IGNORECASE)

    if ioc_type == "ipv6":
        # IPv6 is rarely defanged with brackets around colons; match it literally.
        return re.compile(re.escape(value), re.IGNORECASE)

    # Hashes and CVEs are not defanged; a plain case-insensitive match is enough.
    return re.compile(rf"(?<![\w-]){re.escape(value)}(?![\w-])", re.IGNORECASE)


def _raw_forms_pattern(raw_forms: set[str]) -> re.Pattern[str] | None:
    """Match any of the spellings an extractor actually returned, longest first."""
    if not raw_forms:
        return None
    ordered = sorted(raw_forms, key=len, reverse=True)
    body = "|".join(re.escape(form) for form in ordered)
    try:
        return re.compile(rf"(?<![\w.-])(?:{body})(?![\w-])", re.IGNORECASE)
    except re.error:  # pragma: no cover - defensive
        return None


def _find_spans(pattern: re.Pattern[str] | None, text: str) -> list[tuple[int, int, str]]:
    if pattern is None:
        return []
    return [(m.start(), m.end(), m.group(0)) for m in pattern.finditer(text)]


def _snippet(text: str, start: int, end: int) -> str:
    """A context window around a match, with newlines flattened for display."""
    left = max(0, start - CONTEXT_RADIUS)
    right = min(len(text), end + CONTEXT_RADIUS)
    fragment = text[left:right].replace("\r", " ").replace("\n", " ")
    fragment = re.sub(r"\s{2,}", " ", fragment).strip()
    prefix = "…" if left > 0 else ""
    suffix = "…" if right < len(text) else ""
    return f"{prefix}{fragment}{suffix}"


# --------------------------------------------------------------------------------------
# Raw candidate collection
# --------------------------------------------------------------------------------------


def _collect_candidates(fanged_text: str) -> dict[str, dict[str, set[str]]]:
    """Run the extractors over refanged text.

    Returns, per type, a mapping of normalized value to the raw spellings the extractors
    actually returned. The raw spellings matter because normalization can change a value beyond
    what a defanging pattern can reverse: `ipaddress` compresses
    `2001:0db8:85a3:0000:0000:8a2e:0370:7334` to `2001:db8:85a3::8a2e:370:7334`, which no longer
    occurs anywhere in the document. Keeping the raw form lets the span search fall back to it.
    """
    found = find_iocs(fanged_text)

    raw: dict[str, list[str]] = {
        "ipv4": list(found.get("ipv4s", []) or []),
        "ipv6": list(found.get("ipv6s", []) or []),
        "domain": list(found.get("domains", []) or []),
        "url": list(found.get("urls", []) or []),
        "md5": list(found.get("md5s", []) or []),
        "sha1": list(found.get("sha1s", []) or []),
        "sha256": list(found.get("sha256s", []) or []),
        # Gap filled by iocextract: ioc-finder 9.4.x has no sha512 support.
        "sha512": list(iocextract.extract_sha512_hashes(fanged_text)),
        "email": list(found.get("email_addresses", []) or []),
        "cve": list(found.get("cves", []) or []),
    }

    candidates: dict[str, dict[str, set[str]]] = {}
    for ioc_type, values in raw.items():
        normalize = _NORMALIZERS[ioc_type]
        grouped: dict[str, set[str]] = defaultdict(set)
        for value in values:
            text_value = str(value)
            canonical = normalize(text_value)
            if canonical:
                grouped[canonical].add(text_value)
        candidates[ioc_type] = dict(grouped)
    return candidates


# --------------------------------------------------------------------------------------
# False-positive flags
# --------------------------------------------------------------------------------------


def _ip_flags(value: str) -> list[str]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:  # pragma: no cover - value was normalized by ipaddress already
        return []

    flags: list[str] = []
    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        flags.append(FLAG_DOCUMENTATION_IP)
    if address.is_loopback:
        flags.append(FLAG_LOOPBACK)
    # Documentation ranges are inside Python's private list, so the more specific flag above
    # is reported too; `private_ip` is suppressed for them to keep the signal readable.
    elif address.is_private and FLAG_DOCUMENTATION_IP not in flags:
        flags.append(FLAG_PRIVATE_IP)
    if address.is_reserved or address.is_multicast or address.is_link_local:
        flags.append(FLAG_RESERVED_IP)
    return flags


def _registrable(domain: str) -> str:
    """The last two labels of a domain.

    A deliberate simplification: it treats `example.co.uk` as `co.uk`, which the public suffix
    list would get right. It is only used to guess the publisher's own domain, where the cost of
    being wrong is one extra flag on a value that is still extracted and still shown.
    """
    labels = domain.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def find_publisher_domains(url_values: list[str]) -> set[str]:
    """Guess the domain of whoever published the report, from its own URLs.

    A report links to its publisher far more than to anything else: CISA advisories link to
    cisa.gov throughout, a vendor write-up links to its own blog. Those links are never the
    indicator, so the dominant host is flagged as benign. Requires both an absolute floor and a
    share of all URLs so that a handful of links cannot nominate a publisher.
    """
    counts: dict[str, int] = defaultdict(int)
    for value in url_values:
        try:
            host = urlsplit(value).netloc.lower()
        except ValueError:  # pragma: no cover - values are normalized URLs
            continue
        if host:
            counts[_registrable(host)] += 1
    if not counts:
        return set()

    total = sum(counts.values())
    leader, leader_count = max(counts.items(), key=lambda item: item[1])
    if leader_count >= 3 and leader_count / total >= 0.25:
        return {leader}
    return set()


def _domain_flags(
    value: str,
    contexts: list[str],
    allowlist: frozenset[str],
    publisher_domains: set[str],
) -> list[str]:
    flags: list[str] = []

    labels = value.split(".")
    # A domain matches the allowlist on itself or on any parent, so mail.google.com matches
    # google.com. The publisher's own domain is treated the same way.
    benign = False
    for index in range(len(labels) - 1):
        parent = ".".join(labels[index:])
        if parent in allowlist or parent in publisher_domains:
            benign = True
            break
    if benign:
        flags.append(FLAG_BENIGN_DOMAIN)

    tld = labels[-1] if labels else ""
    if tld in _FILENAME_TLDS and len(labels) == 2:
        joined_context = " ".join(contexts)
        looks_like_file = bool(_FILE_CONTEXT.search(joined_context))
        # `.com` is a real TLD far more often than a filename, so it needs file context.
        # The others (.zip/.mov/.py/.sh/.exe) are flagged on a weaker signal.
        if tld == "com":
            pass
        elif looks_like_file or tld in {"py", "sh", "exe"}:
            flags.append(FLAG_FILENAME_LIKE_DOMAIN)
        elif tld in {"zip", "mov"}:
            flags.append(FLAG_FILENAME_LIKE_DOMAIN)
    return flags


def _version_number_flag(value: str, original_text: str, spans: list[tuple[int, int, str]]) -> bool:
    """True if an IPv4-looking value sits next to version wording.

    Only the 30 characters each side of each occurrence are inspected, per the Phase 2 spec.
    """
    for start, end, _ in spans:
        window = original_text[max(0, start - 30) : min(len(original_text), end + 30)]
        if _VERSION_CONTEXT.search(window):
            return True
    return False


_HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{32,128}\b")


def _hash_without_context(
    value: str,
    original_text: str,
    spans: list[tuple[int, int, str]],
    other_values: set[str],
) -> bool:
    """True if no hash-related keyword and no other IOC appears within 200 characters.

    "Other IOC" includes other hashes, which matters: a hash sitting in a column of fifty other
    hashes inside an IOC table is well attributed, even though no prose surrounds it. An earlier
    version only looked for non-hash IOCs and flagged almost every legitimately tabulated hash,
    which made the flag useless for filtering.

    A hint for later phases rather than a verdict: a lone hash with nothing around it is harder
    to attribute, so Phase 3 and the agent may want to treat it with less confidence.
    """
    for start, end, _ in spans:
        window = original_text[max(0, start - 200) : min(len(original_text), end + 200)]
        if _HASH_CONTEXT.search(window):
            return False
        # Another hash nearby counts as context.
        if any(token.lower() != value for token in _HEX_TOKEN.findall(window)):
            return False
        lowered = window.lower()
        if any(other in lowered for other in other_values):
            return False
    return True


# --------------------------------------------------------------------------------------
# URL-host-only domain suppression
# --------------------------------------------------------------------------------------


def _drop_url_only_domains(
    records: dict[tuple[str, str], dict],
    url_spans_by_source: dict[int, list[tuple[int, int]]],
) -> None:
    """Remove domains whose every occurrence lies inside an extracted URL.

    See the module docstring for the rationale.
    """
    for key in [k for k in records if k[0] == "domain"]:
        record = records[key]
        occurrences = record["spans_by_source"]
        if not occurrences:
            continue
        all_inside = True
        for source_index, spans in occurrences.items():
            url_spans = url_spans_by_source.get(source_index, [])
            for start, end in spans:
                if not any(u_start <= start and end <= u_end for u_start, u_end in url_spans):
                    all_inside = False
                    break
            if not all_inside:
                break
        if all_inside:
            del records[key]


# --------------------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------------------


def _document_sources(doc: Document) -> list[tuple[int, str]]:
    """Every searchable chunk of the document as (page number, text).

    Table cells are included as their own sources because IOC lists in advisories are usually
    tables, and PyMuPDF's page text does not always preserve cell boundaries cleanly. Table
    text is attributed to page 0, meaning "from a table", since pdfplumber tables are collected
    document-wide.

    Both kinds of source are passed through the hash-rejoining repair in `text_repair`, because
    advisories wrap long hashes across lines inside narrow columns. The repaired text is what
    gets searched for spans too, so `original_forms` and `contexts` show the rejoined value
    rather than a fragment.
    """
    sources: list[tuple[int, str]] = [
        (page_number, rejoin_wrapped_hashes(text))
        for page_number, text in enumerate(doc.pages, start=1)
    ]
    for table in doc.tables:
        cell_text = "\n".join(
            " ".join(compact_hex_cell(cell) for cell in row if cell) for row in table
        )
        if cell_text.strip():
            sources.append((0, rejoin_wrapped_hashes(cell_text)))
    return sources


def extract_iocs(doc: Document) -> IOCExtraction:
    """Extract, normalize, deduplicate and flag every IOC in a document.

    Deterministic: the same document always produces the same result, and no network or model
    call is made.
    """
    allowlist = load_allowlist()
    section_pages = find_ioc_section(doc)
    sources = _document_sources(doc)

    # (type, value) -> accumulating record
    records: dict[tuple[str, str], dict] = {}
    url_spans_by_source: dict[int, list[tuple[int, int]]] = defaultdict(list)

    for source_index, (page_number, original_text) in enumerate(sources):
        if not original_text.strip():
            continue
        fanged_text = refang(original_text)
        candidates = _collect_candidates(fanged_text)

        for ioc_type, values in candidates.items():
            for value, raw_forms in values.items():
                pattern = _defanged_pattern(value, ioc_type)
                spans = _find_spans(pattern, original_text)
                search_text = original_text
                if not spans:
                    # Normalization moved the value away from how the document spells it (IPv6
                    # compression, for example). Look for the raw spellings instead.
                    raw_pattern = _raw_forms_pattern(raw_forms)
                    spans = _find_spans(raw_pattern, original_text)
                if not spans:
                    # Only visible after refanging in a way no pattern reconstructs (rare).
                    # Fall back to the refanged text so the value is still counted.
                    spans = _find_spans(pattern, fanged_text) or _find_spans(
                        _raw_forms_pattern(raw_forms), fanged_text
                    )
                    search_text = fanged_text
                if not spans:
                    continue

                key = (ioc_type, value)
                record = records.setdefault(
                    key,
                    {
                        "original_forms": [],
                        "occurrences": 0,
                        "pages": set(),
                        "contexts": [],
                        "spans_by_source": defaultdict(list),
                    },
                )
                record["occurrences"] += len(spans)
                if page_number:
                    record["pages"].add(page_number)
                for start, end, matched in spans:
                    if matched not in record["original_forms"]:
                        record["original_forms"].append(matched)
                    if len(record["contexts"]) < MAX_CONTEXTS:
                        record["contexts"].append(_snippet(search_text, start, end))
                    record["spans_by_source"][source_index].append((start, end))

                if ioc_type == "url":
                    url_spans_by_source[source_index].extend((s, e) for s, e, _ in spans)

    _drop_url_only_domains(records, url_spans_by_source)

    # Non-hash IOC values, used by the hash-without-context check. Nearby hashes are detected
    # separately inside that check, by shape rather than by lookup.
    non_hash_values = {
        value.lower() for (ioc_type, value) in records if ioc_type not in _HASH_TYPES
    }

    publisher_domains = find_publisher_domains(
        [value for (ioc_type, value) in records if ioc_type == "url"]
    )

    iocs: list[IOC] = []
    for (ioc_type, value), record in records.items():
        flags: list[str] = []
        contexts = record["contexts"]

        if ioc_type in ("ipv4", "ipv6"):
            flags.extend(_ip_flags(value))
        if ioc_type == "ipv4":
            flagged_version = False
            for source_index, spans in record["spans_by_source"].items():
                text = sources[source_index][1]
                if _version_number_flag(value, text, [(s, e, "") for s, e in spans]):
                    flagged_version = True
                    break
            if flagged_version:
                flags.append(FLAG_VERSION_NUMBER)
        if ioc_type == "domain":
            flags.extend(_domain_flags(value, contexts, allowlist, publisher_domains))
        if ioc_type in _HASH_TYPES:
            lonely = True
            for source_index, spans in record["spans_by_source"].items():
                text = sources[source_index][1]
                if not _hash_without_context(
                    value, text, [(s, e, "") for s, e in spans], non_hash_values
                ):
                    lonely = False
                    break
            if lonely:
                flags.append(FLAG_HASH_WITHOUT_CONTEXT)

        pages = sorted(record["pages"])
        iocs.append(
            IOC(
                type=ioc_type,  # type: ignore[arg-type]
                value=value,
                original_forms=record["original_forms"],
                occurrences=record["occurrences"],
                pages=pages,
                in_ioc_section=any(page in section_pages for page in pages),
                contexts=contexts,
                flags=[flag for flag in ALL_FLAGS if flag in flags],
            )
        )

    iocs.sort(key=lambda ioc: (ioc.type, ioc.value))

    counts_by_type: dict[str, int] = {}
    for ioc in iocs:
        counts_by_type[ioc.type] = counts_by_type.get(ioc.type, 0) + 1

    return IOCExtraction(
        document_sha256=doc.sha256,
        iocs=iocs,
        ioc_section_found=bool(section_pages),
        ioc_section_pages=sorted(section_pages),
        counts_by_type=counts_by_type,
    )
