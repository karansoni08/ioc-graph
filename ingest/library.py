"""The report library: public advisories available for one-click ingestion.

The PDFs are deliberately **not** committed. They total roughly 8 MB, three of them exceed the
1 MB ceiling the pre-commit hook enforces, and they are third-party files that anyone can fetch
from the publisher. So `library/manifest.json` is committed and the PDFs are downloaded on first
use and cached under `data/library/`.

The trade is one slow click the first time a given report is opened, in exchange for a small
repository and no weakening of the large-file guard. On a hosting platform with an ephemeral
disk the cache is repopulated after each restart, which is the same deal the ATT&CK dataset gets.

Everything fetched here still goes through the normal ingestion path, including sanitization:
a library report is treated as exactly as untrusted as an uploaded one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import requests

from config import Settings, get_settings

from .errors import IngestError

MANIFEST_PATH = Path(__file__).resolve().parent.parent / "library" / "manifest.json"

DOWNLOAD_TIMEOUT_SECONDS = 90

# This module is the only one in the app that makes an outbound request, so it is the one place
# an SSRF could live. The manifest is a committed JSON file in a PUBLIC repository, which means
# a pull request could propose changing a URL. Restricting fetches to a fixed set of publisher
# hosts means even an accepted malicious edit cannot turn the app into a request proxy, and it
# cannot be pointed at cloud metadata endpoints or an internal address.
ALLOWED_HOSTS = frozenset({"www.cisa.gov", "cisa.gov"})


@dataclass(frozen=True)
class LibraryReport:
    """One entry in the library."""

    id: str
    title: str
    category: str
    publisher: str
    advisory_id: str
    description: str
    source_page: str
    pdf_url: str
    filename: str

    @property
    def label(self) -> str:
        return f"{self.advisory_id} — {self.title}"


@lru_cache(maxsize=1)
def load_manifest() -> tuple[LibraryReport, ...]:
    """Parse the committed manifest. Cached; it does not change at runtime."""
    if not MANIFEST_PATH.exists():
        return ()
    try:
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ()
    return tuple(
        LibraryReport(**entry)
        for entry in payload.get("reports", [])
        if {"id", "title", "pdf_url", "filename"} <= set(entry)
    )


def get_report(report_id: str) -> LibraryReport | None:
    for report in load_manifest():
        if report.id == report_id:
            return report
    return None


def categories() -> list[str]:
    return sorted({report.category for report in load_manifest()})


def cache_dir(settings: Settings | None = None) -> Path:
    settings = settings or get_settings()
    return Path(settings.data_dir) / "library"


def cached_path(report: LibraryReport, settings: Settings | None = None) -> Path:
    return cache_dir(settings) / report.filename


def is_cached(report: LibraryReport, settings: Settings | None = None) -> bool:
    path = cached_path(report, settings)
    return path.exists() and path.stat().st_size > 0


def fetch_report(report: LibraryReport, settings: Settings | None = None) -> bytes:
    """Return the PDF bytes, downloading and caching on first use.

    Raises `IngestError` with a message fit for display; the caller is a UI, not a script.
    """
    path = cached_path(report, settings)
    if is_cached(report, settings):
        return path.read_bytes()

    _assert_allowed_url(report.pdf_url)

    try:
        # Default headers on purpose: cisa.gov's CDN rejects a spoofed browser User-Agent and
        # blocks urllib entirely, but allows plain requests.
        response = requests.get(report.pdf_url, timeout=DOWNLOAD_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.content
    except requests.RequestException as exc:
        raise IngestError(
            f"Could not download '{report.title}' from {report.publisher}. "
            f"The publisher may have moved it, or the network is unavailable. ({exc})"
        ) from exc

    # A CDN error page returns 200 with HTML, so verify this really is a PDF before caching it.
    if not payload.startswith(b"%PDF-"):
        raise IngestError(
            f"'{report.title}' did not download as a PDF. The publisher may have moved it; "
            f"the source page is {report.source_page}."
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return payload


def _assert_allowed_url(url: str) -> None:
    """Refuse any URL outside the publisher allowlist. See ALLOWED_HOSTS."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise IngestError("The library entry has an unreadable URL.") from exc

    if parts.scheme != "https":
        raise IngestError(f"Refusing to fetch a library report over {parts.scheme or 'no'} scheme.")
    if parts.hostname not in ALLOWED_HOSTS:
        raise IngestError(
            f"Refusing to fetch from '{parts.hostname}'. The report library may only download "
            f"from: {', '.join(sorted(ALLOWED_HOSTS))}."
        )


def cached_count(settings: Settings | None = None) -> int:
    return sum(1 for report in load_manifest() if is_cached(report, settings))
