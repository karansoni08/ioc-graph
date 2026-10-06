"""Display helpers for IOC values.

IOCs are stored refanged (real) so they can be matched, graphed and exported, but they are
shown defanged so that nobody in the UI can click a live malicious link, and so copying a value
out of the page does not produce something immediately dangerous.
"""

from __future__ import annotations

import re

_SCHEME = re.compile(r"\bhttp(s?)://", re.IGNORECASE)
_FTP_SCHEME = re.compile(r"\bftp://", re.IGNORECASE)

# Types whose values contain hostnames or addresses worth neutralizing.
_DEFANGED_TYPES = {"ipv4", "domain", "url", "email"}


def defang(value: str, ioc_type: str | None = None) -> str:
    """Return a value in a form that is not clickable and not resolvable.

    `http://evil.com/x` becomes `hxxp://evil[.]com/x`, `evil.com` becomes `evil[.]com`,
    `a@evil.com` becomes `a[at]evil[.]com`. Hashes, CVE ids and IPv6 are returned unchanged:
    they are not clickable and bracketing them only hurts readability.
    """
    if ioc_type is not None and ioc_type not in _DEFANGED_TYPES:
        return value

    result = _SCHEME.sub(lambda m: f"hxxp{m.group(1)}://", value)
    result = _FTP_SCHEME.sub("fxp://", result)
    result = result.replace("@", "[at]")
    result = result.replace(".", "[.]")
    return result


def flag_label(flag: str) -> str:
    """Human-readable name for a false-positive flag."""
    return flag.replace("_", " ")


def format_pages(pages: list[int]) -> str:
    """Render page numbers for display. Page 0 means the value came from a table."""
    if not pages:
        return "table"
    return ", ".join(str(page) for page in pages)
