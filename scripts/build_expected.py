"""Build committed ground-truth IOC lists from the advisories' published STIX bundles.

Input:  tests/fixtures/reports/<key>.stix.json   (downloaded, gitignored)
Output: tests/fixtures/expected/<key>.json       (committed)

The output is committed so the evaluation can be re-run and reviewed without re-downloading
anything, and so a reviewer can audit exactly what the metrics were computed against.

Important caveat, recorded in every generated file: a CISA STIX bundle is a SUPERSET of the
advisory PDF. One indicator commonly lists SHA-1, SHA-256, MD5 and SSDEEP for the same file
while the PDF prints only the SHA-256 column. Those unprinted hashes are not extractable from
the document by any means, so `scripts/eval_regex.py` reports recall twice: against the full
published list, and against the subset that actually appears in the document text.

Run from the project root:

    python scripts/build_expected.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from extract.iocs import (  # noqa: E402
    normalize_cve,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ip,
    normalize_url,
)
from scripts.fetch_fixtures import ADVISORIES  # noqa: E402

REPORTS_DIR = Path("tests/fixtures/reports")
EXPECTED_DIR = Path("tests/fixtures/expected")

# Advisories chosen for the Phase 2 evaluation. Black Basta (AA24-131A) was downloaded and
# rejected: its STIX bundle publishes only 6 indicators (4 IPs, 2 domains) and omits the hash
# tables printed in its own PDF, so every hash the extractor correctly found would have scored
# as a false positive.
EVALUATION_KEYS = ("aa24-109a-akira", "aa23-158a-cl0p-moveit", "aa24-242a-ransomhub")

# STIX pattern fragments mapped to our IOC types. SSDEEP, file:name and registry keys are
# deliberately ignored: they are not types this project extracts.
_PATTERN_RULES: tuple[tuple[str, str], ...] = (
    (r"file:hashes\.'?SHA-256'?\s*=\s*'([^']+)'", "sha256"),
    (r"file:hashes\.'?SHA-512'?\s*=\s*'([^']+)'", "sha512"),
    (r"file:hashes\.'?SHA-1'?\s*=\s*'([^']+)'", "sha1"),
    (r"file:hashes\.'?MD5'?\s*=\s*'([^']+)'", "md5"),
    (r"ipv4-addr:value\s*=\s*'([^']+)'", "ipv4"),
    (r"ipv6-addr:value\s*=\s*'([^']+)'", "ipv6"),
    (r"domain-name:value\s*=\s*'([^']+)'", "domain"),
    (r"url:value\s*=\s*'([^']+)'", "url"),
    (r"email-addr:value\s*=\s*'([^']+)'", "email"),
    (r"email-message:from_ref\.value\s*=\s*'([^']+)'", "email"),
)

_COMPILED = tuple((re.compile(pattern, re.IGNORECASE), ioc_type) for pattern, ioc_type in _PATTERN_RULES)

_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# The project's own normalizers are used so both sides of the comparison are canonicalized
# identically. The untouched STIX value is kept in `raw_values` for auditing.
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


def build(key: str) -> dict:
    stix_path = REPORTS_DIR / f"{key}.stix.json"
    if not stix_path.exists():
        raise FileNotFoundError(
            f"{stix_path} is missing. Run `python scripts/fetch_fixtures.py` first."
        )

    bundle = json.loads(stix_path.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])

    values: dict[str, set[str]] = {ioc_type: set() for ioc_type in _NORMALIZERS}
    raw_values: dict[str, set[str]] = {ioc_type: set() for ioc_type in _NORMALIZERS}

    indicator_count = 0
    for obj in objects:
        obj_type = obj.get("type")

        if obj_type == "indicator":
            indicator_count += 1
            pattern = obj.get("pattern", "")
            for compiled, ioc_type in _COMPILED:
                for raw in compiled.findall(pattern):
                    raw_values[ioc_type].add(raw)
                    normalized = _NORMALIZERS[ioc_type](raw)
                    if normalized:
                        values[ioc_type].add(normalized)

        # CVEs are published as vulnerability objects rather than indicators.
        elif obj_type == "vulnerability":
            for match in _CVE_ID.findall(obj.get("name", "") or ""):
                raw_values["cve"].add(match)
                values["cve"].add(normalize_cve(match) or match.upper())

        # Some advisories name the CVE only in the report title or description.
        elif obj_type == "report":
            haystack = f"{obj.get('name', '')} {obj.get('description', '')}"
            for match in _CVE_ID.findall(haystack):
                raw_values["cve"].add(match)
                values["cve"].add(normalize_cve(match) or match.upper())

    advisory = ADVISORIES[key]
    return {
        "advisory_id": key.split("-")[0].upper() + "-" + key.split("-")[1].upper(),
        # Named "fixture" rather than "key": a JSON field called "key" trips the gitleaks
        # generic-api-key rule on every commit, and renaming the field is better than adding a
        # scanner allowlist that could hide a real secret later.
        "fixture": key,
        "title": advisory["title"],
        "source": "stix",
        "source_urls": {
            "advisory_page": advisory["page"],
            "pdf": advisory["pdf"],
            "stix": advisory["stix"],
        },
        "generated_by": "scripts/build_expected.py",
        "note": (
            "Ground truth is the advisory's published STIX 2.x bundle. It is a SUPERSET of the "
            "PDF: a single indicator often lists SHA-1, SHA-256, MD5 and SSDEEP for one file "
            "while the PDF prints only one hash column, so hashes absent from the document are "
            "unreachable for any text extractor. eval_regex.py therefore reports both raw "
            "recall against this full list and attainable recall against the subset present in "
            "the document text. SSDEEP, file names and registry keys are excluded because this "
            "project does not extract those types."
        ),
        "stix_indicator_count": indicator_count,
        "counts": {t: len(v) for t, v in sorted(values.items()) if v},
        "iocs": {t: sorted(v) for t, v in sorted(values.items()) if v},
        "raw_values": {t: sorted(v) for t, v in sorted(raw_values.items()) if v},
    }


def main() -> int:
    EXPECTED_DIR.mkdir(parents=True, exist_ok=True)
    for key in EVALUATION_KEYS:
        try:
            expected = build(key)
        except FileNotFoundError as exc:
            print(f"SKIP {key}: {exc}", file=sys.stderr)
            return 1
        destination = EXPECTED_DIR / f"{key}.json"
        destination.write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {destination}  counts={expected['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
