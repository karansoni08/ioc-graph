"""Download public CISA advisories used as evaluation fixtures.

The PDFs land in `tests/fixtures/reports/`, which is gitignored: the advisories are public
but there is no reason to redistribute them from this repo, and keeping binaries out of git
keeps clones small. The published STIX 2.x IOC lists land beside them and are the raw material
for the committed ground truth in `tests/fixtures/expected/`.

Run from the project root:

    python scripts/fetch_fixtures.py            # download anything missing
    python scripts/fetch_fixtures.py --force    # re-download everything
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import requests

BASE = "https://www.cisa.gov"
REPORTS_DIR = Path("tests/fixtures/reports")

# cisa.gov sits behind a CDN that 403s urllib regardless of headers, and also 403s a
# browser User-Agent string. Plain `requests` with its own default headers is allowed, so
# nothing here spoofs a browser. `requests` is already present as a Streamlit dependency.
TIMEOUT_SECONDS = 60

# Each advisory: the PDF we ingest, plus the STIX 2.x bundle CISA publishes as its
# machine-readable IOC list. Where CISA has revised an advisory, the newest PDF and the
# newest STIX bundle are paired so the two describe the same revision.
ADVISORIES: dict[str, dict[str, str]] = {
    "aa24-109a-akira": {
        "title": "#StopRansomware: Akira Ransomware",
        "page": f"{BASE}/news-events/cybersecurity-advisories/aa24-109a",
        "pdf": f"{BASE}/sites/default/files/2025-12/aa24-109a-stopransomware-akira-ransomware.pdf",
        "stix": (
            f"{BASE}/sites/default/files/2025-11/"
            "AA24-109A-%23StopRansomware-Akira-Ransomware.stix_.json"
        ),
    },
    "aa24-131a-black-basta": {
        "title": "#StopRansomware: Black Basta",
        "page": f"{BASE}/news-events/cybersecurity-advisories/aa24-131a",
        "pdf": (
            f"{BASE}/sites/default/files/2024-11/"
            "aa24-131a-joint-csa-stopransomware-black-basta_3.pdf"
        ),
        "stix": (
            f"{BASE}/sites/default/files/2024-11/"
            "AA24-131A_StopRansomware_Black_Basta.stix_.json"
        ),
    },
    "aa23-158a-cl0p-moveit": {
        "title": "#StopRansomware: CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit",
        "page": f"{BASE}/news-events/cybersecurity-advisories/aa23-158a",
        "pdf": (
            f"{BASE}/sites/default/files/2023-07/"
            "aa23-158a-stopransomware-cl0p-ransomware-gang-exploits-moveit-vulnerability_8.pdf"
        ),
        "stix": (
            f"{BASE}/sites/default/files/2023-06/"
            "AA23-158A%20StopRansomware%20CL0P%20Ransomware%20Gang%20Exploits%20"
            "CVE-2023-34362%20MOVEit%20Vulnerability.stix_.json"
        ),
    },
    "aa24-242a-ransomhub": {
        "title": "#StopRansomware: RansomHub Ransomware",
        "page": f"{BASE}/news-events/cybersecurity-advisories/aa24-242a",
        "pdf": (
            f"{BASE}/sites/default/files/2024-09/"
            "aa24-242a-stopransomware-ransomhub-ransomware_1.pdf"
        ),
        "stix": (
            f"{BASE}/sites/default/files/2024-08/"
            "AA24-242A-StopRansomware-RansomHub-Ransomware.stix_.json"
        ),
    },
}


def download(url: str, destination: Path, force: bool = False) -> bool:
    """Fetch one file. Returns True if it is present afterwards."""
    if destination.exists() and not force:
        size_kb = destination.stat().st_size / 1024
        print(f"  have     {destination.name} ({size_kb:,.0f} KB)")
        return True

    try:
        response = requests.get(url, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.content
    except requests.RequestException as exc:
        print(f"  FAILED   {destination.name}: {exc}", file=sys.stderr)
        return False

    # A CDN error page returns 200 with HTML, so check the payload really is what we asked for.
    if destination.suffix == ".pdf" and not payload.startswith(b"%PDF-"):
        print(f"  FAILED   {destination.name}: response was not a PDF", file=sys.stderr)
        return False

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    print(f"  fetched  {destination.name} ({len(payload) / 1024:,.0f} KB)")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="re-download existing files")
    parser.add_argument("--only", help="fetch a single advisory by key")
    args = parser.parse_args()

    selected = ADVISORIES
    if args.only:
        if args.only not in ADVISORIES:
            print(f"Unknown advisory '{args.only}'. Known: {', '.join(ADVISORIES)}")
            return 2
        selected = {args.only: ADVISORIES[args.only]}

    failures = 0
    for key, advisory in selected.items():
        print(f"\n{key} — {advisory['title']}")
        if not download(advisory["pdf"], REPORTS_DIR / f"{key}.pdf", args.force):
            failures += 1
        if not download(advisory["stix"], REPORTS_DIR / f"{key}.stix.json", args.force):
            failures += 1

    print(f"\nFixtures in {REPORTS_DIR}/ (gitignored).")
    if failures:
        print(
            f"{failures} download(s) failed. CISA re-publishes advisories under dated paths, "
            "so a 404 usually means the URL in this script needs updating from the advisory "
            "page listed above.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
