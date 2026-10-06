"""Download the MITRE ATT&CK Enterprise STIX bundle.

Lands in `data/attack/` which is gitignored: the bundle is tens of megabytes and is a published
artifact that anyone can re-download, so committing it would bloat every clone for no benefit.
The version actually downloaded is recorded in `data/attack/VERSION` so a run trace can say which
ATT&CK release it was mapped against.

Run from the project root:

    python scripts/fetch_attack.py              # fetch if missing
    python scripts/fetch_attack.py --force      # re-download
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests

# The official MITRE repository. `enterprise-attack.json` without a version is the current one.
BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack"
BUNDLE_URL = f"{BASE}/enterprise-attack.json"
INDEX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
)

ATTACK_DIR = Path("data/attack")
BUNDLE_PATH = ATTACK_DIR / "enterprise-attack.json"
VERSION_PATH = ATTACK_DIR / "VERSION"

TIMEOUT_SECONDS = 180


def _detect_version(bundle: dict) -> str:
    """Read the ATT&CK spec version from the bundle's marking or collection object."""
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            for item in obj.get("x_mitre_version", []) if isinstance(obj.get("x_mitre_version"), list) else []:
                return str(item)
            version = obj.get("x_mitre_version")
            if version:
                return str(version)
    # Fall back to the first technique's spec version.
    for obj in bundle.get("objects", []):
        if obj.get("x_mitre_version"):
            return f"unknown (object version {obj['x_mitre_version']})"
    return "unknown"


def fetch(force: bool = False) -> int:
    if BUNDLE_PATH.exists() and not force:
        size_mb = BUNDLE_PATH.stat().st_size / (1024 * 1024)
        version = VERSION_PATH.read_text(encoding="utf-8").strip() if VERSION_PATH.exists() else "?"
        print(f"have {BUNDLE_PATH} ({size_mb:.1f} MB, ATT&CK {version})")
        return 0

    print(f"downloading {BUNDLE_URL} …")
    try:
        response = requests.get(BUNDLE_URL, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    try:
        bundle = response.json()
    except ValueError:
        print("FAILED: response was not JSON", file=sys.stderr)
        return 1

    if not isinstance(bundle, dict) or "objects" not in bundle:
        print("FAILED: response is not a STIX bundle", file=sys.stderr)
        return 1

    ATTACK_DIR.mkdir(parents=True, exist_ok=True)
    BUNDLE_PATH.write_text(json.dumps(bundle), encoding="utf-8")
    version = _detect_version(bundle)
    VERSION_PATH.write_text(version + "\n", encoding="utf-8")

    size_mb = BUNDLE_PATH.stat().st_size / (1024 * 1024)
    techniques = sum(1 for obj in bundle["objects"] if obj.get("type") == "attack-pattern")
    print(f"saved {BUNDLE_PATH} ({size_mb:.1f} MB), ATT&CK {version}, {techniques} techniques")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="re-download even if present")
    args = parser.parse_args()
    return fetch(force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
