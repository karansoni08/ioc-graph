"""Measure regex IOC extraction against the advisories' published IOC lists.

Run from the project root:

    python scripts/eval_regex.py                  # print the report
    python scripts/eval_regex.py --write-docs     # also update docs/EVALUATION.md

Three numbers are reported per type, because two of them answer different questions:

* precision — of what we extracted, how much is in the published list.
* recall — of the published list, how much did we extract.
* attainable recall — of the published entries that are actually present in the document text,
  how much did we extract. A CISA STIX bundle lists every hash of a file while the PDF prints
  only one hash column, so plain recall is capped well below 1.0 by the source itself. Attainable
  recall isolates what the extractor is responsible for.

Metrics are computed twice: counting every extracted IOC as a prediction, and again with
flagged (likely false-positive) IOCs excluded, which is what the `flags` mechanism is for.

A type that the ground truth does not cover at all is listed as "not measurable" rather than
scored, because every correct extraction of that type would otherwise count as a false positive.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import Settings  # noqa: E402
from extract.iocs import _document_sources, extract_iocs, refang  # noqa: E402
from extract.models import IOC_TYPES  # noqa: E402
from ingest.loader import load_document  # noqa: E402

REPORTS_DIR = Path("tests/fixtures/reports")
EXPECTED_DIR = Path("tests/fixtures/expected")
DOCS_PATH = Path("docs/EVALUATION.md")

# Fixtures are real advisories, larger than the 5 MB / 50 page limits the app enforces on
# uploads. The limits are a UI guard, not an extraction guard, so evaluation raises them.
EVAL_SETTINGS = Settings(max_file_mb=25, max_pages=200)

_WHITESPACE = re.compile(r"\s+")


# Hand-written analysis appended to the generated report so that regenerating the document
# does not discard it. The figures quoted here are prose: re-check them after changing the
# extractor.
LIMITATIONS = """
## Known limitations (Phase 2)

Recorded after investigating every type whose recall fell below 0.9.

**Hashes the advisory never printed.** Plain MD5 recall is 0.18 (Akira) and 0.12 (CL0P), and
SHA-1 recall is 0.13, entirely because the STIX bundle lists every hash of a file while the PDF
prints only the SHA-256 column. Attainable recall for all three types is 1.000: every hash that
is actually in the document was found. Nothing can be done about this in the extractor, and
reading plain recall as an extractor defect would be a mistake.

**Hashes wrapped across lines.** Advisories print hashes in narrow table columns, which wraps a
64-character SHA-256 across two or three lines. This initially hid 29 of 42 SHA-256 hashes in
the Akira advisory. `extract/text_repair.py` now rejoins fragments, which took Akira SHA-256
recall from 0.31 to 0.98 and CL0P from 0.80 to 0.98 with no new false positives. The repair only
acts when the fragments divide cleanly into whole hashes, so two stacked SHA-256 hashes are not
merged into a non-existent SHA-512.

**URLs wrapped across lines are still lost.** Four RansomHub URLs are missed for the same reason
hashes were, for example `http://89.23.96.203/333/en-` where the rest of the path continued on
the next line. URLs cannot be repaired with the hash trick, because there is no fixed length to
validate a rejoin against, and guessing would invent URLs that were never in the report. URL
recall is 0.964, above the 0.9 bar, so this is left as a known limitation. A layout-aware
extractor that reads PDF text spans with coordinates would be the real fix.

**Domains printed as bare URLs.** CL0P prints its malicious domains as `http://hiperfdhaus.com`,
and the bundle then lists each one as both a url and a domain-name indicator. By design this
project reports the URL and does not also report its host as a separate domain, so strict domain
recall is 0.000 while the values are all captured: crediting URL hosts, domain recall is 1.000.
The rationale is in `extract/iocs.py` — reporting both would double count every URL in every
report. Phase 4 should decide whether the graph wants a domain node for each URL host, which is
probably yes, and that is the right place to resolve it rather than in extraction.

**Code and query identifiers read as domains.** `f.id` and `fr.name` are extracted as domains
from a SQL snippet (`select f.id, f.instid, ...`), because `.id` and `.name` are real TLDs. Four
such values in CL0P. These are not flagged, since the flags defined for this phase do not cover
them, and distinguishing a SQL column from a domain by regex alone is not reliable. They are the
largest remaining source of domain false positives. Phase 3 is better placed to reject them,
because the LLM sees that the surrounding text is a query.

**Citation domains.** Advisories cite security press and vendor blogs heavily in their
References sections, and those citations are not indicators. `extract/allowlist.txt` now carries
the common ones and the publisher's own domain is detected automatically from the URL
distribution, which is what lifts overall precision with flagged items excluded to 0.845 (CL0P)
and 0.935 (RansomHub). The allowlist is necessarily incomplete and will need extending as new
report sources are ingested.

**IPv4 and CVE precision is not measurable on these fixtures.** CL0P's bundle lists no IPs while
the advisory prints 105, and RansomHub's lists no CVEs while the advisory mentions 9. Those
extractions are almost certainly correct but cannot be scored here. A fixture whose bundle
covers every type would be needed, and no CISA advisory examined publishes one.

**No fixture covers IPv6 or SHA-512.** Both are implemented and unit tested, but neither appears
in the three advisories, so neither has a real-world precision or recall number.
"""


@dataclass
class Metrics:
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def predicted(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def actual(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def precision(self) -> float | None:
        return self.true_positives / self.predicted if self.predicted else None

    @property
    def recall(self) -> float | None:
        return self.true_positives / self.actual if self.actual else None


def _format(value: float | None) -> str:
    return "  -  " if value is None else f"{value:.3f}"


def _compare(predicted: set[str], expected: set[str]) -> Metrics:
    return Metrics(
        true_positives=len(predicted & expected),
        false_positives=len(predicted - expected),
        false_negatives=len(expected - predicted),
    )


def _present_in_document(values: set[str], document_text: str) -> set[str]:
    """Subset of ground-truth values physically present in the extracted document text.

    Compared against whitespace-stripped text as well, so a hash the PDF wrapped across lines
    still counts as present: the question here is whether the document contains the value at
    all, not whether our repair found it.
    """
    lowered = document_text.lower()
    compacted = _WHITESPACE.sub("", lowered)
    present = set()
    for value in values:
        needle = value.lower()
        if needle in lowered or needle in compacted:
            present.add(value)
    return present


def evaluate_one(key: str) -> dict:
    expected_path = EXPECTED_DIR / f"{key}.json"
    pdf_path = REPORTS_DIR / f"{key}.pdf"
    if not expected_path.exists():
        raise FileNotFoundError(f"{expected_path} missing; run scripts/build_expected.py")
    if not pdf_path.exists():
        raise FileNotFoundError(f"{pdf_path} missing; run scripts/fetch_fixtures.py")

    expected_data = json.loads(expected_path.read_text(encoding="utf-8"))
    expected: dict[str, set[str]] = {
        ioc_type: set(values) for ioc_type, values in expected_data["iocs"].items()
    }

    document = load_document(pdf_path.name, pdf_path.read_bytes(), EVAL_SETTINGS)
    extraction = extract_iocs(document)

    # The text the extractor actually searched, including table cells and hash repair, and
    # refanged — ground-truth values are real IOCs, while advisories print them defanged, so
    # the presence check has to compare like with like.
    searched_text = refang("\n".join(text for _, text in _document_sources(document)))

    all_predicted: dict[str, set[str]] = {t: set() for t in IOC_TYPES}
    clean_predicted: dict[str, set[str]] = {t: set() for t in IOC_TYPES}
    for ioc in extraction.iocs:
        all_predicted[ioc.type].add(ioc.value)
        if not ioc.flags:
            clean_predicted[ioc.type].add(ioc.value)

    # By design, a domain that only ever appears as the host of an extracted URL is not
    # reported separately (see extract/iocs.py). Advisories print malicious domains as
    # "http://evil.com", and the published bundle then lists them as BOTH a url and a
    # domain-name indicator. Counting those as misses would measure the design choice rather
    # than the extractor, so URL hosts are credited to the domain type as well.
    url_hosts: set[str] = set()
    for url_value in all_predicted["url"]:
        try:
            host = urlsplit(url_value).netloc.lower()
        except ValueError:  # pragma: no cover
            continue
        if host:
            url_hosts.add(host)

    per_type: dict[str, dict] = {}
    not_measurable: list[str] = []
    for ioc_type in IOC_TYPES:
        truth = expected.get(ioc_type, set())
        if not truth:
            if all_predicted[ioc_type]:
                not_measurable.append(f"{ioc_type} ({len(all_predicted[ioc_type])} extracted)")
            continue
        attainable = _present_in_document(truth, searched_text)
        if ioc_type == "domain":
            credited = all_predicted["domain"] | (truth & url_hosts)
            per_type_extra = {
                "domain_in_url": sorted(truth & url_hosts - all_predicted["domain"]),
                "with_url_hosts": _compare(credited, truth),
            }
        else:
            per_type_extra = {}
        per_type[ioc_type] = {
            "all": _compare(all_predicted[ioc_type], truth),
            "clean": _compare(clean_predicted[ioc_type], truth),
            "attainable": _compare(all_predicted[ioc_type] & attainable, attainable),
            "attainable_total": len(attainable),
            "truth_total": len(truth),
            "missed": sorted(truth - all_predicted[ioc_type]),
            "missed_but_present": sorted(attainable - all_predicted[ioc_type]),
            "extra": sorted(all_predicted[ioc_type] - truth),
            **per_type_extra,
        }

    def totals(which: str) -> Metrics:
        return Metrics(
            sum(per_type[t][which].true_positives for t in per_type),
            sum(per_type[t][which].false_positives for t in per_type),
            sum(per_type[t][which].false_negatives for t in per_type),
        )

    return {
        "key": key,
        "title": expected_data["title"],
        "advisory_page": expected_data["source_urls"]["advisory_page"],
        "pages": document.page_count,
        "tables": document.table_count,
        "characters": document.char_count,
        "section_found": extraction.ioc_section_found,
        "section_pages": extraction.ioc_section_pages,
        "extracted_total": extraction.total,
        "flagged_total": extraction.flagged_count,
        "counts_by_type": extraction.counts_by_type,
        "per_type": per_type,
        "not_measurable": not_measurable,
        "overall_all": totals("all"),
        "overall_clean": totals("clean"),
        "overall_attainable": totals("attainable"),
    }


def render(results: list[dict]) -> str:
    lines: list[str] = []
    add = lines.append

    for result in results:
        add(f"### {result['title']}")
        add("")
        add(f"Source: {result['advisory_page']}")
        add("")
        add(
            f"PDF: {result['pages']} pages, {result['characters']:,} characters, "
            f"{result['tables']} tables detected."
        )
        section = (
            f"pages {', '.join(str(p) for p in result['section_pages'])}"
            if result["section_found"]
            else "not found"
        )
        add(f"IOC section: {section}.")
        add(
            f"Extracted {result['extracted_total']} unique IOCs, "
            f"of which {result['flagged_total']} carry a false-positive flag."
        )
        add("")
        add("| Type | Truth | Present in doc | Extracted | TP | FP | FN | Precision | Recall | Attainable recall |")
        add("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for ioc_type, data in result["per_type"].items():
            metrics: Metrics = data["all"]
            attainable: Metrics = data["attainable"]
            add(
                f"| {ioc_type} | {data['truth_total']} | {data['attainable_total']} | "
                f"{metrics.predicted} | {metrics.true_positives} | {metrics.false_positives} | "
                f"{metrics.false_negatives} | {_format(metrics.precision)} | "
                f"{_format(metrics.recall)} | {_format(attainable.recall)} |"
            )
        overall: Metrics = result["overall_all"]
        clean: Metrics = result["overall_clean"]
        attainable_overall: Metrics = result["overall_attainable"]
        add(
            f"| **overall** | {overall.actual} | {attainable_overall.actual} | "
            f"{overall.predicted} | {overall.true_positives} | {overall.false_positives} | "
            f"{overall.false_negatives} | **{_format(overall.precision)}** | "
            f"**{_format(overall.recall)}** | **{_format(attainable_overall.recall)}** |"
        )
        add(
            f"| overall, flagged excluded | {clean.actual} | - | {clean.predicted} | "
            f"{clean.true_positives} | {clean.false_positives} | {clean.false_negatives} | "
            f"{_format(clean.precision)} | {_format(clean.recall)} | - |"
        )
        add("")
        if result["not_measurable"]:
            add(
                "Not measurable (the published list contains no entries of these types, so "
                "correct extractions cannot be distinguished from false positives): "
                + ", ".join(result["not_measurable"])
                + "."
            )
            add("")
        domain_data = result["per_type"].get("domain")
        if domain_data and domain_data.get("domain_in_url"):
            credited: Metrics = domain_data["with_url_hosts"]
            add(
                f"Domains captured inside a URL rather than as standalone domains: "
                f"{len(domain_data['domain_in_url'])} of "
                f"{domain_data['truth_total']}. The advisory prints these as "
                "`http://evil.com`, and the published bundle lists each one as both a url and a "
                "domain-name indicator; this project reports the URL and does not duplicate the "
                "host (see `extract/iocs.py`). Crediting them, domain recall is "
                f"{_format(credited.recall)} rather than "
                f"{_format(domain_data['all'].recall)}."
            )
            add("")
        for ioc_type, data in result["per_type"].items():
            if data["missed_but_present"]:
                shown = data["missed_but_present"][:5]
                add(
                    f"Missed although present in the document — {ioc_type}: "
                    f"{len(data['missed_but_present'])} values, e.g. "
                    + ", ".join(f"`{v}`" for v in shown)
                    + "."
                )
        for ioc_type, data in result["per_type"].items():
            if data["extra"]:
                shown = data["extra"][:5]
                add(
                    f"Extracted but not in the published list — {ioc_type}: "
                    f"{len(data['extra'])} values, e.g. " + ", ".join(f"`{v}`" for v in shown) + "."
                )
        add("")
    return "\n".join(lines)


def _commit_hash() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):  # pragma: no cover
        return "unknown"


def write_docs(results: list[dict]) -> None:
    DOCS_PATH.parent.mkdir(parents=True, exist_ok=True)
    body = render(results)
    header = [
        "# Evaluation",
        "",
        "Measured accuracy of this project's extraction stages against public reports with",
        "published IOC lists. Regenerate with `python scripts/eval_regex.py --write-docs`.",
        "",
        "## Regex extraction (Phase 2)",
        "",
        f"Date: {date.today().isoformat()}  ",
        f"Commit: `{_commit_hash()}`  ",
        "Extractors: `ioc-finder` 9.4.1 (primary), `iocextract` 1.16.1 (SHA-512 only)",
        "",
        "### How to read these numbers",
        "",
        "Ground truth is each advisory's own published STIX 2.x bundle, converted to",
        "`tests/fixtures/expected/*.json` by `scripts/build_expected.py`. That bundle is a",
        "**superset of the PDF**: one indicator routinely lists SHA-1, SHA-256, MD5 and SSDEEP",
        "for the same file while the advisory prints only one hash column. Hashes that were never",
        "printed cannot be extracted from the document by any means, so plain **recall is capped",
        "below 1.0 by the source**, not by the extractor.",
        "",
        "**Attainable recall** is therefore the number to judge the extractor by: it is measured",
        "only over ground-truth values that are physically present in the document text. Plain",
        "recall is kept because it is the honest end-to-end number for the question \"if I upload",
        "this PDF, how much of the published IOC list do I get?\".",
        "",
        "A type absent from a bundle is marked *not measurable* rather than scored, since every",
        "correct extraction would otherwise be counted as a false positive.",
        "",
    ]
    DOCS_PATH.write_text(
        "\n".join(header) + "\n" + body + "\n" + LIMITATIONS.strip() + "\n",
        encoding="utf-8",
    )
    print(f"wrote {DOCS_PATH}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-docs", action="store_true", help="update docs/EVALUATION.md")
    args = parser.parse_args()

    from scripts.build_expected import EVALUATION_KEYS

    results = []
    for key in EVALUATION_KEYS:
        try:
            results.append(evaluate_one(key))
        except FileNotFoundError as exc:
            print(f"ERROR {exc}", file=sys.stderr)
            return 1

    print(render(results))
    if args.write_docs:
        write_docs(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
