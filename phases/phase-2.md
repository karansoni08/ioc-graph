# Phase 2 — Deterministic IOC Extraction (No LLM)

Read `CLAUDE.md` first. This file adds detail for Phase 2 only.

## Goal
Extract IOCs from ingested reports using regex libraries only, refang defanged values,
flag likely false positives, locate the report's IOC section, and measure precision and
recall against public reports with published IOC lists.

## Before you start
- Confirm Phase 1 is complete: `pytest -q` passes, `git status` is clean, `origin/main`
  is up to date. If not, stop and tell me.

## Out of scope
LLM calls, graphs, storage. No `anthropic` import anywhere in this phase.

## 1. Library choice (short spike, then decide)
1. Install `ioc-finder` and `iocextract`.
2. Write a throwaway script (do not commit it) that runs both on a sample text containing
   the edge cases in section 6, and inspect their actual output structure.
3. Choose one as primary (expected: `ioc-finder`, since it covers domains, CVEs and
   defanged input), and use the other only if it fills a real gap. Record the decision and
   the reason in a short comment at the top of `extract/iocs.py`.
4. Pin the chosen libraries in `requirements.txt`.

## 2. IOC model (`extract/models.py`)
Pydantic model `IOC`:
- `type: Literal["ipv4","ipv6","domain","url","md5","sha1","sha256","sha512","email","cve"]`
- `value: str` (normalized, refanged)
- `original_forms: list[str]` (every form as it appeared, e.g. `evil[.]com`)
- `occurrences: int`
- `pages: list[int]`
- `in_ioc_section: bool`
- `contexts: list[str]` (up to 3 snippets of about 150 characters on each side)
- `flags: list[str]` (see section 4; empty means clean)

Pydantic model `IOCExtraction`: `document_sha256`, `iocs: list[IOC]`,
`ioc_section_found: bool`, `ioc_section_pages: list[int]`, `counts_by_type: dict[str,int]`.

## 3. Extraction (`extract/iocs.py`)
`extract_iocs(doc: Document) -> IOCExtraction`
1. Run extraction on each page's text AND on table cells (tables often hold the IOC lists).
2. Refang: `hxxp`/`hxxps`/`fxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `[:]`, `[://]`, `[@]`, `[at]`.
   Keep the original form in `original_forms`.
3. Normalize: domains lowercase without trailing dot; hashes lowercase; CVE uppercase;
   emails lowercase; IPs via the `ipaddress` module (reject invalid ones); URLs keep the
   path case but lowercase the scheme and host.
4. Deduplicate by `(type, value)`, merging pages, contexts and original forms.
5. Do not report a domain separately if it only appears as the host of an extracted URL
   AND never appears on its own; instead keep it inside the URL. (Document this choice.)

## 4. False-positive flags (flag, never silently drop)
Add `flags` entries:
- `private_ip`, `loopback`, `reserved_ip`, `documentation_ip` (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24) via `ipaddress`.
- `possible_version_number`: IPv4-looking value where the surrounding 30 characters
  contain `version`, `v.`, `build` or `release`.
- `benign_domain`: value or parent domain in `extract/allowlist.txt` (one per line;
  seed with common ones: microsoft.com, windows.com, google.com, github.com, w3.org,
  schema.org, adobe.com, cisa.gov, mitre.org, apple.com, amazon.com, cloudflare.com).
  Also flag the report publisher's own domain if detectable from the URLs.
- `filename_like_domain`: domain whose TLD is also a common file extension
  (`.zip`, `.mov`, `.py`, `.sh`, `.exe` if present) and where context suggests a file.
- `hash_without_context`: a hash with no other IOC or keyword (malware, sample, file,
  payload, hash, SHA, MD5) within 200 characters. This is a hint for later LLM/agent work.
The UI shows flagged items separately.

## 5. IOC section detection (`extract/sections.py`)
`find_ioc_section(doc) -> list[int]` returns pages that contain the IOC section.
- Match headings (case-insensitive, at line start) such as: "Indicators of Compromise",
  "IOCs", "IoCs", "Indicators", "Network Indicators", "Host-Based Indicators",
  "Appendix" followed by IOC-related words, "Technical Details" + "Indicators".
- A section continues until the next heading-like line that is not IOC-related, or the
  end of the document.
- Fallback: if no heading matches, mark pages where IOC density (IOCs per 1,000
  characters) is more than 3x the document average.
Set `in_ioc_section` on each IOC accordingly.

## 6. Unit tests (`tests/test_iocs.py`)
Cover at least:
- `hxxp://evil[.]com/path`, `hxxps://bad(.)org`, `192.168[.]1[.]1`, `user[at]evil[.]com`,
  `evil[dot]net` all refang correctly with original forms preserved.
- MD5, SHA1, SHA256, SHA512 detected by length; a 64-hex string inside a longer hex blob
  is not mis-detected (inspect library behaviour and document it).
- `CVE-2024-3400` and lowercase `cve-2021-44228` both normalize to uppercase.
- Private, loopback and documentation IPs are flagged, not dropped.
- `version 1.2.3.4` gets `possible_version_number`.
- Duplicates across pages merge into one IOC with both pages listed.
- IOCs inside a generated table are found.
- IOC section detection works on a generated document with an "Indicators of
  Compromise" heading on page 3.

## 7. Real-world evaluation set
1. Create `scripts/fetch_fixtures.py` that downloads 3 public CISA cybersecurity advisories
   (PDF) into `tests/fixtures/reports/` (this folder is gitignored). Ask me to confirm the
   3 advisories you picked before downloading. Prefer advisories that publish a separate
   machine-readable IOC file (STIX JSON or CSV).
2. For each, create `tests/fixtures/expected/<name>.json` (committed) with the ground-truth
   IOC list, built from the advisory's published IOC file. Record the source URL in the
   JSON. If no machine-readable list exists, build it by hand from the IOC tables and say
   so in the JSON (`"source": "manual"`).
3. Create `scripts/eval_regex.py` that runs `extract_iocs` on each fixture and prints a
   table: per type and overall, true positives, false positives, false negatives,
   precision, recall. Treat flagged items as predictions but also print metrics with
   flagged items excluded.
4. Save results to `docs/EVALUATION.md` under a "Regex extraction (Phase 2)" heading,
   with the date and the commit hash.
5. If recall is below 0.9 for any type, investigate the misses, fix what is reasonable,
   and list remaining known limitations in `docs/EVALUATION.md`.

## 8. UI updates
Add an "IOCs" section below the document view:
- Metrics row with counts per type.
- Info line: whether an IOC section was found and on which pages.
- Filter by type (multiselect) and a toggle "Show flagged items".
- Table: type, value (DISPLAYED DEFANGED, e.g. `evil[.]com`, `hxxp://`), occurrences,
  pages, in IOC section, flags. Defanging in the UI prevents accidental clicks on
  malicious links. Write a small `defang()` helper in `extract/display.py`.
- Expander per IOC (or a selected IOC) showing its context snippets with `st.text`.
- Download buttons for JSON and CSV (raw refanged values, clearly labelled).

## 9. Finish
1. `pytest -q` passes.
2. Update README status to "Phase 2 of 7" and add a short "How IOC extraction works"
   section.
3. `git status`; confirm no files from `tests/fixtures/reports/` or `data/` are staged.
4. Commit `Phase 2: regex IOC extraction, refanging, FP flags, evaluation` and push.

## Acceptance criteria
- [ ] Defanged IOCs are refanged and deduplicated; UI shows them defanged.
- [ ] Flags appear for private IPs, benign domains and version numbers.
- [ ] IOC section detected on at least 2 of the 3 real advisories.
- [ ] `docs/EVALUATION.md` contains precision/recall per type for the 3 advisories.
- [ ] Tests pass, pushed to GitHub.

## Ask me before
Choosing the 3 advisories, adding any dependency not named here, changing the IOC types.

## When finished, report
Library decision and why, evaluation numbers, the main false positives and misses, and
anything you think should be improved before Phase 3.
