# Evaluation

Measured accuracy of this project's extraction stages against public reports with
published IOC lists. Regenerate with `python scripts/eval_regex.py --write-docs`.

## Regex extraction (Phase 2)

Date: 2026-10-06
Commit: `22615e7`
Extractors: `ioc-finder` 9.4.1 (primary), `iocextract` 1.16.1 (SHA-512 only)

### How to read these numbers

Ground truth is each advisory's own published STIX 2.x bundle, converted to
`tests/fixtures/expected/*.json` by `scripts/build_expected.py`. That bundle is a
**superset of the PDF**: one indicator routinely lists SHA-1, SHA-256, MD5 and SSDEEP
for the same file while the advisory prints only one hash column. Hashes that were never
printed cannot be extracted from the document by any means, so plain **recall is capped
below 1.0 by the source**, not by the extractor.

**Attainable recall** is therefore the number to judge the extractor by: it is measured
only over ground-truth values that are physically present in the document text. Plain
recall is kept because it is the honest end-to-end number for the question "if I upload
this PDF, how much of the published IOC list do I get?".

A type absent from a bundle is marked *not measurable* rather than scored, since every
correct extraction would otherwise be counted as a false positive.

### #StopRansomware: Akira Ransomware

Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a

PDF: 31 pages, 64,298 characters, 62 tables detected.
IOC section: pages 12.
Extracted 91 unique IOCs, of which 5 carry a false-positive flag.

| Type | Truth | Present in doc | Extracted | TP | FP | FN | Precision | Recall | Attainable recall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| md5 | 34 | 6 | 6 | 6 | 0 | 28 | 1.000 | 0.176 | 1.000 |
| sha1 | 31 | 4 | 6 | 4 | 2 | 27 | 0.667 | 0.129 | 1.000 |
| sha256 | 42 | 41 | 41 | 41 | 0 | 1 | 1.000 | 0.976 | 1.000 |
| cve | 8 | 8 | 8 | 8 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| **overall** | 115 | 59 | 61 | 59 | 2 | 56 | **0.967** | **0.513** | **1.000** |
| overall, flagged excluded | 115 | - | 61 | 59 | 2 | 56 | 0.967 | 0.513 | - |

Not measurable (the published list contains no entries of these types, so correct extractions cannot be distinguished from false positives): domain (8 extracted), url (18 extracted), email (4 extracted).

Extracted but not in the published list — sha1: 2 values, e.g. `131da83b521f610819141d5c740313ce46578374`, `95477703e789e6182096a09bc98853e0a70b680a`.

### #StopRansomware: CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit

Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a

PDF: 24 pages, 41,491 characters, 46 tables detected.
IOC section: pages 13, 14, 15, 16.
Extracted 197 unique IOCs, of which 8 carry a false-positive flag.

| Type | Truth | Present in doc | Extracted | TP | FP | FN | Precision | Recall | Attainable recall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| domain | 6 | 6 | 14 | 0 | 14 | 6 | 0.000 | 0.000 | 0.000 |
| url | 8 | 8 | 12 | 8 | 4 | 0 | 0.667 | 1.000 | 1.000 |
| md5 | 41 | 5 | 6 | 5 | 1 | 36 | 0.833 | 0.122 | 1.000 |
| sha256 | 54 | 53 | 53 | 53 | 0 | 1 | 1.000 | 0.981 | 1.000 |
| email | 5 | 4 | 5 | 4 | 1 | 1 | 0.800 | 0.800 | 1.000 |
| cve | 1 | 1 | 2 | 1 | 1 | 0 | 0.500 | 1.000 | 1.000 |
| **overall** | 115 | 77 | 92 | 71 | 21 | 44 | **0.772** | **0.617** | **0.922** |
| overall, flagged excluded | 115 | - | 84 | 71 | 13 | 44 | 0.845 | 0.617 | - |

Not measurable (the published list contains no entries of these types, so correct extractions cannot be distinguished from false positives): ipv4 (105 extracted).

Domains captured inside a URL rather than as standalone domains: 6 of 6. The advisory prints these as `http://evil.com`, and the published bundle lists each one as both a url and a domain-name indicator; this project reports the URL and does not duplicate the host (see `extract/iocs.py`). Crediting them, domain recall is 1.000 rather than 0.000.

Missed although present in the document — domain: 6 values, e.g. `connectzoomdownload.com`, `guerdofest.com`, `hiperfdhaus.com`, `jirostrogud.com`, `qweastradoc.com`.
Extracted but not in the published list — domain: 14 values, e.g. `asp.net`, `cisa.dhs.gov`, `cisa.gov`, `f.id`, `f.name`.
Extracted but not in the published list — url: 4 values, e.g. `https://gist.github.com/JohnHammond/44ce8556f798b7f6a7574148b679c643`, `https://www.bleepingcomputer.com/news/security/new-moveit-`, `https://www.bleepingcomputer.com/news/security/new-moveittransfer-zero-day-mass-exploited-in-data-theft-attacks/`, `https://www.reddit.com/r/msp/comments/13xjs1y/tracking_emerging_moveit_transfer`.
Extracted but not in the published list — md5: 1 values, e.g. `44ce8556f798b7f6a7574148b679c643`.
Extracted but not in the published list — email: 1 values, e.g. `report@cisa.dhs.gov`.
Extracted but not in the published list — cve: 1 values, e.g. `CVE-2023-0669`.

### #StopRansomware: RansomHub Ransomware

Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a

PDF: 24 pages, 43,880 characters, 29 tables detected.
IOC section: pages 10.
Extracted 143 unique IOCs, of which 10 carry a false-positive flag.

| Type | Truth | Present in doc | Extracted | TP | FP | FN | Precision | Recall | Attainable recall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ipv4 | 9 | 9 | 9 | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| domain | 1 | 1 | 10 | 1 | 9 | 0 | 0.100 | 1.000 | 1.000 |
| url | 110 | 110 | 111 | 106 | 5 | 4 | 0.955 | 0.964 | 0.964 |
| email | 1 | 1 | 4 | 1 | 3 | 0 | 0.250 | 1.000 | 1.000 |
| **overall** | 121 | 121 | 134 | 117 | 17 | 4 | **0.873** | **0.967** | **0.967** |
| overall, flagged excluded | 121 | - | 124 | 116 | 8 | 5 | 0.935 | 0.959 | - |

Not measurable (the published list contains no entries of these types, so correct extractions cannot be distinguished from false positives): cve (9 extracted).

Missed although present in the document — url: 4 values, e.g. `http://89.23.96.203/333/en-US/d%E5%AD%97%E5%AD%97.resources/d%E5%AD%97%E5%AD%97.resources.dll`, `http://89.23.96.203/333/en-US/d%E5%AD%97%E5%AD%97.resources/d%E5%AD%97%E5%AD%97.resources.exe`, `http://89.23.96.203/333/en/d%E5%AD%97%E5%AD%97.resources/d%E5%AD%97%E5%AD%97.resources.dll`, `http://89.23.96.203/333/en/d%E5%AD%97%E5%AD%97.resources/d%E5%AD%97%E5%AD%97.resources.exe`.
Extracted but not in the published list — domain: 9 values, e.g. `atlassian.net`, `bleepingcomputer.com`, `cisa.gov`, `cisecurity.org`, `fortinet.com`.
Extracted but not in the published list — url: 5 values, e.g. `http://89.23.96.203/333/en-`, `http://89.23.96.203/333/en/d%E5%AD%97%E5%AD%97.resources/d%E5%AD%97%E5%AD%97.resourc`, `http://www.cisa.gov/tlp`, `https://samuelelena.co/npm/module.external/jquery.min.js`, `https://samuelelena.co/npm/module.external/jquery.min.js&nbsp`.
Extracted but not in the published list — email: 3 values, e.g. `report@cisa.gov`, `soc@cisecurity.org`, `thre@uptycs.com`.

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
