"""Tests for deterministic IOC extraction.

Fixtures are built in memory. No network access and no LLM call happens anywhere here; the
real-advisory evaluation lives in `scripts/eval_regex.py` instead, because it needs downloaded
PDFs that are deliberately not committed.
"""

from __future__ import annotations

import pytest

from extract.display import defang, format_pages
from extract.iocs import (
    extract_iocs,
    find_publisher_domains,
    normalize_ip,
    normalize_url,
    refang,
)
from extract.models import (
    FLAG_BENIGN_DOMAIN,
    FLAG_DOCUMENTATION_IP,
    FLAG_FILENAME_LIKE_DOMAIN,
    FLAG_HASH_WITHOUT_CONTEXT,
    FLAG_LOOPBACK,
    FLAG_PRIVATE_IP,
    FLAG_VERSION_NUMBER,
)
from extract.sections import find_ioc_section, is_heading_like
from extract.text_repair import compact_hex_cell, rejoin_wrapped_hashes, segment_hex_fragments
from ingest.models import Document, join_pages

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA512 = (
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)


def make_doc(pages: list[str], tables: list[list[list[str]]] | None = None) -> Document:
    """Build a Document directly, skipping PDF generation."""
    return Document(
        filename="report.pdf",
        file_type="pdf",
        sha256="a" * 64,
        size_bytes=1000,
        page_count=len(pages),
        pages=pages,
        tables=tables or [],
        text=join_pages(pages),
    )


def extract(pages: list[str], tables: list[list[list[str]]] | None = None):
    return extract_iocs(make_doc(pages, tables))


def values_of(result, ioc_type: str) -> set[str]:
    return {ioc.value for ioc in result.iocs if ioc.type == ioc_type}


def get_ioc(result, ioc_type: str, value: str):
    for ioc in result.iocs:
        if ioc.type == ioc_type and ioc.value == value:
            return ioc
    raise AssertionError(f"{ioc_type} {value!r} not extracted; got {result.counts_by_type}")


class TestRefanging:
    def test_refang_handles_all_required_forms(self) -> None:
        assert refang("hxxp://evil[.]com/path") == "http://evil.com/path"
        assert refang("hxxps://bad(.)org") == "https://bad.org"
        assert refang("192.168[.]1[.]1") == "192.168.1.1"
        assert refang("evil[dot]net") == "evil.net"

    def test_defanged_url_is_extracted_and_normalized(self) -> None:
        result = extract(["Beacon to hxxp://evil[.]com/path/Payload.EXE for tasking."])
        assert "http://evil.com/path/Payload.EXE" in values_of(result, "url")

    def test_original_defanged_form_is_preserved(self) -> None:
        result = extract(["Contacted hxxps://bad(.)org repeatedly."])
        ioc = get_ioc(result, "url", "https://bad.org")
        assert ioc.original_forms == ["hxxps://bad(.)org"]
        assert ioc.was_defanged is True

    def test_defanged_ip_keeps_original_form(self) -> None:
        result = extract(["Traffic to 192.168[.]1[.]1 was observed."])
        ioc = get_ioc(result, "ipv4", "192.168.1.1")
        assert ioc.original_forms == ["192.168[.]1[.]1"]

    def test_defanged_email_is_extracted(self) -> None:
        result = extract(["Ransom note lists user[at]evil[.]com as contact."])
        ioc = get_ioc(result, "email", "user@evil.com")
        assert ioc.original_forms == ["user[at]evil[.]com"]

    def test_bracket_dot_domain_is_extracted(self) -> None:
        result = extract(["The domain evil[dot]net resolved to the C2."])
        ioc = get_ioc(result, "domain", "evil.net")
        assert ioc.original_forms == ["evil[dot]net"]

    def test_url_path_case_is_preserved_but_host_is_lowercased(self) -> None:
        result = extract(["Download from hxxp://EVIL[.]com/Path/File.EXE now."])
        assert "http://evil.com/Path/File.EXE" in values_of(result, "url")


class TestHashes:
    def test_all_four_hash_lengths_detected(self) -> None:
        page = f"Malware sample hashes: {MD5} {SHA1} {SHA256} {SHA512}"
        result = extract([page])
        assert values_of(result, "md5") == {MD5}
        assert values_of(result, "sha1") == {SHA1}
        assert values_of(result, "sha256") == {SHA256}
        assert values_of(result, "sha512") == {SHA512}

    def test_uppercase_hash_is_normalized_to_lowercase(self) -> None:
        result = extract([f"Sample file hash {SHA256.upper()} observed."])
        assert values_of(result, "sha256") == {SHA256}

    def test_hash_inside_longer_hex_blob_is_not_detected(self) -> None:
        """Documented library behaviour.

        Both ioc-finder and iocextract anchor hash patterns on word boundaries, so a 64-hex
        SHA-256 sitting inside an unbroken 96-character hex run is correctly NOT reported. This
        was verified directly against both libraries during the Phase 2 spike.
        """
        blob = "0011223344556677" + SHA256 + "8899aabbccddeeff"
        result = extract([f"Memory dump fragment: {blob}"])
        assert values_of(result, "sha256") == set()
        assert values_of(result, "sha512") == set()

    def test_eighty_character_hex_run_is_not_any_hash(self) -> None:
        hex80 = "aabbccddeeff00112233445566778899" * 2 + "aabbccddeeff0011"
        result = extract([f"Blob {hex80} end"])
        assert not any(ioc.type.startswith("sha") or ioc.type == "md5" for ioc in result.iocs)

    def test_lone_hash_with_no_context_is_flagged(self) -> None:
        result = extract([f"{SHA256}"])
        assert FLAG_HASH_WITHOUT_CONTEXT in get_ioc(result, "sha256", SHA256).flags

    def test_hash_with_keyword_context_is_not_flagged(self) -> None:
        result = extract([f"The malware sample had hash {SHA256} when analysed."])
        assert get_ioc(result, "sha256", SHA256).flags == []

    def test_hash_beside_another_hash_is_not_flagged(self) -> None:
        # A hash in a column of other hashes is well attributed even without prose.
        result = extract([f"{SHA256}\n{'b' * 64}\n{'c' * 64}"])
        assert get_ioc(result, "sha256", SHA256).flags == []


class TestWrappedHashRepair:
    def test_wrapped_sha256_is_rejoined(self) -> None:
        wrapped = f"{SHA256[:43]}\n{SHA256[43:]}"
        result = extract([f"File hashes:\n{wrapped}\nend of table"])
        assert values_of(result, "sha256") == {SHA256}

    def test_two_stacked_sha256_are_not_merged_into_a_sha512(self) -> None:
        other = "b" * 64
        result = extract([f"Sample hashes:\n{SHA256}\n{other}\n"])
        assert values_of(result, "sha512") == set()
        assert values_of(result, "sha256") == {SHA256, other}

    def test_wrapped_first_line_is_not_mistaken_for_a_sha1(self) -> None:
        """A 40-character first line of a wrapped SHA-256 must not become a SHA-1.

        This was a real defect: greedy segmentation cut at 40 because that is a valid SHA-1
        length, inventing a SHA-1 and losing the SHA-256.
        """
        wrapped = f"{SHA256[:40]}\n{SHA256[40:]}"
        result = extract([f"Hashes:\n{wrapped}\n"])
        assert values_of(result, "sha1") == set()
        assert values_of(result, "sha256") == {SHA256}

    def test_segmentation_prefers_more_pieces(self) -> None:
        assert segment_hex_fragments(["a" * 64, "b" * 64]) is None
        assert segment_hex_fragments(["a" * 40, "b" * 24]) == ["a" * 40 + "b" * 24]
        assert segment_hex_fragments(["a" * 43, "b" * 43, "c" * 42]) == [
            "a" * 43 + "b" * 43 + "c" * 42
        ]

    def test_segmentation_rejects_incomplete_runs(self) -> None:
        assert segment_hex_fragments(["a" * 10, "b" * 15]) is None
        assert segment_hex_fragments(["a" * 7]) is None

    def test_rejoin_leaves_ordinary_text_alone(self) -> None:
        text = "deadbeef and cafebabe are short hex values"
        assert rejoin_wrapped_hashes(text) == text

    def test_compact_hex_cell_rejoins_one_wrapped_hash(self) -> None:
        assert compact_hex_cell(f"{SHA256[:30]}\n{SHA256[30:]}") == SHA256

    def test_compact_hex_cell_leaves_two_whole_hashes_alone(self) -> None:
        cell = f"{SHA256}\n{'b' * 64}"
        assert compact_hex_cell(cell) == cell

    def test_compact_hex_cell_ignores_non_hex(self) -> None:
        assert compact_hex_cell("Akira ransomware") == "Akira ransomware"


class TestCves:
    def test_uppercase_and_lowercase_cves_normalize_to_uppercase(self) -> None:
        result = extract(["Exploited CVE-2024-3400 and cve-2021-44228 for access."])
        assert values_of(result, "cve") == {"CVE-2024-3400", "CVE-2021-44228"}

    def test_lowercase_cve_keeps_its_original_form(self) -> None:
        result = extract(["Targeting cve-2021-44228 in the wild."])
        assert get_ioc(result, "cve", "CVE-2021-44228").original_forms == ["cve-2021-44228"]


class TestIpFlags:
    def test_private_ip_is_flagged_not_dropped(self) -> None:
        result = extract(["Lateral movement to 10.1.2.3 and 192.168.5.5 internally."])
        assert FLAG_PRIVATE_IP in get_ioc(result, "ipv4", "10.1.2.3").flags
        assert FLAG_PRIVATE_IP in get_ioc(result, "ipv4", "192.168.5.5").flags

    def test_loopback_is_flagged(self) -> None:
        result = extract(["The listener bound to 127.0.0.1 locally."])
        assert FLAG_LOOPBACK in get_ioc(result, "ipv4", "127.0.0.1").flags

    def test_documentation_ip_is_flagged(self) -> None:
        result = extract(["Example C2 at 203.0.113.5 and 192.0.2.7 in the appendix."])
        assert FLAG_DOCUMENTATION_IP in get_ioc(result, "ipv4", "203.0.113.5").flags
        assert FLAG_DOCUMENTATION_IP in get_ioc(result, "ipv4", "192.0.2.7").flags

    def test_public_ip_is_not_flagged(self) -> None:
        result = extract(["C2 server at 45.66.77.88 received beacons."])
        assert get_ioc(result, "ipv4", "45.66.77.88").flags == []

    def test_version_number_is_flagged(self) -> None:
        result = extract(["Software version 1.2.3.4 was affected by this."])
        assert FLAG_VERSION_NUMBER in get_ioc(result, "ipv4", "1.2.3.4").flags

    def test_build_and_release_wording_also_flags(self) -> None:
        result = extract(["Agent build 9.8.7.6 shipped.", "Release v. 5.4.3.2 followed."])
        assert FLAG_VERSION_NUMBER in get_ioc(result, "ipv4", "9.8.7.6").flags
        assert FLAG_VERSION_NUMBER in get_ioc(result, "ipv4", "5.4.3.2").flags

    def test_ipv6_is_extracted_and_canonicalized(self) -> None:
        result = extract(["Beacon from 2001:0db8:85a3:0000:0000:8a2e:0370:7334 observed."])
        assert values_of(result, "ipv6") == {"2001:db8:85a3::8a2e:370:7334"}

    def test_invalid_ip_is_rejected_by_normalization(self) -> None:
        assert normalize_ip("999.1.1.1") is None
        assert normalize_ip("45.66.77.88") == "45.66.77.88"


class TestDomainFlags:
    def test_allowlisted_domain_is_flagged_benign(self) -> None:
        result = extract(["Apply the patch described by microsoft.com guidance."])
        assert FLAG_BENIGN_DOMAIN in get_ioc(result, "domain", "microsoft.com").flags

    def test_subdomain_of_allowlisted_parent_is_flagged(self) -> None:
        result = extract(["See docs.github.com for the advisory text."])
        assert FLAG_BENIGN_DOMAIN in get_ioc(result, "domain", "docs.github.com").flags

    def test_unknown_domain_is_not_flagged_benign(self) -> None:
        result = extract(["The C2 domain evil-c2-example.net was registered recently."])
        assert FLAG_BENIGN_DOMAIN not in get_ioc(result, "domain", "evil-c2-example.net").flags

    def test_filename_like_domain_is_flagged(self) -> None:
        result = extract(["The dropped file payload.zip contained the loader."])
        assert FLAG_FILENAME_LIKE_DOMAIN in get_ioc(result, "domain", "payload.zip").flags

    def test_publisher_domain_is_detected_from_urls(self) -> None:
        urls = [
            "https://example-vendor.com/a",
            "https://example-vendor.com/b",
            "https://example-vendor.com/c",
        ]
        assert find_publisher_domains(urls) == {"example-vendor.com"}

    def test_publisher_detection_needs_a_clear_majority(self) -> None:
        urls = ["https://a.com/1", "https://b.com/1", "https://c.com/1", "https://d.com/1"]
        assert find_publisher_domains(urls) == set()

    def test_publisher_domain_is_flagged_benign_in_a_document(self) -> None:
        page = (
            "Report by Example Vendor. See https://example-vendor.com/one and "
            "https://example-vendor.com/two and https://example-vendor.com/three. "
            "Also the host example-vendor.com is mentioned alone here."
        )
        result = extract([page])
        assert FLAG_BENIGN_DOMAIN in get_ioc(result, "domain", "example-vendor.com").flags


class TestUrlOnlyDomains:
    def test_domain_only_seen_as_url_host_is_not_reported_separately(self) -> None:
        result = extract(["Beacon to https://only-in-url-example.net/path here."])
        assert "only-in-url-example.net" not in values_of(result, "domain")
        assert "https://only-in-url-example.net/path" in values_of(result, "url")

    def test_domain_also_seen_alone_is_reported(self) -> None:
        page = (
            "Beacon to https://both-example.net/path and the domain both-example.net "
            "was registered in May."
        )
        result = extract([page])
        assert "both-example.net" in values_of(result, "domain")
        assert "https://both-example.net/path" in values_of(result, "url")

    def test_email_host_counts_as_a_standalone_appearance(self) -> None:
        page = "Contact at admin@shared-example.net and beacon to https://shared-example.net/x"
        result = extract([page])
        assert "shared-example.net" in values_of(result, "domain")


class TestDeduplication:
    def test_duplicate_across_pages_merges_with_both_pages(self) -> None:
        result = extract(
            [
                "First mention of C2 45.66.77.88 on page one.",
                "No indicators on this page.",
                "Second mention of C2 45.66.77.88 on page three.",
            ]
        )
        ioc = get_ioc(result, "ipv4", "45.66.77.88")
        assert ioc.pages == [1, 3]
        assert ioc.occurrences == 2

    def test_differently_defanged_forms_merge_into_one_ioc(self) -> None:
        result = extract(["Seen as evil-dup-example[.]com and also evil-dup-example[dot]com."])
        ioc = get_ioc(result, "domain", "evil-dup-example.com")
        assert len(ioc.original_forms) == 2
        assert ioc.occurrences == 2

    def test_contexts_are_capped_at_three(self) -> None:
        sentence = "C2 at 45.66.77.88 beaconed. "
        result = extract([sentence * 6])
        assert len(get_ioc(result, "ipv4", "45.66.77.88").contexts) == 3

    def test_counts_by_type_matches_the_ioc_list(self) -> None:
        result = extract([f"Sample hash {SHA256} and C2 45.66.77.88 using CVE-2024-3400."])
        assert sum(result.counts_by_type.values()) == result.total


class TestTables:
    def test_iocs_inside_a_table_are_found(self) -> None:
        tables = [
            [
                ["Type", "Value"],
                ["IP", "45.66.77.88"],
                ["SHA256", SHA256],
                ["Domain", "table-example[.]net"],
            ]
        ]
        result = extract(["Indicators of Compromise\n\nSee the table below."], tables)
        assert "45.66.77.88" in values_of(result, "ipv4")
        assert SHA256 in values_of(result, "sha256")
        assert "table-example.net" in values_of(result, "domain")

    def test_table_only_ioc_reports_no_page_number(self) -> None:
        tables = [[["Hash"], [SHA256]]]
        result = extract(["Nothing here."], tables)
        assert get_ioc(result, "sha256", SHA256).pages == []

    def test_wrapped_hash_in_a_table_cell_is_recovered(self) -> None:
        tables = [[["Hash"], [f"{SHA256[:33]}\n{SHA256[33:]}"]]]
        result = extract(["Nothing here."], tables)
        assert SHA256 in values_of(result, "sha256")


class TestSectionDetection:
    def test_heading_on_page_three_is_found(self) -> None:
        pages = [
            "Executive Summary\n\nThis report describes activity.",
            "Technical Analysis\n\nThe actor used living-off-the-land binaries.",
            "Indicators of Compromise\n\nThe following indicators were observed.\n45.66.77.88",
        ]
        assert find_ioc_section(make_doc(pages)) == [3]

    def test_in_ioc_section_is_set_on_iocs(self) -> None:
        pages = [
            "Overview\n\nNothing of interest on this page at all.",
            "Indicators of Compromise\n\nC2 server 45.66.77.88 was used.",
        ]
        result = extract(pages)
        assert result.ioc_section_found is True
        assert result.ioc_section_pages == [2]
        assert get_ioc(result, "ipv4", "45.66.77.88").in_ioc_section is True

    def test_section_closes_at_a_non_ioc_heading(self) -> None:
        pages = [
            "IOCs\n\n45.66.77.88\n\nMitigations\n\nApply patches promptly.",
            "References\n\nSee the vendor advisory for more detail.",
        ]
        assert find_ioc_section(make_doc(pages)) == [1]

    def test_ioc_subheading_does_not_close_the_section(self) -> None:
        pages = [
            "Indicators of Compromise\n\nSome preamble text here.\n"
            "Network Indicators\n\n45.66.77.88\n"
            "Host-Based Indicators\n\n" + SHA256
        ]
        assert find_ioc_section(make_doc(pages)) == [1]

    def test_no_heading_falls_back_to_density(self) -> None:
        filler = "This page contains ordinary prose about the intrusion. " * 20
        dense = " ".join(f"45.66.77.{n}" for n in range(1, 40))
        pages = [filler, filler, dense, filler]
        assert find_ioc_section(make_doc(pages)) == [3]

    def test_no_iocs_means_no_section(self) -> None:
        pages = ["Just prose.", "More prose with no indicators at all."]
        assert find_ioc_section(make_doc(pages)) == []

    def test_heading_like_accepts_titles_and_rejects_prose(self) -> None:
        assert is_heading_like("Indicators of Compromise") is True
        assert is_heading_like("INDICATORS OF COMPROMISE") is True
        assert is_heading_like("Mitigations:") is True
        assert (
            is_heading_like(
                "The threat actor used a wide variety of living off the land binaries "
                "throughout the intrusion to avoid detection."
            )
            is False
        )


class TestDisplay:
    def test_defang_neutralizes_urls(self) -> None:
        assert defang("http://evil.com/x", "url") == "hxxp://evil[.]com/x"
        assert defang("https://evil.com", "url") == "hxxps://evil[.]com"

    def test_defang_neutralizes_domains_ips_and_emails(self) -> None:
        assert defang("evil.com", "domain") == "evil[.]com"
        assert defang("45.66.77.88", "ipv4") == "45[.]66[.]77[.]88"
        assert defang("a@evil.com", "email") == "a[at]evil[.]com"

    def test_defang_leaves_hashes_and_cves_readable(self) -> None:
        assert defang(SHA256, "sha256") == SHA256
        assert defang("CVE-2024-3400", "cve") == "CVE-2024-3400"

    def test_format_pages_marks_table_only_values(self) -> None:
        assert format_pages([]) == "table"
        assert format_pages([1, 3]) == "1, 3"


class TestNormalizeUrl:
    def test_scheme_and_host_lowercased_path_preserved(self) -> None:
        assert normalize_url("HTTP://EVIL.COM/Path") == "http://evil.com/Path"

    def test_trailing_punctuation_is_stripped(self) -> None:
        assert normalize_url("http://evil.com/x.") == "http://evil.com/x"

    def test_value_without_scheme_is_rejected(self) -> None:
        assert normalize_url("evil.com/path") is None


class TestExtractionResult:
    def test_document_hash_is_carried_through(self) -> None:
        doc = make_doc(["C2 at 45.66.77.88 observed."])
        assert extract_iocs(doc).document_sha256 == doc.sha256

    def test_clean_excludes_flagged(self) -> None:
        result = extract(["Internal host 10.0.0.1 and C2 45.66.77.88 both seen."])
        clean_values = {ioc.value for ioc in result.clean()}
        assert "45.66.77.88" in clean_values
        assert "10.0.0.1" not in clean_values

    def test_empty_document_yields_nothing(self) -> None:
        result = extract(["No indicators of any kind appear in this prose."])
        assert result.total == 0
        assert result.counts_by_type == {}

    def test_extraction_is_deterministic(self) -> None:
        pages = [f"Sample {SHA256} beaconed to hxxp://evil[.]com/x from 45.66.77.88."]
        first = extract(pages)
        second = extract(pages)
        assert [ioc.value for ioc in first.iocs] == [ioc.value for ioc in second.iocs]


@pytest.mark.parametrize(
    "text,expected_type,expected_value",
    [
        ("Observed hxxp://evil[.]com/a today.", "url", "http://evil.com/a"),
        ("Observed hxxps://bad(.)org today.", "url", "https://bad.org"),
        ("Observed 192.168[.]1[.]1 today.", "ipv4", "192.168.1.1"),
        ("Observed user[at]evil[.]com today.", "email", "user@evil.com"),
        ("Observed evil[dot]net today.", "domain", "evil.net"),
    ],
)
def test_required_refang_cases(text: str, expected_type: str, expected_value: str) -> None:
    """The exact edge cases named in the Phase 2 specification."""
    result = extract([text])
    assert expected_value in values_of(result, expected_type)
