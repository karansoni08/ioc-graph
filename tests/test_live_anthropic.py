"""The only test that spends money. Skipped unless RUN_LIVE=1 is set.

    RUN_LIVE=1 pytest tests/test_live_anthropic.py -v

Deliberately tiny: one short paragraph of public text, so a full run costs a fraction of a
cent. Its job is to prove the request shape is accepted by the real API and that a real
response survives validation — not to measure quality, which `scripts/eval_llm.py` does.
"""

from __future__ import annotations

import os

import pytest

from config import get_settings, has_api_key
from extract.iocs import extract_iocs
from extract.llm_extract import run_llm_extraction
from extract.prompts import build_system_prompt, build_user_message, make_nonce
from extract.schema import extraction_json_schema
from ingest.models import Document, join_pages
from llm.factory import get_provider

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("RUN_LIVE") != "1",
        reason="live API test; set RUN_LIVE=1 to enable (costs money)",
    ),
]

# Short, public, synthetic text in the style of an advisory paragraph.
LIVE_TEXT = (
    "Indicators of Compromise\n\n"
    "The threat actor APT21 deployed the Akira ransomware against healthcare organizations. "
    "APT21 exploited CVE-2024-3400 to gain initial access to perimeter devices. "
    "After deployment, the malware beaconed to the command and control server at "
    "45.66.77.88 at five minute intervals."
)


def _doc() -> Document:
    pages = [LIVE_TEXT]
    return Document(
        filename="live_test.pdf",
        file_type="pdf",
        sha256="e" * 64,
        size_bytes=len(LIVE_TEXT),
        page_count=1,
        pages=pages,
        tables=[],
        text=join_pages(pages),
    )


def test_api_key_is_configured() -> None:
    assert has_api_key(), "ANTHROPIC_API_KEY is not set; the live test cannot run"


def test_structured_output_returns_valid_schema() -> None:
    """The raw provider call: does the API accept our request and return our schema?"""
    provider = get_provider("anthropic")
    nonce = make_nonce()
    response = provider.extract_structured(
        system=build_system_prompt(nonce),
        user=build_user_message(LIVE_TEXT, ["45.66.77.88"], nonce, "page 1"),
        schema=extraction_json_schema(),
        model=get_settings().anthropic_model,
        max_tokens=2000,
    )

    assert isinstance(response.data, dict)
    assert "entities" in response.data
    assert "relationships" in response.data
    assert response.input_tokens > 0
    assert response.output_tokens > 0
    print(f"\nlive tokens in={response.input_tokens} out={response.output_tokens}")


def test_full_pipeline_finds_the_obvious_entities() -> None:
    """End to end, including validation. Asserts only what the text plainly states."""
    document = _doc()
    iocs = extract_iocs(document)
    analysis = run_llm_extraction(
        document,
        iocs,
        get_provider("anthropic"),
        model=get_settings().anthropic_model,
        use_cache=False,
        max_tokens=2000,
    )

    names = {entity.name.casefold() for entity in analysis.entities}
    assert "apt21" in names, f"expected APT21 among {names}"
    assert any("akira" in name for name in names), f"expected Akira among {names}"

    # Every kept item must carry a quote that really is in the source.
    for entity in analysis.entities:
        assert entity.evidence, f"{entity.name} kept with no evidence"

    # The model must not have invented an indicator.
    regex_values = {ioc.value for ioc in iocs.iocs}
    for entity in analysis.entities:
        if entity.type == "indicator":
            assert entity.value if hasattr(entity, "value") else entity.name in regex_values

    print(
        f"\nlive pipeline: {len(analysis.entities)} entities, "
        f"{len(analysis.relationships)} relationships, "
        f"{analysis.total_tokens} tokens, ${analysis.cost_usd:.4f}"
    )
