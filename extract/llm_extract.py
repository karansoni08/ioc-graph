"""Orchestration: chunk, call the model, validate, merge, cache.

No API call happens unless the caller asks for one, and a cache hit makes none at all. Cost is
tracked per chunk and totalled so the UI can show what a report actually cost.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from config import Settings, get_settings
from ingest.models import Document
from llm.base import LLMError, LLMProvider
from llm.pricing import estimate_cost

from .chunking import Chunk, chunk_document, estimate_tokens
from .models import IOCExtraction
from .prompts import PROMPT_VERSION, build_system_prompt, build_user_message, make_nonce
from .schema import Entity, ExtractionResult, Relationship, extraction_json_schema
from .validate import ValidationReport, validate

MAX_EVIDENCE_PER_ENTITY = 5


@dataclass
class ChunkUsage:
    """Token and cost accounting for one chunk."""

    index: int
    pages: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0
    failed: bool = False
    error: str = ""


@dataclass
class MergedEntity:
    """An entity after merging across chunks, carrying every quote that supported it."""

    name: str
    type: str
    aliases: list[str] = field(default_factory=list)
    descriptions: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@dataclass
class MergedRelationship:
    source: str
    relation: str
    target: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class ReportAnalysis:
    """The full result of analysing one report with the LLM."""

    document_sha256: str
    model: str
    prompt_version: str
    entities: list[MergedEntity] = field(default_factory=list)
    relationships: list[MergedRelationship] = field(default_factory=list)
    validation: ValidationReport = field(default_factory=ValidationReport)
    chunk_usage: list[ChunkUsage] = field(default_factory=list)
    chunks_processed: int = 0
    chunks_skipped: int = 0
    duration_ms: int = 0
    from_cache: bool = False
    # Guardrail findings for this report (guards.pipeline.SecurityReport.to_dict()).
    security: dict[str, Any] = field(default_factory=dict)

    @property
    def input_tokens(self) -> int:
        return sum(usage.input_tokens for usage in self.chunk_usage)

    @property
    def output_tokens(self) -> int:
        return sum(usage.output_tokens for usage in self.chunk_usage)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def cost_usd(self) -> float:
        """Zero on a cache hit, because no call was made."""
        return 0.0 if self.from_cache else sum(usage.cost_usd for usage in self.chunk_usage)

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_sha256": self.document_sha256,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "entities": [asdict(entity) for entity in self.entities],
            "relationships": [asdict(rel) for rel in self.relationships],
            "validation": {
                "entities_proposed": self.validation.entities_proposed,
                "relationships_proposed": self.validation.relationships_proposed,
                "entities_kept": self.validation.entities_kept,
                "relationships_kept": self.validation.relationships_kept,
                "dropped": [asdict(item) for item in self.validation.dropped],
                "schema_errors": self.validation.schema_errors,
                "retried": self.validation.retried,
            },
            "chunk_usage": [asdict(usage) for usage in self.chunk_usage],
            "chunks_processed": self.chunks_processed,
            "chunks_skipped": self.chunks_skipped,
            "duration_ms": self.duration_ms,
            "security": self.security,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ReportAnalysis:
        validation = ValidationReport(
            entities_proposed=payload["validation"]["entities_proposed"],
            relationships_proposed=payload["validation"]["relationships_proposed"],
            entities_kept=payload["validation"]["entities_kept"],
            relationships_kept=payload["validation"]["relationships_kept"],
            schema_errors=list(payload["validation"].get("schema_errors", [])),
            retried=payload["validation"].get("retried", False),
        )
        from .validate import DroppedItem

        validation.dropped = [
            DroppedItem(**item) for item in payload["validation"].get("dropped", [])
        ]
        return cls(
            document_sha256=payload["document_sha256"],
            model=payload["model"],
            prompt_version=payload["prompt_version"],
            entities=[MergedEntity(**entity) for entity in payload["entities"]],
            relationships=[MergedRelationship(**rel) for rel in payload["relationships"]],
            validation=validation,
            chunk_usage=[ChunkUsage(**usage) for usage in payload.get("chunk_usage", [])],
            chunks_processed=payload.get("chunks_processed", 0),
            chunks_skipped=payload.get("chunks_skipped", 0),
            duration_ms=payload.get("duration_ms", 0),
            security=payload.get("security", {}),
            from_cache=True,
        )


def cache_key(sha256: str, model: str) -> str:
    """Cache identity: document, model and prompt version together.

    The prompt version is included so that changing the instructions invalidates the cache,
    rather than silently serving results produced by different rules.
    """
    return f"{sha256}_{model}_{PROMPT_VERSION}"


def _cache_path(settings: Settings, key: str) -> Path:
    return Path(settings.data_dir) / "cache" / f"{key}.json"


def load_cached(
    sha256: str,
    model: str,
    settings: Settings | None = None,
    store: Any | None = None,
) -> ReportAnalysis | None:
    """Return a cached analysis, or None.

    Goes through the storage interface when one is supplied, so Phase 7 can share the cache
    across the deployed app; falls back to a direct file read otherwise.
    """
    key = cache_key(sha256, model)

    if store is not None:
        payload = store.cache_get(key)
        if payload is None:
            return None
        try:
            return ReportAnalysis.from_dict(payload)
        except (KeyError, TypeError):
            return None

    settings = settings or get_settings()
    path = _cache_path(settings, key)
    if not path.exists():
        return None
    try:
        return ReportAnalysis.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, KeyError, TypeError):
        # A corrupt or outdated cache entry is not worth failing over; re-analyse instead.
        return None


def save_cached(
    analysis: ReportAnalysis,
    settings: Settings | None = None,
    store: Any | None = None,
) -> None:
    key = cache_key(analysis.document_sha256, analysis.model)

    if store is not None:
        store.cache_set(key, analysis.to_dict())
        return

    settings = settings or get_settings()
    path = _cache_path(settings, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(analysis.to_dict(), indent=2), encoding="utf-8")


def candidate_indicators_for(chunk: Chunk, ioc_extraction: IOCExtraction) -> list[str]:
    """Indicators found by regex on this chunk's pages.

    Scoped to the chunk's pages so the model is not handed the whole report's indicators for a
    chunk that cannot possibly quote them.
    """
    if not chunk.pages:
        values = [ioc.value for ioc in ioc_extraction.iocs]
    else:
        pages = set(chunk.pages)
        values = [
            ioc.value
            for ioc in ioc_extraction.iocs
            if not ioc.pages or pages.intersection(ioc.pages)
        ]
    # Stable order so the prompt is deterministic, which keeps caching meaningful.
    return sorted(set(values))


def estimate_max_cost(
    chunks: list[Chunk], model: str, max_tokens: int, system_overhead_tokens: int = 500
) -> float:
    """Worst-case cost: every chunk sent, every response using the full output budget."""
    input_tokens = sum(chunk.estimated_tokens + system_overhead_tokens for chunk in chunks)
    output_tokens = max_tokens * len(chunks)
    return estimate_cost(model, input_tokens, output_tokens)


def _merge_into(
    entities: dict[str, MergedEntity],
    relationships: dict[tuple[str, str, str], MergedRelationship],
    result: ExtractionResult,
) -> None:
    """Merge one chunk's validated result into the running totals."""
    for entity in result.entities:
        key = f"{entity.type}::{entity.name.casefold()}"
        existing = entities.get(key)
        if existing is None:
            entities[key] = MergedEntity(
                name=entity.name,
                type=entity.type,
                aliases=list(entity.aliases),
                descriptions=[entity.description] if entity.description else [],
                evidence=[entity.evidence],
            )
            continue
        for alias in entity.aliases:
            if alias not in existing.aliases:
                existing.aliases.append(alias)
        if entity.description and entity.description not in existing.descriptions:
            existing.descriptions.append(entity.description)
        if entity.evidence not in existing.evidence:
            if len(existing.evidence) < MAX_EVIDENCE_PER_ENTITY:
                existing.evidence.append(entity.evidence)

    for rel in result.relationships:
        key = (rel.source.casefold(), rel.relation, rel.target.casefold())
        existing_rel = relationships.get(key)
        if existing_rel is None:
            relationships[key] = MergedRelationship(
                source=rel.source,
                relation=rel.relation,
                target=rel.target,
                evidence=[rel.evidence],
            )
        elif rel.evidence not in existing_rel.evidence:
            if len(existing_rel.evidence) < MAX_EVIDENCE_PER_ENTITY:
                existing_rel.evidence.append(rel.evidence)


def run_llm_extraction(
    doc: Document,
    ioc_extraction: IOCExtraction,
    provider: LLMProvider,
    settings: Settings | None = None,
    model: str | None = None,
    max_chunks: int | None = None,
    max_tokens: int = 4000,
    use_cache: bool = True,
    progress: Callable[[int, int, str], None] | None = None,
    store: Any | None = None,
    security_report: Any | None = None,
) -> ReportAnalysis:
    """Analyse a document with the LLM and return the validated result.

    `progress(index, total, label)` is called before each chunk so the UI can show status.
    """
    settings = settings or get_settings()
    model = model or settings.anthropic_model
    max_chunks = max_chunks if max_chunks is not None else settings.max_chunks_per_report

    if use_cache:
        cached = load_cached(doc.sha256, model, settings, store=store)
        if cached is not None:
            return cached

    started = time.monotonic()
    chunks, skipped = chunk_document(doc, ioc_extraction, max_chunks=max_chunks)

    # Guardrail layer 1c: a chunk carrying a HIGH-severity injection pattern is never sent.
    # The cheapest way to defeat an injection is not to pass it to the model at all.
    from guards.pipeline import SecurityReport, screen_chunks

    security = security_report if security_report is not None else SecurityReport()
    chunks = screen_chunks(chunks, security, block_on=settings.injection_block_on)

    schema = extraction_json_schema()

    entities: dict[str, MergedEntity] = {}
    relationships: dict[tuple[str, str, str], MergedRelationship] = {}
    combined_report = ValidationReport()
    usages: list[ChunkUsage] = []

    for chunk in chunks:
        if progress is not None:
            progress(chunk.index, len(chunks), chunk.page_label)

        usage = ChunkUsage(index=chunk.index, pages=chunk.page_label)
        candidates = candidate_indicators_for(chunk, ioc_extraction)
        nonce = make_nonce()
        system = build_system_prompt(nonce)
        user = build_user_message(chunk.text, candidates, nonce, chunk.page_label)

        result, chunk_report, chunk_usage = _analyse_chunk(
            provider=provider,
            system=system,
            user=user,
            schema=schema,
            model=model,
            max_tokens=max_tokens,
            chunk_text=chunk.text,
            ioc_extraction=ioc_extraction,
            usage=usage,
        )

        if chunk_report.suspicious:
            security.suspicious_chunks.append(chunk.index)

        _merge_into(entities, relationships, result)
        combined_report.merge(chunk_report)
        usages.append(chunk_usage)

    analysis = ReportAnalysis(
        document_sha256=doc.sha256,
        model=model,
        prompt_version=PROMPT_VERSION,
        entities=list(entities.values()),
        relationships=list(relationships.values()),
        validation=combined_report,
        chunk_usage=usages,
        chunks_processed=len(chunks),
        chunks_skipped=skipped + len(security.excluded_chunks),
        security=security.to_dict(),
        duration_ms=int((time.monotonic() - started) * 1000),
        from_cache=False,
    )

    if use_cache:
        save_cached(analysis, settings, store=store)

    return analysis


def _analyse_chunk(
    provider: LLMProvider,
    system: str,
    user: str,
    schema: dict[str, Any],
    model: str,
    max_tokens: int,
    chunk_text: str,
    ioc_extraction: IOCExtraction,
    usage: ChunkUsage,
) -> tuple[ExtractionResult, ValidationReport, ChunkUsage]:
    """One chunk, with exactly one retry on malformed output."""
    attempt_user = user
    last_error = ""

    for attempt in range(2):
        try:
            response = provider.extract_structured(
                system=system,
                user=attempt_user,
                schema=schema,
                model=model,
                max_tokens=max_tokens,
            )
        except LLMError as exc:
            last_error = str(exc)
            if attempt == 0:
                # Retry once with the problem described, per the Phase 3 spec.
                attempt_user = (
                    f"{user}\n\nYour previous response could not be used: {last_error}\n"
                    "Return only JSON matching the schema."
                )
                continue
            usage.failed = True
            usage.error = last_error
            report = ValidationReport(chunk_failed=True)
            report.drop("chunk", "schema", f"provider error: {last_error}")
            report.retried = True
            return ExtractionResult(), report, usage

        usage.input_tokens += response.input_tokens
        usage.output_tokens += response.output_tokens
        usage.latency_ms += response.latency_ms
        usage.cost_usd += estimate_cost(model, response.input_tokens, response.output_tokens)

        result, report = validate(response.data, chunk_text, ioc_extraction)

        if report.chunk_failed and attempt == 0:
            attempt_user = (
                f"{user}\n\nYour previous response failed validation: "
                f"{'; '.join(report.schema_errors) or 'schema mismatch'}\n"
                "Return only JSON matching the schema."
            )
            report.retried = True
            continue

        if attempt == 1:
            report.retried = True
        return result, report, usage

    # Unreachable: both attempts either return or fall through to the error path above.
    return ExtractionResult(), ValidationReport(chunk_failed=True), usage
