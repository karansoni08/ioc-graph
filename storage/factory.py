"""Storage backend selection, driven by `STORAGE_BACKEND`."""

from __future__ import annotations

from functools import lru_cache

from config import Settings, get_settings

from .base import GraphStore

KNOWN_BACKENDS = ("local", "supabase")


@lru_cache(maxsize=4)
def _build(backend: str, data_dir: str) -> GraphStore:
    if backend == "local":
        from .local import LocalGraphStore

        return LocalGraphStore(data_dir)
    if backend == "supabase":
        # Phase 7. Imported lazily so the Supabase client is not a hard dependency locally.
        from .supabase_store import SupabaseGraphStore

        return SupabaseGraphStore()
    raise ValueError(f"Unknown STORAGE_BACKEND '{backend}'. Known: {KNOWN_BACKENDS}.")


def get_store(settings: Settings | None = None) -> GraphStore:
    settings = settings or get_settings()
    return _build(settings.storage_backend, settings.data_dir)
