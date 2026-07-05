"""Process-wide cache for embedding / cross-encoder models.

Several agents (hallucination guard, KG builder, hybrid retriever, source
attributor, RAGAS evaluator) independently load the *same* sentence-transformer
and cross-encoder checkpoints. Before this module, ``all-MiniLM-L6-v2`` was
instantiated in five separate places — and ``kg_builder._embedding_search``
re-loaded it on *every* call from a local variable. On a 10-advisory run that
produced dozens of redundant model loads.

Routing every load through these ``lru_cache``-d helpers means each unique
checkpoint is loaded **once** per process and shared everywhere, cutting both
wall-clock time and memory.
"""
from functools import lru_cache
from typing import Any

import structlog

log = structlog.get_logger()


@lru_cache(maxsize=8)
def get_sentence_transformer(name: str = "all-MiniLM-L6-v2", device: str = "cpu") -> Any:
    """Return a cached SentenceTransformer; load once per (name, device)."""
    import torch
    torch.set_num_threads(1)  # avoid OMP SIGSEGV on macOS ARM64
    from sentence_transformers import SentenceTransformer
    log.info("model_cache_load", kind="sentence_transformer", model=name)
    return SentenceTransformer(name, device=device)


@lru_cache(maxsize=8)
def get_cross_encoder(name: str, device: str = "cpu") -> Any:
    """Return a cached CrossEncoder; load once per (name, device)."""
    from sentence_transformers import CrossEncoder
    log.info("model_cache_load", kind="cross_encoder", model=name)
    return CrossEncoder(name, device=device)
