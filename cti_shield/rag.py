"""
RAG Module — Retrieval-Augmented Generation
============================================
Embeds CTI text using sentence-transformers, indexes in FAISS,
and retrieves relevant context using MMR for diversity.
"""
from __future__ import annotations
import json, time
from pathlib import Path
from typing import Optional
import numpy as np
import structlog
from cachetools import TTLCache  # type: ignore[import-untyped]
from config import FAISS_DIR, settings

logger = structlog.get_logger(__name__)
_faiss = None
_model = None

def _get_faiss():
    global _faiss
    if _faiss is None:
        import faiss
        _faiss = faiss
    return _faiss

def _get_embedding_model():
    global _model
    if _model is None:
        import os
        os.environ.setdefault("OMP_NUM_THREADS", "1")
        os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
        from cti_shield.model_cache import get_sentence_transformer
        # Force CPU to avoid MPS deadlocks on Apple Silicon in
        # subprocess/threaded contexts (e.g. research ablation runs).
        _model = get_sentence_transformer(settings.rag.embedding_model, device="cpu")
    return _model

_query_cache: TTLCache = TTLCache(maxsize=256, ttl=settings.rag.cache_ttl_seconds)

class VectorStore:
    """FAISS-backed vector store for CTI documents."""
    def __init__(self) -> None:
        self.faiss = _get_faiss()
        self.index = None
        self.documents: list[dict] = []
        self.dimension: int = 384
        self._index_path = FAISS_DIR / "index.faiss"
        self._meta_path = FAISS_DIR / "metadata.json"

    def build_index(self, chunks: list[dict]) -> None:
        if not chunks:
            return
        model = _get_embedding_model()
        texts = [c["text"] for c in chunks]
        embeddings = model.encode(texts, normalize_embeddings=True, batch_size=64)
        self.dimension = embeddings.shape[1]
        self.index = self.faiss.IndexFlatIP(self.dimension)
        emb_np = np.array(embeddings, dtype=np.float32)
        self.index.add(emb_np)  # type: ignore[call-arg]
        self.documents = chunks
        logger.info("FAISS index built", vectors=self.index.ntotal)

    def save(self) -> None:
        if self.index is None:
            return
        self.faiss.write_index(self.index, str(self._index_path))
        with open(self._meta_path, "w") as f:
            json.dump(self.documents, f, indent=2)

    def load(self) -> bool:
        if not self._index_path.exists():
            return False
        try:
            self.index = self.faiss.read_index(str(self._index_path))
            with open(self._meta_path) as f:
                self.documents = json.load(f)
            self.dimension = self.index.d
            return True
        except Exception:
            return False

    def search(self, query: str, top_k: int | None = None, use_mmr: bool = True, mmr_lambda: float | None = None) -> list[dict]:
        if self.index is None or self.index.ntotal == 0:
            return []
        top_k = top_k or settings.rag.top_k
        mmr_lambda = mmr_lambda if mmr_lambda is not None else settings.rag.mmr_lambda
        cache_key = f"{query}::{top_k}::{use_mmr}"
        if cache_key in _query_cache:
            return _query_cache[cache_key]
        model = _get_embedding_model()
        qe_raw = model.encode([query], normalize_embeddings=True)
        qe = np.array(qe_raw, dtype=np.float32)
        if use_mmr:
            results = self._mmr_search(qe, top_k, mmr_lambda)
        else:
            scores, indices = self.index.search(qe, top_k)
            results = []
            for s, i in zip(scores[0], indices[0]):
                if i < 0: continue
                doc = self.documents[i].copy()
                doc["score"] = float(s)
                doc["rank"] = len(results) + 1
                results.append(doc)
        _query_cache[cache_key] = results
        return results

    def _mmr_search(self, qe: np.ndarray, top_k: int, lam: float) -> list[dict]:
        assert self.index is not None
        ck = min(top_k * 4, self.index.ntotal)
        scores, indices = self.index.search(qe, ck)
        valid = [(s, i) for s, i in zip(scores[0], indices[0]) if i >= 0]
        if not valid:
            return []
        model = _get_embedding_model()
        ce = model.encode([self.documents[i]["text"] for _, i in valid], normalize_embeddings=True)
        selected, remaining = [], list(range(len(valid)))
        for _ in range(min(top_k, len(valid))):
            best_s, best_i = -float("inf"), -1
            for ri in remaining:
                rel = float(valid[ri][0])
                ms = float(np.max(np.dot(ce[selected], ce[ri]))) if selected else 0.0
                sc = lam * rel - (1 - lam) * ms
                if sc > best_s:
                    best_s, best_i = sc, ri
            if best_i >= 0:
                selected.append(best_i)
                remaining.remove(best_i)
        results = []
        for rank, si in enumerate(selected):
            s, di = valid[si]
            doc = self.documents[di].copy()
            doc["score"] = float(s)
            doc["rank"] = rank + 1
            results.append(doc)
        return results

    @property
    def total_vectors(self) -> int:
        return self.index.ntotal if self.index else 0

_store: VectorStore | None = None

def get_vector_store() -> VectorStore:
    global _store
    if _store is None:
        _store = VectorStore()
        _store.load()
    return _store

def build_and_save(chunks: list[dict]) -> VectorStore:
    store = get_vector_store()
    store.build_index(chunks)
    store.save()
    return store

def search(query: str, top_k: int = 5) -> list[dict]:
    return get_vector_store().search(query, top_k=top_k)
