"""
Threat Reasoner Agent — Hybrid RAG + ATT&CK Tactical Inference
================================================================
Based on CTI-Thinker (Springer Cybersecurity, Jan 2026) —
Hybrid KG + Vector retrieval with ATT&CK semantic alignment.

Combines:
  1. Knowledge Graph semantic search (embedding-based)
  2. FAISS vector similarity search (MMR diversity)
  3. Reciprocal Rank Fusion (RRF) for hybrid context
  4. LLM grounded inference (LiteLLM)
  5. ATT&CK TTP mapping with source attribution

Fixes addressed:
  - G1.1: Vector retrieval not wired into reasoning
  - G1.2: No retrieval-augmented prompt construction
  - G2.1: No hybrid fusion of KG + vector results
  - I3:   "GraphRAG" without retrieval
"""
from __future__ import annotations
import time
from typing import Any
from dataclasses import dataclass, field
import structlog

log = structlog.get_logger()


@dataclass
class ThreatAnalysis:
    """Output from the Threat Reasoner Agent."""
    raw_analysis: dict[str, Any] = field(default_factory=dict)
    ttps: list[dict] = field(default_factory=list)
    stix_objects: list[dict] = field(default_factory=list)
    model_used: str = ""
    confidence: float = 0.0
    kg_context_used: int = 0
    vec_context_used: int = 0
    latency_ms: float = 0.0
    # NEW: Source attribution — tracks which retrieved passages grounded the analysis
    retrieval_result: dict[str, Any] = field(default_factory=dict)
    source_attributions: list[dict] = field(default_factory=list)


class ThreatReasonerAgent:
    """
    Hybrid RAG-powered threat analysis combining:
    1. Knowledge graph semantic search (KG Builder)
    2. FAISS vector similarity search (RAG module)
    3. Reciprocal Rank Fusion for hybrid context merging
    4. LLM grounded inference (LiteLLM)
    5. ATT&CK TTP mapping with source attribution
    """

    def __init__(self) -> None:
        self.analysis_count = 0

    def reason(self, query: str, kg_builder, llm_engine,
               context: dict | None = None) -> ThreatAnalysis:
        """Run full Hybrid RAG reasoning pipeline."""
        start = time.time()
        self.analysis_count += 1
        result = ThreatAnalysis()

        # ── Step 1: Hybrid Retrieval (KG + Vector with RRF) ──────
        retrieval = self._hybrid_retrieve(query, kg_builder)
        result.kg_context_used = retrieval.kg_results_count
        result.vec_context_used = retrieval.vec_results_count
        result.retrieval_result = retrieval.to_dict()
        result.source_attributions = retrieval.source_attributions

        # ── Step 2: Skip extraction — orchestrator already called ──
        # extract_triples(raw_input, source="pipeline") at Stage 3.
        # A4 fix: removed duplicate call that double-counted KG triples.
        new_triples = []

        # ── Step 3: Build grounded prompt with retrieved context ─
        grounded_query = self._build_grounded_prompt(
            query, retrieval.context_text
        )

        # ── Step 4: LLM inference via existing engine ────────────
        analysis = llm_engine.analyse_threat(grounded_query, query[:2000])
        result.raw_analysis = analysis

        # ── Step 5: TTP extraction from KG triples + analysis ────
        kg_triples = kg_builder.semantic_search(query, k=5)
        result.ttps = self._extract_ttps(analysis, kg_triples, new_triples)

        # ── Step 6: STIX generation ──────────────────────────────
        stix_context = query[:2000]
        result.stix_objects = llm_engine.get_stix_objects(query, stix_context)

        # ── Step 7: Confidence estimation ────────────────────────
        result.confidence = self._estimate_confidence(
            analysis, kg_triples, result.ttps, retrieval
        )
        result.model_used = getattr(llm_engine, '_last_model', 'unknown')
        result.latency_ms = (time.time() - start) * 1000

        log.info("threat_reasoning_complete",
                 confidence=result.confidence,
                 ttps=len(result.ttps),
                 kg_context=result.kg_context_used,
                 vec_context=result.vec_context_used,
                 retrieval_mode=retrieval.mode)

        return result

    def _hybrid_retrieve(self, query: str, kg_builder):
        """
        Execute hybrid retrieval via agents.hybrid_retriever.

        Uses two-path retrieval (FAISS dense + KG graph traversal)
        with Reciprocal Rank Fusion for score merging.
        """
        try:
            from agents.hybrid_retriever import get_hybrid_retriever
            retriever = get_hybrid_retriever()
            return retriever.retrieve(query, kg_builder=kg_builder)
        except Exception as e:
            log.warning("hybrid_retrieval_error_fallback", error=str(e))
            from agents.hybrid_retriever import RetrievalResult
            return RetrievalResult(mode="fallback")

    def _build_grounded_prompt(self, query: str, retrieved_context: str) -> str:
        """
        Build a retrieval-augmented prompt grounded in retrieved context.

        This is the core of RAG: the LLM receives [Retrieved Context] + [Query]
        rather than the raw query alone.
        """
        if retrieved_context:
            return (
                f"You are a Cyber Threat Intelligence analyst. "
                f"Use ONLY the following verified context to ground your analysis. "
                f"Do not fabricate CVE numbers, ATT&CK technique IDs, or threat actor names. "
                f"If the context does not contain relevant information, say so.\n\n"
                f"{retrieved_context}\n\n"
                f"─── Threat Report to Analyse ───\n\n"
                f"{query}"
            )
        return query

    def _extract_ttps(self, analysis: dict, kg_triples, new_triples) -> list[dict]:
        """Extract TTPs from analysis and KG triples."""
        ttps = []
        seen_ids = set()

        # From analysis result
        inner = analysis.get("analysis", {})
        if isinstance(inner, dict) and inner.get("ttps"):
            for ttp in inner["ttps"]:
                tid = ttp.get("id", "")
                if tid and tid not in seen_ids:
                    ttps.append(ttp)
                    seen_ids.add(tid)

        # From KG triples
        for triple in list(kg_triples) + list(new_triples):
            if triple.technique_id and triple.technique_id not in seen_ids:
                ttps.append({
                    "id": triple.technique_id,
                    "name": triple.technique_name,
                    "tactic": "See ATT&CK",
                    "confidence": triple.confidence,
                    "source": "knowledge_graph",
                })
                seen_ids.add(triple.technique_id)

        return ttps

    def _estimate_confidence(
        self, analysis: dict, kg_triples, ttps, retrieval,
    ) -> float:
        """Estimate analysis confidence based on evidence quality."""
        score = 0.3  # base

        # KG evidence boosts confidence
        if kg_triples:
            score += min(0.15, len(kg_triples) * 0.03)

        # Vector retrieval evidence boosts confidence
        if retrieval.vec_results_count > 0:
            score += min(0.15, retrieval.vec_results_count * 0.03)

        # Hybrid fusion bonus (both sources present)
        if retrieval.kg_results_count > 0 and retrieval.vec_results_count > 0:
            score += 0.05

        # TTP mapping boosts confidence
        if ttps:
            score += min(0.15, len(ttps) * 0.04)

        # Analysis quality
        inner = analysis.get("analysis", {})
        if isinstance(inner, dict):
            if inner.get("summary"): score += 0.1
            if inner.get("red_flags"): score += 0.05
            if inner.get("iocs"): score += 0.05

        return min(1.0, score)


_reasoner: ThreatReasonerAgent | None = None
def get_threat_reasoner() -> ThreatReasonerAgent:
    global _reasoner
    if _reasoner is None:
        _reasoner = ThreatReasonerAgent()
    return _reasoner
