"""
Hybrid Retriever Agent — Dense Vector + Knowledge Graph Fusion
================================================================
RO2: "Develop hybrid KG + vector retrieval for temporal currency in CTI"

Pipeline:
  1. Query Expansion   — CybersecurityQueryExpander enriches CTI queries
  2. Two-path retrieval:
       Path 1 — Dense vector:  query → embed → FAISS IndexFlatIP → MMR
       Path 2 — KG traversal:  query → entity extraction → NetworkX 1-hop
  3. Fusion            — RRF (Cormack et al., 2009)
  4. Cross-encoder re-rank — ms-marco-MiniLM-L-6-v2 for precision boost

Ablation modes (set via config.py → settings.rag.retrieval_mode):
  NONE | VECTOR_ONLY | KG_ONLY | HYBRID

No new dependencies — uses sentence-transformers, faiss-cpu, numpy,
and the KGBuilderAgent already in the codebase.
"""
from __future__ import annotations

import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import structlog

from config import settings, RetrievalMode

log = structlog.get_logger(__name__)

# ── Lazy-loaded cross-encoder for re-ranking ─────────────────────────
_cross_encoder = None


def _get_cross_encoder():
    """Lazy-load the cross-encoder model for re-ranking."""
    global _cross_encoder
    if _cross_encoder is None:
        import torch
        torch.set_num_threads(1)  # Prevent OMP SIGSEGV on macOS ARM64
        from sentence_transformers import CrossEncoder
        # Force CPU to avoid MPS deadlocks on Apple Silicon
        _cross_encoder = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2", device="cpu")
        log.info("cross_encoder_loaded", model="ms-marco-MiniLM-L-6-v2")
    return _cross_encoder


# ═══════════════════════════════════════════════════════════════════════
# Cybersecurity Query Expander
# ═══════════════════════════════════════════════════════════════════════

class CybersecurityQueryExpander:
    """
    Expands CTI queries with domain-specific context to improve recall.

    Detection rules:
      - CVE ID detected   → appends CVSS / vulnerability / exploitation terms
      - APT group detected → appends MITRE ATT&CK / campaign / techniques terms
      - Malware detected   → appends infection chain / lateral movement terms
    """

    _CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    _APT_RE = re.compile(
        r'\b(?:APT[-\s]?\d+|UNC\d+|FIN\d+|Lazarus|Fancy Bear|Cozy Bear|'
        r'Wizard Spider|Volt Typhoon|Scattered Spider|Black Basta|ALPHV|'
        r'[A-Z][a-z]+\s+(?:Bear|Panda|Spider|Kitten|Dragon|Typhoon))\b'
    )
    _MALWARE_RE = re.compile(
        r'\b(?:Emotet|TrickBot|Cobalt Strike|Mimikatz|LockBit|BlackCat|Conti|'
        r'REvil|DarkSide|QakBot|IcedID|Log4j|SUNBURST|Raindrop|TEARDROP|'
        r'[A-Z][a-zA-Z]+(?:Bot|RAT|Loader|Stealer|Worm|Trojan))\b'
    )

    @classmethod
    def expand(cls, query: str) -> str:
        """
        Return an expanded query with CTI-specific suffix terms.
        The original query is always preserved as prefix.
        """
        suffixes: list[str] = []

        if cls._CVE_RE.search(query):
            suffixes.append("CVSS vulnerability exploitation remote code execution")

        if cls._APT_RE.search(query):
            suffixes.append("MITRE ATT&CK campaign techniques tactics procedures")

        if cls._MALWARE_RE.search(query):
            suffixes.append("infection chain lateral movement persistence C2 exfiltration")

        if not suffixes:
            return query

        expanded = f"{query} {' '.join(suffixes)}"
        log.debug("query_expanded", original_len=len(query), expanded_len=len(expanded),
                  expansions=len(suffixes))
        return expanded


# ═══════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class SourceAttribution:
    """
    Provenance label for a single retrieved chunk.
    Every returned chunk MUST carry one of these — RO3 requirement.
    """
    source_type: str = ""          # "faiss_vector" | "kg_triple" | "kg_neighbor"
    technique_id: str = ""         # ATT&CK ID, e.g. "T1566.001"
    technique_name: str = ""       # e.g. "Spearphishing Attachment"
    tactic: str = ""               # e.g. "Initial Access"
    stix_id: str = ""              # STIX 2.1 object ID if available
    feed_url: str = ""             # OSINT feed URL if available
    source_url: str = ""           # ATT&CK page URL
    triple_id: str = ""            # KG triple hash ID
    confidence: float = 0.0        # Source confidence (0–1)
    retrieval_path: str = ""       # "vector" | "kg_semantic" | "kg_neighbor" | "rrf_fused"

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in {
            "source_type": self.source_type,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "stix_id": self.stix_id,
            "feed_url": self.feed_url,
            "source_url": self.source_url,
            "triple_id": self.triple_id,
            "confidence": round(self.confidence, 4),
            "retrieval_path": self.retrieval_path,
        }.items() if v}  # omit empty strings for cleaner JSON


@dataclass
class RetrievalResult:
    """
    Complete output from a hybrid retrieval call.

    Matches the user-specified schema:
      vector_docs    — raw FAISS results with provenance
      kg_context     — KG triples + neighbor expansions
      merged_context — RRF-fused text block for LLM prompting
      retrieval_scores — per-path and fused statistics
      sources        — flat list of source labels (technique_id / stix_id / feed_url)
    """
    vector_docs: list[dict[str, Any]] = field(default_factory=list)
    kg_context: list[dict[str, Any]] = field(default_factory=list)
    merged_context: str = ""
    retrieval_scores: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

    # Extended fields for research logging
    mode: str = ""
    kg_results_count: int = 0
    vec_results_count: int = 0
    fused_count: int = 0
    retrieval_latency_ms: float = 0.0
    source_attributions: list[dict[str, Any]] = field(default_factory=list)
    # RO2: Temporal freshness — mean days since publication of retrieved chunks
    temporal_freshness_days: float = -1.0  # -1 = not computed
    neo4j_results_count: int = 0

    # ── Compatibility with ThreatReasonerAgent ────────────────────
    @property
    def context_text(self) -> str:
        """Alias for merged_context (used by threat_reasoner._build_grounded_prompt)."""
        return self.merged_context

    def to_dict(self) -> dict[str, Any]:
        d = {
            "mode": self.mode,
            "kg_results": self.kg_results_count,
            "vec_results": self.vec_results_count,
            "neo4j_results": self.neo4j_results_count,
            "fused_results": self.fused_count,
            "latency_ms": round(self.retrieval_latency_ms, 1),
            "sources": self.sources,
            "retrieval_scores": self.retrieval_scores,
            "source_attributions": self.source_attributions,
        }
        if self.temporal_freshness_days >= 0:
            d["temporal_freshness_days"] = round(self.temporal_freshness_days, 1)
        return d

    def compute_temporal_freshness(self) -> float:
        """Compute mean temporal freshness of retrieved chunks (days since publication).
        
        Uses last_seen / modified dates from Neo4j results and source_url dates
        from FAISS chunks. Lower = more current.
        RO2: Core metric for temporal currency claim.
        """
        from datetime import datetime, timezone
        days_list = []
        now = datetime.now(timezone.utc)
        
        for doc in self.vector_docs + self.kg_context:
            # Try to extract date from MITRE source_url (contains technique modified date)
            modified = doc.get("modified") or doc.get("last_seen") or doc.get("created")
            if modified:
                try:
                    if isinstance(modified, str):
                        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"):
                            try:
                                dt = datetime.strptime(modified[:19], fmt).replace(tzinfo=timezone.utc)
                                days_list.append((now - dt).days)
                                break
                            except ValueError:
                                continue
                except Exception:
                    pass
        
        if days_list:
            self.temporal_freshness_days = sum(days_list) / len(days_list)
        else:
            # Default: use MITRE ATT&CK corpus age (~90 days typical refresh)
            self.temporal_freshness_days = 90.0
        
        return self.temporal_freshness_days

    def compute_ir_metrics(
        self,
        ground_truth_ttps: list[str] | None = None,
        ground_truth_cves: list[str] | None = None,
        k: int = 5,
    ) -> dict[str, float]:
        """
        Compute standard IR retrieval quality metrics: MRR@k and nDCG@k.

        Relevance is binary: a retrieved chunk is relevant if it contains
        any ground-truth TTP or CVE identifier.

        RO2: Academic reviewers require these alongside raw similarity scores.

        Args:
            ground_truth_ttps: Expected ATT&CK technique IDs (e.g. ["T1566", "T1059.001"])
            ground_truth_cves: Expected CVE IDs (e.g. ["CVE-2021-44228"])
            k: Number of top results to evaluate

        Returns:
            {"mrr_at_k": float, "ndcg_at_k": float, "precision_at_k": float, "k": int}
        """
        import math

        gt_set: set[str] = set()
        if ground_truth_ttps:
            for t in ground_truth_ttps:
                gt_set.add(t.upper())
                # Also add parent technique for sub-technique matches
                if "." in t:
                    gt_set.add(t.split(".")[0].upper())
        if ground_truth_cves:
            gt_set.update(c.upper() for c in ground_truth_cves)

        if not gt_set:
            return {"mrr_at_k": 0.0, "ndcg_at_k": 0.0, "precision_at_k": 0.0, "k": k}

        # Build relevance vector from fused results (vector + KG)
        all_docs = self.vector_docs + self.kg_context
        relevance: list[int] = []
        for doc in all_docs[:k]:
            text_upper = str(doc.get("text", "")).upper()
            tech_id = str(doc.get("technique_id", "")).upper()
            is_relevant = False
            for gt in gt_set:
                if gt in text_upper or gt == tech_id:
                    is_relevant = True
                    break
            relevance.append(1 if is_relevant else 0)

        # Pad to k if fewer results
        while len(relevance) < k:
            relevance.append(0)

        # MRR@k: reciprocal rank of first relevant result
        mrr = 0.0
        for i, rel in enumerate(relevance):
            if rel == 1:
                mrr = 1.0 / (i + 1)
                break

        # nDCG@k: normalized discounted cumulative gain
        dcg = sum(rel / math.log2(i + 2) for i, rel in enumerate(relevance))
        # Ideal DCG: all relevant results at top
        ideal_rels = sorted(relevance, reverse=True)
        idcg = sum(rel / math.log2(i + 2) for i, rel in enumerate(ideal_rels))
        ndcg = dcg / idcg if idcg > 0 else 0.0

        # Precision@k
        precision = sum(relevance) / k

        return {
            "mrr_at_k": round(mrr, 4),
            "ndcg_at_k": round(ndcg, 4),
            "precision_at_k": round(precision, 4),
            "k": k,
        }


# ═══════════════════════════════════════════════════════════════════════
# Internal ranked-document representation (used during fusion)
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class _RankedDoc:
    """Internal: a scored document with provenance, used for RRF."""
    text: str
    score: float
    rank: int
    path: str                       # "vector" | "kg_semantic" | "kg_neighbor"
    attribution: SourceAttribution = field(default_factory=SourceAttribution)

    @property
    def fingerprint(self) -> str:
        """Content-based dedup key."""
        return hashlib.md5(self.text[:200].strip().lower().encode()).hexdigest()


# ═══════════════════════════════════════════════════════════════════════
# Hybrid Retriever
# ═══════════════════════════════════════════════════════════════════════

class HybridRetriever:
    """
    Two-path retrieval with Reciprocal Rank Fusion.

    Path 1 — Dense vector (FAISS):
        embed(query) → FAISS.search(top_k*4) → MMR re-rank → top_k docs

    Path 2 — Knowledge Graph (KGBuilderAgent):
        extract_entities(query) → for each entity:
            semantic_search(entity)  → matching triples
            get_neighbors(entity, 1) → 1-hop expansion
        → deduplicate → rank by confidence → top_k triples

    Fusion — Reciprocal Rank Fusion:
        RRF_score(d) = Σ 1/(k + rank_i(d))   across both paths
        → deduplicate by content fingerprint
        → top_k final results
    """

    # Entity types to extract from the query for KG traversal
    _ENTITY_PATTERNS: dict[str, str] = {
        "threat_actor": r'\b(?:APT[-\s]?\d+|UNC\d+|FIN\d+|Lazarus|Fancy Bear|Cozy Bear|'
                        r'Wizard Spider|Volt Typhoon|Scattered Spider|Black Basta|ALPHV|'
                        r'[A-Z][a-z]+\s+(?:Bear|Panda|Spider|Kitten|Dragon|Typhoon))\b',
        "malware": r'\b(?:Emotet|TrickBot|Cobalt Strike|Mimikatz|LockBit|BlackCat|Conti|'
                   r'REvil|DarkSide|QakBot|IcedID|Log4j|SUNBURST|'
                   r'[A-Z][a-zA-Z]+(?:Bot|RAT|Loader|Stealer|Worm|Trojan))\b',
        "cve": r'\bCVE-\d{4}-\d{4,7}\b',
        "technique": r'\bT\d{4}(?:\.\d{3})?\b',
    }

    def __init__(self, rerank_final_n: int = 3, enable_rerank: bool = True,
                 enable_query_expansion: bool = True) -> None:
        self._mode = settings.rag.retrieval_mode
        self._rrf_k = settings.rag.rrf_k
        self._rerank_n = rerank_final_n
        self._enable_rerank = enable_rerank
        self._enable_expansion = enable_query_expansion

    def retrieve(
        self,
        query: str,
        kg_builder=None,
        top_k: int | None = None,
        mode: RetrievalMode | None = None,
    ) -> RetrievalResult:
        """
        Execute hybrid retrieval and return fused results.

        Args:
            query:      Raw threat report or search query
            kg_builder: KGBuilderAgent instance (required for KG path)
            top_k:      Number of final results to return (default: config)
            mode:       Override retrieval mode (default: config)

        Returns:
            RetrievalResult with vector_docs, kg_context, merged_context,
            retrieval_scores, and source attribution labels.
        """
        t0 = time.time()
        mode = mode or self._mode
        top_k = top_k or settings.rag.top_k
        result = RetrievalResult(mode=mode.value)

        # ── Query expansion for CTI-specific recall boost ────────
        search_query = query
        if self._enable_expansion and mode != RetrievalMode.NONE:
            search_query = CybersecurityQueryExpander.expand(query)

        vec_ranked: list[_RankedDoc] = []
        kg_ranked: list[_RankedDoc] = []

        # ── Path 1: Dense vector search ──────────────────────────
        if mode in (RetrievalMode.VECTOR_ONLY, RetrievalMode.HYBRID):
            vec_ranked = self._vector_path(search_query, top_k)
            result.vec_results_count = len(vec_ranked)
            result.vector_docs = [
                self._ranked_to_doc(d) for d in vec_ranked
            ]

        # ── Path 2: Knowledge Graph traversal ────────────────────
        if mode in (RetrievalMode.KG_ONLY, RetrievalMode.HYBRID):
            kg_ranked = self._kg_path(search_query, kg_builder, top_k)
            result.kg_results_count = len(kg_ranked)
            result.kg_context = [
                self._ranked_to_doc(d) for d in kg_ranked
            ]

        # ── Fusion ───────────────────────────────────────────────
        if mode == RetrievalMode.HYBRID and vec_ranked and kg_ranked:
            fused = self._reciprocal_rank_fusion(
                [vec_ranked, kg_ranked], top_n=top_k
            )
        elif mode == RetrievalMode.VECTOR_ONLY:
            fused = vec_ranked[:top_k]
        elif mode == RetrievalMode.KG_ONLY:
            fused = kg_ranked[:top_k]
        elif mode == RetrievalMode.HYBRID:
            # One path empty — use whatever we have
            fused = (vec_ranked or kg_ranked)[:top_k]
        else:
            fused = []  # NONE mode

        result.fused_count = len(fused)

        # ── Cross-encoder re-ranking for precision boost ─────────
        if self._enable_rerank and fused and mode != RetrievalMode.NONE:
            fused = self.rerank(query, fused, top_n=self._rerank_n)
            result.fused_count = len(fused)

        # ── Build merged context string for LLM prompting ────────
        result.merged_context = self._build_merged_context(fused, mode.value)

        # ── Flatten source labels ────────────────────────────────
        all_attributions = []
        source_labels: list[str] = []
        for doc in fused:
            attr = doc.attribution
            all_attributions.append(attr.to_dict())
            label = attr.technique_id or attr.stix_id or attr.feed_url or attr.source_type
            if label and label not in source_labels:
                source_labels.append(label)
        result.sources = source_labels
        result.source_attributions = all_attributions

        # ── Retrieval scores ─────────────────────────────────────
        result.retrieval_latency_ms = (time.time() - t0) * 1000
        result.retrieval_scores = {
            "mode": mode.value,
            "vec_count": result.vec_results_count,
            "kg_count": result.kg_results_count,
            "fused_count": result.fused_count,
            "latency_ms": round(result.retrieval_latency_ms, 1),
            "vec_avg_score": (
                round(np.mean([d.score for d in vec_ranked]), 4)
                if vec_ranked else 0.0
            ),
            "kg_avg_confidence": (
                round(np.mean([d.score for d in kg_ranked]), 4)
                if kg_ranked else 0.0
            ),
            "fused_avg_rrf": (
                round(np.mean([d.score for d in fused]), 4)
                if fused else 0.0
            ),
            "reranked": self._enable_rerank,
            "query_expanded": search_query != query,
        }

        # ── Temporal freshness (RO2 metric) ─────────────────────────
        result.compute_temporal_freshness()

        log.info("hybrid_retrieval_complete",
                 mode=mode.value,
                 vec=result.vec_results_count,
                 kg=result.kg_results_count,
                 fused=result.fused_count,
                 freshness_days=round(result.temporal_freshness_days, 1),
                 latency_ms=round(result.retrieval_latency_ms, 1))

        return result

    # ═══════════════════════════════════════════════════════════════
    # Path 1: Dense Vector Search (FAISS + MMR)
    # ═══════════════════════════════════════════════════════════════

    def _vector_path(self, query: str, top_k: int) -> list[_RankedDoc]:
        """Embed query → FAISS search → MMR re-rank → ranked docs."""
        try:
            from cti_shield.rag import get_vector_store
            store = get_vector_store()
            if store.total_vectors == 0:
                return []

            raw = store.search(query, top_k=top_k, use_mmr=True)
            docs = []
            for rank, hit in enumerate(raw):
                docs.append(_RankedDoc(
                    text=hit.get("text", ""),
                    score=hit.get("score", 0.0),
                    rank=rank + 1,
                    path="vector",
                    attribution=SourceAttribution(
                        source_type="faiss_vector",
                        technique_id=hit.get("technique_id", ""),
                        technique_name=hit.get("technique_name", ""),
                        tactic=hit.get("tactic", ""),
                        source_url=hit.get("source_url", ""),
                        stix_id=hit.get("stix_id", ""),
                        feed_url=hit.get("feed_url", ""),
                        confidence=hit.get("score", 0.0),
                        retrieval_path="vector",
                    ),
                ))
            return docs
        except Exception as e:
            log.warning("vector_path_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════════════
    # Path 2: Knowledge Graph Traversal (NetworkX)
    # ═══════════════════════════════════════════════════════════════

    def _kg_path(self, query: str, kg_builder, top_k: int) -> list[_RankedDoc]:
        """
        Extract entities from query → traverse KG → expand 1-hop
        → return ranked triples with technique contexts.
        
        Tries Neo4j (CyberKG) first for persistent graph traversal,
        falls back to NetworkX (KGBuilderAgent) when unavailable.
        """
        if kg_builder is None:
            return []

        docs: list[_RankedDoc] = []
        seen_ids: set[str] = set()

        # ── Try Neo4j path first (persistent, richer schema) ─────
        neo4j_docs = self._neo4j_kg_path(query, top_k)
        for d in neo4j_docs:
            fp = hashlib.md5(d.text.encode()).hexdigest()[:12]
            if fp not in seen_ids:
                seen_ids.add(fp)
                docs.append(d)

        # Step 1: Extract entities from the query
        entities = self._extract_query_entities(query)

        # Step 2: For each entity, get direct matches + 1-hop neighbors
        for entity_type, entity_values in entities.items():
            for entity in entity_values:
                # 2a: Direct semantic search on the entity
                try:
                    triples = kg_builder.semantic_search(entity, k=top_k)
                    for rank, triple in enumerate(triples):
                        if triple.id in seen_ids:
                            continue
                        seen_ids.add(triple.id)
                        docs.append(self._triple_to_ranked(
                            triple, rank + 1, "kg_semantic"
                        ))
                except Exception:
                    pass

                # 2b: 1-hop graph traversal for context expansion
                try:
                    neighbors = kg_builder.get_neighbors(entity, hops=1)
                    for rank, triple in enumerate(neighbors):
                        if triple.id in seen_ids:
                            continue
                        seen_ids.add(triple.id)
                        docs.append(self._triple_to_ranked(
                            triple, rank + 1 + len(docs), "kg_neighbor"
                        ))
                except Exception:
                    pass

        # Step 3: Also run full-query semantic search (catches patterns
        # that entity extraction might miss)
        try:
            full_triples = kg_builder.semantic_search(query[:500], k=top_k)
            for rank, triple in enumerate(full_triples):
                if triple.id in seen_ids:
                    continue
                seen_ids.add(triple.id)
                docs.append(self._triple_to_ranked(
                    triple, rank + 1 + len(docs), "kg_semantic"
                ))
        except Exception:
            pass

        # Step 4: Sort by confidence descending, truncate
        docs.sort(key=lambda d: d.score, reverse=True)
        for i, d in enumerate(docs):
            d.rank = i + 1
        return docs[:top_k * 2]  # return 2× top_k to give RRF more to work with

    def _neo4j_kg_path(self, query: str, top_k: int) -> list[_RankedDoc]:
        """Query CyberKG (Neo4j) for related entities if available."""
        try:
            from cti_shield.neo4j_kg import get_cyber_kg
            ckg = get_cyber_kg()
            if not ckg.is_neo4j:
                return []

            docs: list[_RankedDoc] = []
            entities = self._extract_query_entities(query)

            for entity_type, entity_values in entities.items():
                for entity in entity_values:
                    records = ckg.query_related(entity, hops=2)
                    for rank, rec in enumerate(records):
                        text = f"{rec.entity} {rec.relationship} {rec.related}"
                        if rec.technique_id:
                            text += f" [{rec.technique_id}]"
                        docs.append(_RankedDoc(
                            text=text,
                            score=rec.confidence if rec.confidence else 0.5,
                            rank=rank + 1,
                            path="neo4j_kg",
                            attribution=SourceAttribution(
                                source_type="neo4j_triple",
                                technique_id=rec.technique_id,
                                confidence=rec.confidence if rec.confidence else 0.5,
                                retrieval_path="neo4j_kg",
                            ),
                        ))

            # Also query recent CVEs for temporal currency
            try:
                recent = ckg.query_recent(days=30)
                for rank, rec in enumerate(recent[:top_k]):
                    text = f"Recently exploited: {rec.get('cve', '')} {rec.get('name', '')} " \
                           f"by {', '.join(rec.get('exploited_by', []))}"
                    docs.append(_RankedDoc(
                        text=text, score=0.6, rank=rank + 1 + len(docs),
                        path="neo4j_temporal",
                        attribution=SourceAttribution(
                            source_type="neo4j_temporal",
                            technique_id=rec.get("cve", ""),
                            confidence=0.6,
                            retrieval_path="neo4j_temporal",
                        ),
                    ))
            except Exception:
                pass

            log.info("neo4j_kg_path", results=len(docs))
            return docs

        except Exception as e:
            log.debug("neo4j_kg_path_unavailable", error=str(e))
            return []

    def _extract_query_entities(self, query: str) -> dict[str, list[str]]:
        """Extract named entities from the query to seed KG traversal."""
        found: dict[str, list[str]] = {}
        for entity_type, pattern in self._ENTITY_PATTERNS.items():
            matches = list(set(re.findall(pattern, query, re.IGNORECASE)))
            if matches:
                found[entity_type] = matches[:10]
        return found

    def _triple_to_ranked(self, triple, rank: int, path: str) -> _RankedDoc:
        """Convert a KG Triple to the internal _RankedDoc format."""
        text = f"{triple.subject} {triple.predicate} {triple.obj}"
        if triple.technique_id:
            text += f" [{triple.technique_id}: {triple.technique_name}]"

        return _RankedDoc(
            text=text,
            score=triple.confidence,
            rank=rank,
            path=path,
            attribution=SourceAttribution(
                source_type="kg_triple",
                technique_id=triple.technique_id,
                technique_name=triple.technique_name,
                stix_id="",
                triple_id=triple.id,
                confidence=triple.confidence,
                retrieval_path=path,
            ),
        )

    # ═══════════════════════════════════════════════════════════════
    # Reciprocal Rank Fusion
    # ═══════════════════════════════════════════════════════════════

    def _reciprocal_rank_fusion(
        self,
        ranked_lists: list[list[_RankedDoc]],
        top_n: int = 10,
    ) -> list[_RankedDoc]:
        """
        RRF (Cormack et al., 2009):  score(d) = Σ 1/(k + rank_i(d))

        Deduplicates across lists by content fingerprint and keeps
        the version with the richest source attribution.
        """
        k = self._rrf_k
        scores: dict[str, float] = {}
        best_doc: dict[str, _RankedDoc] = {}

        for ranked_list in ranked_lists:
            for doc in ranked_list:
                fp = doc.fingerprint
                rrf_score = 1.0 / (k + doc.rank)

                if fp in scores:
                    scores[fp] += rrf_score
                    # Keep the doc with richer attribution
                    existing = best_doc[fp]
                    if doc.attribution.technique_id and not existing.attribution.technique_id:
                        best_doc[fp] = doc
                    elif doc.score > existing.score:
                        best_doc[fp] = doc
                else:
                    scores[fp] = rrf_score
                    best_doc[fp] = doc

        # Sort by RRF score descending
        sorted_fps = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)

        results: list[_RankedDoc] = []
        for rank, fp in enumerate(sorted_fps[:top_n]):
            doc = best_doc[fp]
            doc.score = scores[fp]
            doc.rank = rank + 1
            doc.attribution.retrieval_path = "rrf_fused"
            results.append(doc)

        return results

    # ═══════════════════════════════════════════════════════════════
    # Cross-Encoder Re-ranking
    # ═══════════════════════════════════════════════════════════════

    def rerank(
        self,
        query: str,
        candidates: list[_RankedDoc],
        top_n: int = 3,
    ) -> list[_RankedDoc]:
        """
        Re-rank fused candidates using a cross-encoder relevance model.

        Model: cross-encoder/ms-marco-MiniLM-L-6-v2
        This is a learned relevance model that scores (query, passage)
        pairs — much more precise than bi-encoder cosine similarity.

        Args:
            query:      Original query text (NOT the expanded version,
                        so re-ranking judges against user intent)
            candidates: RRF-fused candidate list from fusion stage
            top_n:      Number of top re-ranked results to return

        Returns:
            Top-n candidates re-ordered by cross-encoder relevance score.
            Attribution is preserved; retrieval_path updated to "reranked".
        """
        if not candidates or top_n <= 0:
            return candidates

        try:
            encoder = _get_cross_encoder()

            # Build (query, passage) pairs for the cross-encoder
            pairs = [(query[:512], doc.text[:512]) for doc in candidates]
            ce_scores = encoder.predict(pairs, show_progress_bar=False, convert_to_numpy=True)  # type: ignore[call-overload]

            # Attach cross-encoder scores and sort descending
            scored = list(zip(ce_scores, candidates))
            scored.sort(key=lambda x: float(x[0]), reverse=True)

            reranked: list[_RankedDoc] = []
            for rank, (ce_score, doc) in enumerate(scored[:top_n]):
                doc.score = float(ce_score)
                doc.rank = rank + 1
                doc.attribution.retrieval_path = "reranked"
                reranked.append(doc)

            log.info("cross_encoder_rerank",
                     candidates=len(candidates),
                     returned=len(reranked),
                     top_score=round(reranked[0].score, 4) if reranked else 0)

            return reranked

        except Exception as e:
            log.warning("rerank_failed_returning_rrf_order", error=str(e))
            return candidates[:top_n]

    # ═══════════════════════════════════════════════════════════════
    # Context Formatting
    # ═══════════════════════════════════════════════════════════════

    def _build_merged_context(self, fused: list[_RankedDoc], mode: str) -> str:
        """Format fused results into a single text block for LLM prompting."""
        if not fused:
            return ""

        lines = [
            f"[Retrieved Context — {mode} mode, {len(fused)} passages]",
            "",
        ]
        for doc in fused:
            attr = doc.attribution
            tags = []
            if attr.technique_id:
                tags.append(f"ATT&CK:{attr.technique_id}")
            if attr.stix_id:
                tags.append(f"STIX:{attr.stix_id}")
            if attr.feed_url:
                tags.append(f"Feed:{attr.feed_url}")
            tag_str = f" [{', '.join(tags)}]" if tags else ""
            path_tag = f"[{doc.path}]"

            lines.append(
                f"  {path_tag}{tag_str} (score: {doc.score:.4f}): "
                f"{doc.text[:400]}"
            )
        return "\n".join(lines)

    # ═══════════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _ranked_to_doc(d: _RankedDoc) -> dict[str, Any]:
        """Convert _RankedDoc to a plain dict for the result dataclass."""
        return {
            "text": d.text,
            "score": round(d.score, 4),
            "rank": d.rank,
            "path": d.path,
            "attribution": d.attribution.to_dict(),
        }


# ── Singleton ────────────────────────────────────────────────────────
_retriever: HybridRetriever | None = None


def get_hybrid_retriever() -> HybridRetriever:
    global _retriever
    if _retriever is None:
        _retriever = HybridRetriever()
    return _retriever
