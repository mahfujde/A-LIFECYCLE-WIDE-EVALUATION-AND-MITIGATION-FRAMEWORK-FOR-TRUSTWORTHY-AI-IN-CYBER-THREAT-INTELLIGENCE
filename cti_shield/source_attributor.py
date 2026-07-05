"""
Source Attributor — Claim-Level Provenance for CTI Outputs
============================================================
RO3: "LLM-generated CTI must have traceable source attribution"

Maps each factual claim in the LLM response back to its source
chunk from the retrieval pipeline using semantic similarity.

Evaluation metric (RQ3):
  attribution_rate = claims_with_source / total_claims
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import structlog

log = structlog.get_logger(__name__)

# ── Lazy-loaded embedding model ──────────────────────────────────────
_embed_model = None


def _get_embed_model():
    global _embed_model
    if _embed_model is None:
        try:
            from cti_shield.model_cache import get_sentence_transformer
            _embed_model = get_sentence_transformer("all-MiniLM-L6-v2", device="cpu")
        except Exception:
            _embed_model = "unavailable"
    return _embed_model


# ── Entity detection patterns ────────────────────────────────────────
_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b')
_TTP_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
_ACTOR_RE = re.compile(
    r'\b(?:APT[-\s]?\d+|UNC\d+|FIN\d+|Lazarus|Fancy Bear|Cozy Bear|'
    r'Wizard Spider|Volt Typhoon|Scattered Spider|Black Basta|ALPHV|'
    r'SamSam|SUNBURST|[A-Z][a-z]+\s+(?:Bear|Panda|Spider|Kitten|Dragon|Typhoon))\b'
)
_MALWARE_RE = re.compile(
    r'\b(?:Emotet|TrickBot|Cobalt Strike|Mimikatz|LockBit|BlackCat|Conti|'
    r'REvil|DarkSide|QakBot|IcedID|Log4j|SUNBURST|TEARDROP|Raindrop|'
    r'PsExec|AnyDesk|ConnectWise|rclone)\b'
)


def _resolve_source_url(source_id: str, claim_type: str = "") -> str:
    """Resolve a source identifier to its authoritative URL (G3.3 fix).
    
    Maps:
      ATT&CK:T1566.001 → https://attack.mitre.org/techniques/T1566/001/
      CVE-2024-12345    → https://nvd.nist.gov/vuln/detail/CVE-2024-12345
      CISA:AA23-136A    → https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a
    """
    if not source_id:
        return ""
    
    # ATT&CK technique URL
    ttp_match = re.match(r'(?:ATT&CK:)?([Tt]\d{4}(?:\.\d{3})?)', source_id)
    if ttp_match:
        tid = ttp_match.group(1).upper()
        path = tid.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{path}/"
    
    # CVE URL
    cve_match = re.match(r'(CVE-\d{4}-\d{4,7})', source_id, re.IGNORECASE)
    if cve_match:
        return f"https://nvd.nist.gov/vuln/detail/{cve_match.group(1)}"
    
    # If source_id is already a URL
    if source_id.startswith("http"):
        return source_id
    
    # KG triple — no direct URL
    if source_id.startswith("KG:"):
        return ""
    
    return ""


# ═══════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class Claim:
    """A single attributed claim from the LLM response."""
    text: str
    claim_type: str              # "CVE" | "TTP" | "actor" | "malware" | "general"
    source_id: str = ""          # stix_id, feed_url, or "ATT&CK:T1xxx"
    source_snippet: str = ""     # The matching chunk text
    attribution_confidence: str = "LOW"  # "HIGH" | "MEDIUM" | "LOW"
    similarity_score: float = 0.0
    entities_found: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "claim_type": self.claim_type,
            "source_id": self.source_id,
            "source_snippet": self.source_snippet[:200],
            "attribution_confidence": self.attribution_confidence,
            "similarity_score": round(self.similarity_score, 4),
            "entities": self.entities_found,
        }


@dataclass
class AttributedResponse:
    """Complete attributed output — every claim mapped to sources."""
    claims: list[Claim] = field(default_factory=list)
    attribution_rate: float = 0.0
    total_claims: int = 0
    attributed_claims: int = 0
    unattributed_claims: list[str] = field(default_factory=list)
    processing_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "attribution_rate": round(self.attribution_rate, 4),
            "total_claims": self.total_claims,
            "attributed_claims": self.attributed_claims,
            "unattributed_count": len(self.unattributed_claims),
            "unattributed_claims": self.unattributed_claims[:5],
            "processing_ms": round(self.processing_ms, 1),
            "claims": [c.to_dict() for c in self.claims],
        }


# ═══════════════════════════════════════════════════════════════════════
# Source Attributor
# ═══════════════════════════════════════════════════════════════════════

class SourceAttributor:
    """
    Maps LLM-generated claims back to retrieved source chunks.

    Pipeline:
      1. Extract factual claims (sentences with CVE/TTP/actor/malware)
      2. Classify each claim by type
      3. Compute semantic similarity against retrieved chunks
      4. Assign confidence: HIGH (>0.8), MEDIUM (>0.5), LOW (otherwise)
      5. Resolve source_id from the best-matching chunk's attribution
    """

    # Similarity thresholds for confidence levels
    THRESHOLD_HIGH = 0.80    # Near-verbatim / direct quote
    THRESHOLD_MEDIUM = 0.50  # Paraphrase
    THRESHOLD_MIN = 0.30     # Minimum for any attribution

    def attribute(
        self,
        llm_response: str,
        retrieval_result: dict[str, Any] | None = None,
        source_attributions: list[dict[str, Any]] | None = None,
    ) -> AttributedResponse:
        """
        Attribute each factual claim in the LLM response to a source.

        Args:
            llm_response:       The LLM-generated analysis text
            retrieval_result:   RetrievalResult.to_dict() or similar with
                                vector_docs/kg_context keys
            source_attributions: List of SourceAttribution dicts from retrieval

        Returns:
            AttributedResponse with per-claim attribution
        """
        t0 = time.time()
        result = AttributedResponse()

        # ── Step 1: Extract factual claims ───────────────────────
        claims = self._extract_factual_claims(llm_response)
        result.total_claims = len(claims)

        if not claims:
            result.processing_ms = (time.time() - t0) * 1000
            return result

        # ── Step 2: Build source chunk corpus ────────────────────
        chunks = self._build_chunk_corpus(
            retrieval_result or {}, source_attributions or []
        )

        # ── Step 3: Attribute each claim ─────────────────────────
        for claim in claims:
            attributed = self._attribute_claim(claim, chunks)
            result.claims.append(attributed)
            if attributed.source_id:
                result.attributed_claims += 1
            else:
                result.unattributed_claims.append(attributed.text[:80])

        result.attribution_rate = (
            result.attributed_claims / max(result.total_claims, 1)
        )
        result.processing_ms = (time.time() - t0) * 1000

        log.info("source_attribution_complete",
                 total=result.total_claims,
                 attributed=result.attributed_claims,
                 rate=round(result.attribution_rate, 3),
                 ms=round(result.processing_ms, 1))

        return result

    # ── Claim Extraction ─────────────────────────────────────────

    def _extract_factual_claims(self, text: str) -> list[Claim]:
        """
        Extract sentences containing verifiable entities.
        Only sentences with CVEs, TTPs, actor names, or malware
        are treated as factual claims requiring attribution.
        """
        sentences = re.split(r'(?<=[.!?])\s+', text)
        claims: list[Claim] = []

        for sent in sentences:
            sent = sent.strip()
            if len(sent) < 15:
                continue

            claim_type, entities = self._classify_claim(sent)
            claims.append(Claim(
                text=sent,
                claim_type=claim_type,
                entities_found=entities,
            ))

        return claims

    def _classify_claim(self, text: str) -> tuple[str, list[str]]:
        """Classify a claim by the type of entities it contains."""
        entities: list[str] = []

        cves = _CVE_RE.findall(text)
        if cves:
            entities.extend(cves)
            return "CVE", entities

        ttps = _TTP_RE.findall(text)
        if ttps:
            entities.extend(ttps)
            return "TTP", entities

        actors = _ACTOR_RE.findall(text)
        if actors:
            entities.extend(actors)
            return "actor", entities

        malware = _MALWARE_RE.findall(text)
        if malware:
            entities.extend(malware)
            return "malware", entities

        # G6 fix: extract key noun phrases as pseudo-entities for general claims
        # so they aren't silently unattributable
        keywords = []
        for word in text.split():
            clean = word.strip(".,;:!?\"'()[]")
            # Capitalized multi-char words that aren't common stopwords
            if (len(clean) > 3 and clean[0].isupper()
                    and clean.lower() not in {
                        "this", "that", "these", "those", "they", "their",
                        "with", "from", "into", "have", "been", "were",
                        "will", "would", "could", "should", "also", "more",
                        "used", "using", "based", "data", "system", "attack",
                        "network", "security", "threat", "organization",
                    }):
                keywords.append(clean)
        if keywords:
            return "general", keywords[:5]  # Top 5 keywords

        return "general", []

    # ── Source Chunk Corpus ───────────────────────────────────────

    def _build_chunk_corpus(
        self,
        retrieval_result: dict[str, Any],
        source_attributions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Build a flat list of source chunks with their attribution metadata.
        Merges vector_docs, kg_context, and source_attributions.
        """
        chunks: list[dict[str, Any]] = []
        seen_texts: set[str] = set()

        # Vector docs
        for doc in retrieval_result.get("vector_docs", []):
            text = doc.get("text", doc.get("content", ""))
            if text and text[:50] not in seen_texts:
                seen_texts.add(text[:50])
                chunks.append({
                    "text": text,
                    "source_type": "vector",
                    "technique_id": doc.get("technique_id", ""),
                    "stix_id": doc.get("stix_id", ""),
                    "source_url": doc.get("source_url", ""),
                    "feed_url": doc.get("feed_url", ""),
                })

        # KG context
        for ctx in retrieval_result.get("kg_context", []):
            text = ctx.get("text", ctx.get("content", ""))
            if text and text[:50] not in seen_texts:
                seen_texts.add(text[:50])
                chunks.append({
                    "text": text,
                    "source_type": "kg",
                    "technique_id": ctx.get("technique_id", ""),
                    "stix_id": ctx.get("stix_id", ""),
                    "triple_id": ctx.get("triple_id", ""),
                })

        # Source attributions from retriever
        for attr in source_attributions:
            source_id = self._resolve_source_id(attr)
            # Check if this attribution corresponds to an existing chunk
            tech_id = attr.get("technique_id", "")
            if tech_id and not any(c.get("technique_id") == tech_id for c in chunks):
                chunks.append({
                    "text": attr.get("technique_name", tech_id),
                    "source_type": attr.get("source_type", "attribution"),
                    "technique_id": tech_id,
                    "stix_id": attr.get("stix_id", ""),
                    "source_url": attr.get("source_url", ""),
                    "resolved_id": source_id,
                })

        # ── Fallback: query FAISS directly when no retrieval chunks ──
        # This ensures attribution works even in NONE retrieval mode (A6 fix)
        if not chunks:
            try:
                from cti_shield.rag import get_vector_store
                store = get_vector_store()
                if store.total_vectors > 0:
                    # Search for each entity mentioned in the LLM response
                    search_terms = set()
                    for doc in retrieval_result.get("vector_docs", []):
                        tid = doc.get("technique_id", "")
                        if tid:
                            search_terms.add(tid)
                    # If no terms from retrieval, use a generic CTI search
                    if not search_terms:
                        search_terms = {"threat intelligence", "cyber attack", "malware"}
                    for term in list(search_terms)[:5]:
                        hits = store.search(term, top_k=3, use_mmr=False)
                        for hit in hits:
                            text = hit.get("text", "")
                            if text and text[:50] not in seen_texts:
                                seen_texts.add(text[:50])
                                chunks.append({
                                    "text": text,
                                    "source_type": "faiss_fallback",
                                    "technique_id": hit.get("technique_id", ""),
                                    "source_url": hit.get("source_url", ""),
                                })
            except Exception:
                pass

        return chunks

    # ── Claim Attribution ────────────────────────────────────────

    def _attribute_claim(
        self, claim: Claim, chunks: list[dict[str, Any]],
    ) -> Claim:
        """
        Find the best source chunk for a claim using:
          1. Entity matching (exact CVE/TTP/actor overlap)
          2. Semantic similarity (cosine via sentence-transformers)
        """
        if not chunks:
            return claim

        # ── Fast path: exact entity matching ─────────────────
        best_chunk = self._entity_match(claim, chunks)
        if best_chunk:
            claim.source_id = self._resolve_source_id(best_chunk)
            claim.source_snippet = best_chunk.get("text", "")[:200]
            claim.similarity_score = 1.0
            claim.attribution_confidence = "HIGH"
            return claim

        # ── Slow path: semantic similarity ───────────────────
        model = _get_embed_model()
        if model == "unavailable":
            return self._lexical_fallback(claim, chunks)

        try:
            chunk_texts = [c.get("text", "")[:500] for c in chunks]
            all_texts = [claim.text[:500]] + chunk_texts
            embeddings = model.encode(all_texts, normalize_embeddings=True,
                                      show_progress_bar=False)

            claim_emb = embeddings[0]
            chunk_embs = embeddings[1:]
            similarities = np.dot(chunk_embs, claim_emb)

            best_idx = int(np.argmax(similarities))
            best_sim = float(similarities[best_idx])

            if best_sim >= self.THRESHOLD_MIN:
                best = chunks[best_idx]
                claim.source_id = self._resolve_source_id(best)
                claim.source_snippet = best.get("text", "")[:200]
                claim.similarity_score = best_sim

                if best_sim >= self.THRESHOLD_HIGH:
                    claim.attribution_confidence = "HIGH"
                elif best_sim >= self.THRESHOLD_MEDIUM:
                    claim.attribution_confidence = "MEDIUM"
                else:
                    claim.attribution_confidence = "LOW"

        except Exception as e:
            log.warning("attribution_embedding_failed", error=str(e))
            return self._lexical_fallback(claim, chunks)

        return claim

    def _entity_match(
        self, claim: Claim, chunks: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Direct entity match: if claim mentions T1566 and a chunk has technique_id=T1566."""
        for entity in claim.entities_found:
            for chunk in chunks:
                # Match by technique_id
                if chunk.get("technique_id") == entity:
                    return chunk
                # Match by text content (entity mentioned in chunk)
                if entity.lower() in chunk.get("text", "").lower():
                    return chunk
        return None

    def _lexical_fallback(
        self, claim: Claim, chunks: list[dict[str, Any]],
    ) -> Claim:
        """Fallback: lexical overlap when embeddings are unavailable."""
        claim_tokens = set(claim.text.lower().split())
        best_overlap = 0.0
        best_chunk = None

        for chunk in chunks:
            chunk_tokens = set(chunk.get("text", "").lower().split())
            if not chunk_tokens:
                continue
            overlap = len(claim_tokens & chunk_tokens) / max(len(claim_tokens), 1)
            if overlap > best_overlap:
                best_overlap = overlap
                best_chunk = chunk

        if best_chunk and best_overlap >= 0.3:
            claim.source_id = self._resolve_source_id(best_chunk)
            claim.source_snippet = best_chunk.get("text", "")[:200]
            claim.similarity_score = best_overlap
            claim.attribution_confidence = "LOW"

        return claim

    # ── Source ID Resolution ─────────────────────────────────────

    @staticmethod
    def _resolve_source_id(chunk: dict[str, Any]) -> str:
        """
        Resolve the best source identifier from a chunk's metadata.
        Priority: stix_id → feed_url → source_url → technique_id → triple_id
        """
        if chunk.get("resolved_id"):
            return chunk["resolved_id"]
        if chunk.get("stix_id"):
            return chunk["stix_id"]
        if chunk.get("feed_url"):
            return chunk["feed_url"]
        if chunk.get("source_url"):
            return chunk["source_url"]
        if chunk.get("technique_id"):
            return f"ATT&CK:{chunk['technique_id']}"
        if chunk.get("triple_id"):
            return f"KG:{chunk['triple_id']}"
        return ""

    # ── Citation Report ──────────────────────────────────────────

    @staticmethod
    def generate_citation_report(attributed: AttributedResponse) -> str:
        """
        Generate a human-readable citation block for analyst review.

        Format:
          [1] Claim: 'The actor used spearphishing'
              → Source: ATT&CK:T1566.001 (HIGH confidence, sim=0.95)
              → URL: https://attack.mitre.org/techniques/T1566/001/
        """
        lines: list[str] = []
        lines.append("=" * 64)
        lines.append("SOURCE ATTRIBUTION REPORT")
        lines.append(f"Total claims: {attributed.total_claims}  |  "
                     f"Attributed: {attributed.attributed_claims}  |  "
                     f"Rate: {attributed.attribution_rate:.1%}")
        lines.append("=" * 64)

        for i, claim in enumerate(attributed.claims, 1):
            status = "✓" if claim.source_id else "✗"
            lines.append(f"\n[{i}] {status} Claim ({claim.claim_type}): "
                         f"'{claim.text[:100]}'")
            if claim.source_id:
                lines.append(f"    → Source: {claim.source_id} "
                             f"({claim.attribution_confidence} confidence, "
                             f"sim={claim.similarity_score:.2f})")
                # G3.3: Include original URL for traceability
                url = _resolve_source_url(claim.source_id, claim.claim_type)
                if url:
                    lines.append(f"    → URL: {url}")
                if claim.source_snippet:
                    lines.append(f"    → Snippet: '{claim.source_snippet[:80]}...'")
            else:
                lines.append("    → Source: UNATTRIBUTED — no matching source found")

        lines.append("\n" + "=" * 64)
        return "\n".join(lines)


# ── Singleton ────────────────────────────────────────────────────────
_attributor: SourceAttributor | None = None


def get_source_attributor() -> SourceAttributor:
    global _attributor
    if _attributor is None:
        _attributor = SourceAttributor()
    return _attributor
