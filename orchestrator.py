"""
CTI-Shield v3 Orchestrator — Multi-Agent Pipeline
===================================================
Connects all 8 agents in a 5-layer pipeline with 3 feedback loops:

  Input → Command → KG Build → OSINT → Hybrid Retrieve → Reason → Guard → Drift → Learn → Output

Based on AgentSOC (IEEE 2026) sense-reason-act loop,
Phoenix Security pipeline architecture [21],
and LangGraph stateful workflow patterns.

Guard failure triggers retry (max 3), then human escalation.
Drift detection can trigger urgent KG rebuild or weight recalibration.
Hybrid Retrieval: FAISS vector search + KG graph search with RRF fusion.
"""
from __future__ import annotations
import time
from typing import Any
import structlog

from agents.command_agent import (
    get_command_agent, PipelineState, ActionType, EscalationLevel,
)
from agents.kg_builder import get_kg_builder
from agents.threat_reasoner import get_threat_reasoner
from agents.hallucination_guard import get_hallucination_guard
from agents.drift_detector import get_drift_detector
from agents.learning_agent import get_learning_agent, AnalystFeedback
from agents.osint_agent import get_osint_agent
from cti_shield.llm_engine import get_engine
from cti_shield.preprocessing import clean_text, extract_iocs
from cti_shield.explainer import explain_threat
from cti_shield.trust_engine import get_trust_engine
from cti_shield.lifecycle import get_lifecycle_engine
from cti_shield.adaptation import (
    AdaptationContext, auto_detect_threat_type,
    get_feedback_loop, FeedbackEntry,
)
from cti_shield.log_collector import get_log_collector
from cti_shield.source_attributor import get_source_attributor

log = structlog.get_logger()


class Orchestrator:
    """
    Multi-agent orchestrator implementing the full CTI-Shield v3 pipeline.
    
    8-Agent Pipeline (5 Layers):
    1. Command Agent  — classify, init state, enforce policy
    2. KG Builder     — extract entities/triples from input
    3. OSINT Agent    — real-time CVE/IOC/ATT&CK enrichment
    4. Threat Reasoner — GraphRAG + LLM analysis
    5. Hallucination Guard — 3-tier validation
    6. Drift Detector — ADWIN monitoring
    7. Learning Agent — feedback integration
    8. Output — explanation, STIX, trust score
    """

    def __init__(self) -> None:
        self.command = get_command_agent()
        self.kg_builder = get_kg_builder()
        self.osint = get_osint_agent()
        self.reasoner = get_threat_reasoner()
        self.guard = get_hallucination_guard()
        self.drift = get_drift_detector()
        self.learner = get_learning_agent()
        self.llm_engine = get_engine()
        self.trust_engine = get_trust_engine()
        self.lifecycle_engine = get_lifecycle_engine()
        self.feedback_loop = get_feedback_loop()
        self.log_collector = get_log_collector()
        self.source_attributor = get_source_attributor()

        # Auto-build FAISS index from MITRE ATT&CK if not already indexed
        self._ensure_vector_index()

    def _ensure_vector_index(self) -> None:
        """Ensure FAISS vector store is populated with ATT&CK corpus."""
        try:
            from cti_shield.rag import get_vector_store
            store = get_vector_store()
            if store.total_vectors == 0:
                log.info("vector_store_empty_building_corpus")
                from cti_shield.corpus_builder import build_and_index_corpus
                count = build_and_index_corpus()
                log.info("vector_store_initialized", vectors=count)
            else:
                log.info("vector_store_loaded", vectors=store.total_vectors)
        except Exception as e:
            log.warning("vector_store_init_failed", error=str(e))

    def _compute_stix_compliance(self, stix_objects: list[dict]) -> dict:
        """A7: Compute real STIX 2.1 compliance instead of hardcoded 0.9."""
        if not stix_objects:
            return {"overall_compliance": 0.0, "total": 0, "valid": 0}
        required = {"type", "id"}
        recommended = {"created", "modified", "name"}
        valid = 0
        for obj in stix_objects:
            if isinstance(obj, dict) and required.issubset(obj.keys()):
                valid += 1
        compliance = valid / len(stix_objects) if stix_objects else 0.0
        return {
            "overall_compliance": round(compliance, 4),
            "total": len(stix_objects),
            "valid": valid,
        }

    def run_pipeline(
        self,
        raw_input: str,
        context: dict[str, Any] | None = None,
        audience: str = "general",
        progress_callback: Any | None = None,
        cancel_event: Any | None = None,
    ) -> dict[str, Any]:
        """
        Execute the full 7-agent pipeline.
        
        Args:
            progress_callback: Optional callable(stage_name, step, total, detail)
                               called at each pipeline stage for UI progress.
            cancel_event: Optional threading.Event; if set, pipeline aborts early.
        
        Returns a comprehensive result dict with analysis, trust score,
        lifecycle report, guard results, drift signal, and audit log.
        """
        t0 = time.time()
        ctx = context or {}
        _total = 8  # total pipeline stages

        def _progress(name: str, step: int, detail: str = ""):
            if progress_callback:
                try:
                    progress_callback(name, step, _total, detail)
                except Exception:
                    pass

        def _cancelled() -> bool:
            return cancel_event is not None and cancel_event.is_set()

        # ═══════════════════════════════════════════════════════════
        # STAGE 1: COMMAND AGENT — Initialize & classify
        # ═══════════════════════════════════════════════════════════
        _progress("🎯 Command Agent — Initializing & classifying input", 1, "Creating pipeline state")
        if _cancelled(): return {"cancelled": True}
        state = self.command.create_state(raw_input, ctx)

        # Auto-detect threat type
        adapt_ctx = AdaptationContext(
            industry=ctx.get("industry", "general"),
            threat_type=ctx.get("threat_type", "auto_detect"),
            risk_tolerance=ctx.get("risk_tolerance", "medium"),
            data_source=ctx.get("data_source", "manual"),
        )
        if adapt_ctx.threat_type == "auto_detect":
            detected = auto_detect_threat_type(raw_input)
            if detected != "auto_detect":
                adapt_ctx.threat_type = detected
                state.log_action("CommandAgent", "auto_detect_threat",
                                 metadata={"detected": detected})

        # ═══════════════════════════════════════════════════════════
        # STAGE 2: PREPROCESSING
        # ═══════════════════════════════════════════════════════════
        _progress("🧹 Preprocessor — Cleaning text & extracting IOCs", 2, "Deduplication, normalization")
        if _cancelled(): return {"cancelled": True}
        state.cleaned_text = clean_text(raw_input)
        state.iocs = extract_iocs(state.cleaned_text)
        state.log_action("Preprocessor", "clean_and_extract",
                         metadata={"ioc_count": sum(len(v) for v in state.iocs.values())})

        # ═══════════════════════════════════════════════════════════
        # STAGE 3: KG BUILDER — Extract triples
        # ═══════════════════════════════════════════════════════════
        _progress("🕸️ KG Builder — Extracting knowledge graph triples", 3, "Entity & TTP extraction")
        if _cancelled(): return {"cancelled": True}
        t_kg = time.time()
        new_triples = self.kg_builder.extract_triples(raw_input, source="pipeline")
        state.kg_triples = [{"s": t.subject, "p": t.predicate, "o": t.obj,
                             "tech": t.technique_id, "conf": t.confidence}
                            for t in new_triples]
        state.log_action("KGBuilder", "extract_triples",
                         duration_ms=(time.time() - t_kg) * 1000,
                         metadata={"triples": len(new_triples)})

        # ═══════════════════════════════════════════════════════════
        # STAGE 3.5: OSINT AGENT — Real-time enrichment
        # ═══════════════════════════════════════════════════════════
        _progress("🌐 OSINT Agent — Querying NVD, CISA KEV, URLhaus", 4, "Live threat enrichment")
        if _cancelled(): return {"cancelled": True}
        t_osint = time.time()
        import re as _re
        import os as _os
        found_cves = list(set(_re.findall(r'CVE-\d{4}-\d{4,7}', raw_input)))
        nlp_ttps = self.kg_builder.extract_nlp_ttps(raw_input)
        if _os.getenv("CTI_SKIP_OSINT", "").lower() in ("1", "true", "yes"):
            # Fast-eval path: skip the live OSINT network enrichment (NVD/URLhaus
            # round-trips dominate wall-clock). The LLM analysis, RAG retrieval,
            # and guard remain fully real — only external enrichment is bypassed.
            from agents.osint_agent import EnrichmentReport
            osint_report = EnrichmentReport()
        else:
            osint_report = self.osint.enrich(
                text=raw_input,
                cves=found_cves,
                ttps=nlp_ttps,
                iocs=state.iocs,
            )
        state.log_action("OSINTAgent", "enrich",
                         duration_ms=(time.time() - t_osint) * 1000,
                         metadata={"sources": osint_report.total_sources_queried,
                                   "found": osint_report.total_enrichments_found})

        # ═══════════════════════════════════════════════════════════
        # STAGE 4: THREAT REASONER — GraphRAG analysis (with retry)
        # ═══════════════════════════════════════════════════════════
        _progress("🧠 Threat Reasoner — LLM analysis with RAG grounding", 5, "Reasoning + TTP mapping")
        if _cancelled(): return {"cancelled": True}
        for attempt in range(self.command.MAX_GUARD_RETRIES + 1):
            t_reason = time.time()
            threat_result = self.reasoner.reason(
                raw_input, self.kg_builder, self.llm_engine, ctx
            )
            state.analysis = threat_result.raw_analysis
            state.analysis["latency_ms"] = threat_result.latency_ms
            state.analysis["mode"] = "api" if threat_result.model_used else "demo"
            state.ttps = threat_result.ttps
            state.stix_objects = threat_result.stix_objects
            state.confidence = threat_result.confidence
            state.model_used = threat_result.model_used
            state.log_action("ThreatReasoner", "analyse",
                             duration_ms=(time.time() - t_reason) * 1000,
                             metadata={"confidence": threat_result.confidence,
                                       "attempt": attempt + 1})

            # ═══════════════════════════════════════════════════════
            # STAGE 5: HALLUCINATION GUARD — 3-tier validation
            # ═══════════════════════════════════════════════════════
            _progress("🛡️ Hallucination Guard — Validating claims", 6, f"Attempt {attempt + 1}")
            if _cancelled(): return {"cancelled": True}
            t_guard = time.time()
            analysis_text = str(state.analysis.get("analysis", ""))
            guard_result = self.guard.validate(
                analysis_text, state.cleaned_text[:2000], state.stix_objects
            )
            state.guard_passed = guard_result.passed
            state.guard_result = {
                "passed": guard_result.passed,
                "tier_failed": guard_result.tier_failed,
                "reason": guard_result.reason,
                "hallucination_rate": guard_result.hallucination_rate,
                "tier_scores": guard_result.tier_scores,
                "claims_checked": guard_result.claims_checked,
                "claims_grounded": guard_result.claims_grounded,
                "hallucination": {
                    "hallucination_rate": guard_result.hallucination_rate,
                    "grounded": guard_result.claims_grounded,
                    "total": guard_result.claims_checked,
                },
                "stix_validation": self._compute_stix_compliance(state.stix_objects),
            }
            state.log_action("HallucinationGuard", "validate",
                             duration_ms=(time.time() - t_guard) * 1000,
                             success=guard_result.passed,
                             metadata={"tier_scores": guard_result.tier_scores})

            if guard_result.passed:
                break
            else:
                state.guard_retries += 1
                if not self.command.should_retry_reasoning(state):
                    state.log_action("CommandAgent", "guard_exhausted")
                    break

        # ═══════════════════════════════════════════════════════════
        # STAGE 6: DRIFT DETECTOR — ADWIN monitoring
        # ═══════════════════════════════════════════════════════════
        _progress("📊 Drift Detector — Monitoring trust & consistency", 7, "ADWIN analysis")
        if _cancelled(): return {"cancelled": True}
        t_drift = time.time()
        
        # Compute trust score first for drift monitoring
        trust_score = self.trust_engine.evaluate(
            state.analysis, state.guard_result,
            context=adapt_ctx.to_dict(),
        )
        state.trust_score = trust_score.compute()

        drift_signal = self.drift.monitor(
            trust_score=state.trust_score,
            fp_rate=0.0,
            hallucination_rate=guard_result.hallucination_rate,
        )
        state.drift_signal = drift_signal.type
        state.log_action("DriftDetector", "monitor",
                         duration_ms=(time.time() - t_drift) * 1000,
                         metadata={"signal": drift_signal.type,
                                   "severity": drift_signal.severity})

        # Handle drift actions
        drift_action = self.command.route_drift_action(state)
        if drift_action == "kg_build":
            state.log_action("CommandAgent", "urgent_kg_rebuild")
        elif drift_action == "recalibrate":
            state.log_action("CommandAgent", "weight_recalibration")

        # ═══════════════════════════════════════════════════════════
        # STAGE 7: POLICY ENFORCEMENT + OUTPUT
        # ═══════════════════════════════════════════════════════════
        _progress("✅ Finalizing — Policy enforcement & output compilation", 8, "STIX + citations")
        state = self.command.enforce_policy(state)

        # Lifecycle evaluation
        lifecycle_report = self.lifecycle_engine.evaluate_full_lifecycle(
            raw_input=raw_input,
            cleaned_text=state.cleaned_text,
            iocs=state.iocs,
            analysis_result=state.analysis,
            guardrail_result=state.guard_result,
            stix_objects=state.stix_objects,
            context=adapt_ctx.to_dict(),
        )

        # Feedback loop
        fb_entry = FeedbackEntry(
            trust_score=state.trust_score,
            hallucination_rate=guard_result.hallucination_rate,
            context=adapt_ctx.to_dict(),
        )
        fb_adjustments = self.feedback_loop.record_feedback(fb_entry)

        # ═══════════════════════════════════════════════════════════
        # STAGE 7.5: SOURCE ATTRIBUTION — RO3 claim provenance
        # ═══════════════════════════════════════════════════════════
        t_attr = time.time()
        analysis_text = str(state.analysis.get("analysis", state.analysis))
        attribution = self.source_attributor.attribute(
            llm_response=analysis_text,
            retrieval_result=threat_result.retrieval_result
                if isinstance(threat_result.retrieval_result, dict) else {},
            source_attributions=threat_result.source_attributions
                if isinstance(threat_result.source_attributions, list) else [],
        )
        state.log_action("SourceAttributor", "attribute",
                         duration_ms=(time.time() - t_attr) * 1000,
                         metadata={"attribution_rate": attribution.attribution_rate,
                                   "total": attribution.total_claims,
                                   "attributed": attribution.attributed_claims})

        # Explanation
        explanation = explain_threat(state.analysis, audience=audience)

        # Final latency
        state.latency_ms = (time.time() - t0) * 1000

        # ═══════════════════════════════════════════════════════════
        # COMPILE FINAL RESULT
        # ═══════════════════════════════════════════════════════════
        final_result = {
            "analysis": state.analysis,
            "explanation": explanation,
            "trust_score": trust_score.to_dict(),
            "trust_value": state.trust_score,
            "trust_grade": trust_score.grade,
            "lifecycle": lifecycle_report.to_dict(),
            "guard_result": state.guard_result,
            "guard_passed": state.guard_passed,
            "drift_signal": drift_signal.type,
            "drift_severity": drift_signal.severity,
            "confidence": state.confidence,
            "escalation": state.escalation.value,
            "iocs": state.iocs,
            "ttps": state.ttps,
            "stix_objects": state.stix_objects,
            "kg_triples": state.kg_triples,
            "nlp_ttps": nlp_ttps,
            "osint_report": osint_report.to_dict(),
            "osint_summary": osint_report.summary,
            "model_used": state.model_used,
            "latency_ms": state.latency_ms,
            "agent_pipeline": [a.agent for a in state.audit_log],
            "audit_log": [
                {"agent": a.agent, "action": a.action,
                 "duration_ms": round(a.duration_ms, 1),
                 "success": a.success, "timestamp": a.timestamp}
                for a in state.audit_log
            ],
            "feedback_adjustments": fb_adjustments,
            "adaptation_context": adapt_ctx.to_dict(),
            # Retrieval & source attribution for RO1/RO2/RO3
            "retrieval_result": threat_result.retrieval_result,
            "source_attributions": threat_result.source_attributions,
            # RO3: Claim-level provenance
            "attributed_claims": attribution.to_dict(),
            "citation_report": self.source_attributor.generate_citation_report(attribution),
        }

        # ═══════════════════════════════════════════════════════════
        # LOG COLLECTOR — Record structured metrics for research
        # ═══════════════════════════════════════════════════════════
        try:
            self.log_collector.record_from_pipeline_result(raw_input, final_result)
        except Exception as e:
            log.warning("log_collector_failed", error=str(e))

        # G7: Persist KG to disk after each pipeline run
        try:
            self.kg_builder.save_to_disk()
        except Exception:
            pass

        return final_result


# Singleton
_orchestrator: Orchestrator | None = None

def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator

def reset_orchestrator() -> None:
    global _orchestrator
    _orchestrator = None
