"""
Log Collector — Structured Pipeline Metrics for Research Evaluation
=====================================================================
Collects per-agent latency, input/output sizes, guard tier scores,
trust scores, hallucination rates, and model metadata from each
pipeline run. Exports clean JSON matching the evaluation schema
for statistical analysis.

Usage:
    from cti_shield.log_collector import get_log_collector

    collector = get_log_collector()
    run = collector.start_run(raw_input, model_mode="demo")
    run.record_agent("KGBuilder", latency_ms=12.3, success=True, ...)
    run.record_guard(tier_scores={...}, hallucination_rate=0.05, ...)
    run.record_metrics(trust_score=72.5, cve_f1=0.95, ...)
    run.finish()

    # Export single run
    collector.export_for_research(run.run_id)

    # Export all runs to research/results/
    collector.export_all()
"""
from __future__ import annotations

import json
import uuid
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from config import BASE_DIR

log = structlog.get_logger(__name__)

RESULTS_DIR = BASE_DIR / "research" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════
# Per-Agent Timing Record
# ═══════════════════════════════════════════════════════════════════════
@dataclass
class AgentTiming:
    """Timing and metadata for a single agent invocation."""
    agent_name: str = ""
    latency_ms: float = 0.0
    success: bool = True
    input_chars: int = 0
    output_chars: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "latency_ms": round(self.latency_ms, 2),
            "success": self.success,
            "input_chars": self.input_chars,
            "output_chars": self.output_chars,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


# ═══════════════════════════════════════════════════════════════════════
# Single Pipeline Run Record
# ═══════════════════════════════════════════════════════════════════════
@dataclass
class PipelineRun:
    """
    Complete metrics record for one pipeline execution.
    Collects agent timings, guard scores, and evaluation metrics.
    """
    run_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    model_mode: str = "demo"
    model_name: str = ""
    retrieval_mode: str = "hybrid"
    input_chars: int = 0
    output_chars: int = 0

    # Per-agent timings
    agents: dict[str, AgentTiming] = field(default_factory=dict)

    # Guard-specific metrics
    guard_passed: bool = False
    guard_retries: int = 0
    tier_scores: dict[str, float] = field(default_factory=dict)
    hallucination_rate: float = 0.0
    claims_checked: int = 0
    claims_grounded: int = 0

    # Trust & drift
    trust_score: float = 0.0
    trust_grade: str = ""
    drift_signal: str = "STABLE"
    confidence: float = 0.0

    # Retrieval metrics
    kg_results_count: int = 0
    vec_results_count: int = 0
    fused_results_count: int = 0
    retrieval_latency_ms: float = 0.0

    # Evaluation metrics (filled when ground truth is available)
    cve_precision: float = 0.0
    cve_recall: float = 0.0
    cve_f1: float = 0.0
    ttp_precision: float = 0.0
    ttp_recall: float = 0.0
    ttp_f1: float = 0.0

    # Pipeline totals
    total_latency_ms: float = 0.0
    escalation: str = "none"

    # Internal
    _start_time: float = field(default_factory=time.time, repr=False)
    _finished: bool = field(default=False, repr=False)

    # ── Recording Methods ────────────────────────────────────────
    def record_agent(
        self,
        agent_name: str,
        latency_ms: float = 0.0,
        success: bool = True,
        input_chars: int = 0,
        output_chars: int = 0,
        **extra,
    ) -> None:
        """Record timing and metadata for a single agent."""
        self.agents[agent_name] = AgentTiming(
            agent_name=agent_name,
            latency_ms=latency_ms,
            success=success,
            input_chars=input_chars,
            output_chars=output_chars,
            metadata=extra,
        )

    def record_guard(
        self,
        passed: bool,
        tier_scores: dict[str, float] | None = None,
        hallucination_rate: float = 0.0,
        claims_checked: int = 0,
        claims_grounded: int = 0,
        retries: int = 0,
    ) -> None:
        """Record hallucination guard results."""
        self.guard_passed = passed
        self.tier_scores = tier_scores or {}
        self.hallucination_rate = hallucination_rate
        self.claims_checked = claims_checked
        self.claims_grounded = claims_grounded
        self.guard_retries = retries

    def record_retrieval(
        self,
        kg_results: int = 0,
        vec_results: int = 0,
        fused_results: int = 0,
        latency_ms: float = 0.0,
        mode: str = "",
    ) -> None:
        """Record hybrid retrieval metrics."""
        self.kg_results_count = kg_results
        self.vec_results_count = vec_results
        self.fused_results_count = fused_results
        self.retrieval_latency_ms = latency_ms
        if mode:
            self.retrieval_mode = mode

    def record_metrics(
        self,
        trust_score: float = 0.0,
        trust_grade: str = "",
        confidence: float = 0.0,
        drift_signal: str = "STABLE",
        escalation: str = "none",
        cve_precision: float = 0.0,
        cve_recall: float = 0.0,
        cve_f1: float = 0.0,
        ttp_precision: float = 0.0,
        ttp_recall: float = 0.0,
        ttp_f1: float = 0.0,
    ) -> None:
        """Record evaluation and trust metrics."""
        self.trust_score = trust_score
        self.trust_grade = trust_grade
        self.confidence = confidence
        self.drift_signal = drift_signal
        self.escalation = escalation
        self.cve_precision = cve_precision
        self.cve_recall = cve_recall
        self.cve_f1 = cve_f1
        self.ttp_precision = ttp_precision
        self.ttp_recall = ttp_recall
        self.ttp_f1 = ttp_f1

    def finish(self) -> None:
        """Mark run as complete, compute final latency."""
        self.total_latency_ms = (time.time() - self._start_time) * 1000
        self._finished = True
        log.info(
            "pipeline_run_finished",
            run_id=self.run_id,
            latency_ms=round(self.total_latency_ms, 1),
            guard_passed=self.guard_passed,
            trust_score=round(self.trust_score, 1),
        )

    # ── Export ────────────────────────────────────────────────────
    def to_research_dict(self) -> dict[str, Any]:
        """
        Export in the exact schema required for evaluation tables.

        Schema:
        {
          "run_id": str,
          "timestamp": ISO8601,
          "model_mode": str,
          "input_chars": int,
          "agents": { agent_name: { "latency_ms": float, "success": bool } },
          "metrics": { ... }
        }
        """
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "model_mode": self.model_mode,
            "model_name": self.model_name,
            "retrieval_mode": self.retrieval_mode,
            "input_chars": self.input_chars,
            "output_chars": self.output_chars,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "agents": {
                name: {"latency_ms": round(t.latency_ms, 2), "success": t.success}
                for name, t in self.agents.items()
            },
            "retrieval": {
                "kg_results": self.kg_results_count,
                "vec_results": self.vec_results_count,
                "fused_results": self.fused_results_count,
                "latency_ms": round(self.retrieval_latency_ms, 2),
                "mode": self.retrieval_mode,
            },
            "guard": {
                "passed": self.guard_passed,
                "retries": self.guard_retries,
                "tier_scores": {
                    k: round(v, 4) for k, v in self.tier_scores.items()
                },
                "claims_checked": self.claims_checked,
                "claims_grounded": self.claims_grounded,
            },
            "metrics": {
                "cve_precision": round(self.cve_precision, 4),
                "cve_recall": round(self.cve_recall, 4),
                "cve_f1": round(self.cve_f1, 4),
                "ttp_precision": round(self.ttp_precision, 4),
                "ttp_recall": round(self.ttp_recall, 4),
                "ttp_f1": round(self.ttp_f1, 4),
                "hallucination_rate": round(self.hallucination_rate, 4),
                "trust_score": round(self.trust_score, 2),
                "trust_grade": self.trust_grade,
                "confidence": round(self.confidence, 4),
                "guard_passed": self.guard_passed,
                "drift_signal": self.drift_signal,
                "escalation": self.escalation,
            },
        }

    def to_full_dict(self) -> dict[str, Any]:
        """Export all data including per-agent detail and metadata."""
        d = self.to_research_dict()
        # Add full agent detail with input/output sizes
        d["agents_detail"] = {
            name: t.to_dict() for name, t in self.agents.items()
        }
        return d

    # ── Summary Statistics ────────────────────────────────────────
    def summary(self) -> dict[str, Any]:
        """Quick summary for console display."""
        agent_latencies = {
            n: round(t.latency_ms, 1) for n, t in self.agents.items()
        }
        return {
            "run_id": self.run_id,
            "total_ms": round(self.total_latency_ms, 1),
            "model": self.model_mode,
            "trust": round(self.trust_score, 1),
            "hallucination": round(self.hallucination_rate, 4),
            "guard": "✅" if self.guard_passed else "❌",
            "agents": agent_latencies,
        }


# ═══════════════════════════════════════════════════════════════════════
# Log Collector — Aggregates multiple pipeline runs
# ═══════════════════════════════════════════════════════════════════════
class LogCollector:
    """
    Central metrics collector for CTI-Shield pipeline runs.

    Aggregates per-run PipelineRun objects, computes cross-run
    summary statistics, and exports clean JSON for research.
    """

    def __init__(self, results_dir: Path | None = None) -> None:
        self.results_dir = results_dir or RESULTS_DIR
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.runs: list[PipelineRun] = []

    def start_run(
        self,
        raw_input: str,
        model_mode: str = "demo",
        model_name: str = "",
        retrieval_mode: str = "hybrid",
    ) -> PipelineRun:
        """Start a new pipeline run and return its record object."""
        run = PipelineRun(
            model_mode=model_mode,
            model_name=model_name,
            retrieval_mode=retrieval_mode,
            input_chars=len(raw_input),
        )
        self.runs.append(run)
        log.info(
            "pipeline_run_started",
            run_id=run.run_id,
            model=model_mode,
            retrieval=retrieval_mode,
        )
        return run

    # ── Populate from Orchestrator result ─────────────────────────
    def record_from_pipeline_result(
        self,
        raw_input: str,
        result: dict[str, Any],
    ) -> PipelineRun:
        """
        Convenience: populate a PipelineRun from the dict returned
        by Orchestrator.run_pipeline(). This is the simplest integration
        path — call this after the pipeline finishes.
        """
        model_mode = result.get("analysis", {}).get("mode", "demo")
        retrieval_info = result.get("retrieval_result", {})

        run = self.start_run(
            raw_input=raw_input,
            model_mode=model_mode,
            model_name=result.get("model_used", ""),
            retrieval_mode=retrieval_info.get("mode", "hybrid"),
        )
        run.output_chars = len(json.dumps(result.get("analysis", {})))

        # ── Record per-agent timings from audit log ──────────────
        for entry in result.get("audit_log", []):
            run.record_agent(
                agent_name=entry.get("agent", "Unknown"),
                latency_ms=entry.get("duration_ms", 0.0),
                success=entry.get("success", True),
            )

        # ── Record guard results ─────────────────────────────────
        guard = result.get("guard_result", {})
        run.record_guard(
            passed=result.get("guard_passed", False),
            tier_scores=guard.get("tier_scores", {}),
            hallucination_rate=guard.get("hallucination_rate", 0.0),
            claims_checked=guard.get("claims_checked", 0),
            claims_grounded=guard.get("claims_grounded", 0),
        )

        # ── Record retrieval metrics ─────────────────────────────
        if retrieval_info:
            run.record_retrieval(
                kg_results=retrieval_info.get("kg_results", 0),
                vec_results=retrieval_info.get("vec_results", 0),
                fused_results=retrieval_info.get("fused_results", 0),
                latency_ms=retrieval_info.get("latency_ms", 0.0),
                mode=retrieval_info.get("mode", ""),
            )

        # ── Record trust / drift / escalation ────────────────────
        run.record_metrics(
            trust_score=result.get("trust_value", 0.0),
            trust_grade=result.get("trust_grade", ""),
            confidence=result.get("confidence", 0.0),
            drift_signal=result.get("drift_signal", "STABLE"),
            escalation=result.get("escalation", "none"),
        )

        run.total_latency_ms = result.get("latency_ms", 0.0)
        run._finished = True
        return run

    # ── Export Methods ────────────────────────────────────────────
    def export_for_research(self, run_id: str) -> dict[str, Any]:
        """
        Export a single run in the clean research evaluation schema.

        Returns the dict matching the user's required schema:
        {
          "run_id", "timestamp", "model_mode", "input_chars",
          "agents": {name: {latency_ms, success}},
          "metrics": {cve_*, ttp_*, hallucination_rate, trust_score, ...}
        }
        """
        run = self._find_run(run_id)
        if run is None:
            raise ValueError(f"Run {run_id} not found in {len(self.runs)} runs")
        return run.to_research_dict()

    def export_run_to_file(self, run_id: str) -> Path:
        """Export a single run to a JSON file in research/results/."""
        data = self.export_for_research(run_id)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self.results_dir / f"run_{run_id}_{ts}.json"
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        log.info("run_exported", path=str(path), run_id=run_id)
        return path

    def export_all(self, filename: str | None = None) -> Path:
        """Export all runs to a single JSON file for batch analysis."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = filename or f"pipeline_runs_{ts}.json"
        path = self.results_dir / filename

        data = {
            "metadata": {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "total_runs": len(self.runs),
                "summary": self.compute_summary(),
            },
            "runs": [r.to_research_dict() for r in self.runs],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        log.info("all_runs_exported", path=str(path), count=len(self.runs))
        return path

    # ── Summary Statistics ────────────────────────────────────────
    def compute_summary(self) -> dict[str, Any]:
        """Compute aggregate statistics across all recorded runs."""
        if not self.runs:
            return {"total_runs": 0}

        n = len(self.runs)
        latencies = [r.total_latency_ms for r in self.runs]
        trust_scores = [r.trust_score for r in self.runs]
        hall_rates = [r.hallucination_rate for r in self.runs]
        guard_pass_count = sum(1 for r in self.runs if r.guard_passed)

        # Per-agent average latency
        agent_latencies: dict[str, list[float]] = {}
        for run in self.runs:
            for name, timing in run.agents.items():
                agent_latencies.setdefault(name, []).append(timing.latency_ms)

        avg_agent = {
            name: {
                "mean_ms": round(sum(vals) / len(vals), 2),
                "max_ms": round(max(vals), 2),
                "min_ms": round(min(vals), 2),
            }
            for name, vals in agent_latencies.items()
        }

        # Model mode distribution
        mode_counts: dict[str, int] = {}
        for r in self.runs:
            mode_counts[r.model_mode] = mode_counts.get(r.model_mode, 0) + 1

        # Retrieval mode distribution
        retrieval_counts: dict[str, int] = {}
        for r in self.runs:
            retrieval_counts[r.retrieval_mode] = (
                retrieval_counts.get(r.retrieval_mode, 0) + 1
            )

        return {
            "total_runs": n,
            "latency": {
                "mean_ms": round(sum(latencies) / n, 2),
                "median_ms": round(sorted(latencies)[n // 2], 2),
                "p95_ms": round(
                    sorted(latencies)[int(n * 0.95)] if n >= 2 else latencies[0], 2
                ),
                "min_ms": round(min(latencies), 2),
                "max_ms": round(max(latencies), 2),
            },
            "trust_score": {
                "mean": round(sum(trust_scores) / n, 2),
                "min": round(min(trust_scores), 2),
                "max": round(max(trust_scores), 2),
            },
            "hallucination_rate": {
                "mean": round(sum(hall_rates) / n, 4),
                "min": round(min(hall_rates), 4),
                "max": round(max(hall_rates), 4),
            },
            "guard_pass_rate": round(guard_pass_count / n, 4),
            "model_modes": mode_counts,
            "retrieval_modes": retrieval_counts,
            "per_agent_latency": avg_agent,
        }

    # ── Internal ─────────────────────────────────────────────────
    def _find_run(self, run_id: str) -> PipelineRun | None:
        for run in self.runs:
            if run.run_id == run_id:
                return run
        return None

    def get_run(self, run_id: str) -> PipelineRun | None:
        """Public accessor for a specific run."""
        return self._find_run(run_id)

    def clear(self) -> None:
        """Clear all recorded runs."""
        self.runs.clear()


# ── Singleton ────────────────────────────────────────────────────────
_collector: LogCollector | None = None


def get_log_collector() -> LogCollector:
    global _collector
    if _collector is None:
        _collector = LogCollector()
    return _collector
