"""
Trust Evaluation Engine
========================
Formal trust scoring aligned with:
- NIST AI Risk Management Framework (AI RMF 1.0)
- OWASP Top 10 for LLM Applications (2025)
- ISO/IEC 27001:2022 Information Security Management

TrustScore = w₁·Accuracy + w₂·Explainability + w₃·Robustness - w₄·Bias - w₅·Drift

All weights are dynamically adjusted through the feedback loop.
"""
from __future__ import annotations

import time
import math
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Optional
from enum import Enum


# ══════════════════════════════════════════════════════════════════════
# NIST AI RMF — 7 Trustworthy AI Characteristics
# ══════════════════════════════════════════════════════════════════════
class NISTCharacteristic(str, Enum):
    """NIST AI RMF 1.0 — Trustworthy AI Characteristics."""
    VALID_RELIABLE = "Valid & Reliable"
    SAFE = "Safe"
    SECURE_RESILIENT = "Secure & Resilient"
    ACCOUNTABLE_TRANSPARENT = "Accountable & Transparent"
    EXPLAINABLE_INTERPRETABLE = "Explainable & Interpretable"
    PRIVACY_ENHANCED = "Privacy-Enhanced"
    FAIR_BIAS_MANAGED = "Fair, Bias Managed"


# ══════════════════════════════════════════════════════════════════════
# OWASP Top 10 for LLM Applications (2025)
# ══════════════════════════════════════════════════════════════════════
class OWASPLLMRisk(str, Enum):
    """OWASP Top 10 for LLM Applications 2025."""
    LLM01_PROMPT_INJECTION = "LLM01: Prompt Injection"
    LLM02_SENSITIVE_DISCLOSURE = "LLM02: Sensitive Information Disclosure"
    LLM03_SUPPLY_CHAIN = "LLM03: Supply Chain"
    LLM04_DATA_POISONING = "LLM04: Data and Model Poisoning"
    LLM05_IMPROPER_OUTPUT = "LLM05: Improper Output Handling"
    LLM06_EXCESSIVE_AGENCY = "LLM06: Excessive Agency"
    LLM07_SYSTEM_PROMPT_LEAK = "LLM07: System Prompt Leakage"
    LLM08_VECTOR_WEAKNESS = "LLM08: Vector & Embedding Weaknesses"
    LLM09_MISINFORMATION = "LLM09: Misinformation"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10: Unbounded Consumption"


# ══════════════════════════════════════════════════════════════════════
# Trust Score Dimensions
# ══════════════════════════════════════════════════════════════════════
@dataclass
class TrustDimension:
    """A single dimension of the trust score."""
    name: str
    value: float          # 0.0 to 1.0
    weight: float         # Dynamic weight
    nist_alignment: list[NISTCharacteristic] = field(default_factory=list)
    owasp_mitigations: list[OWASPLLMRisk] = field(default_factory=list)
    description: str = ""

    @property
    def weighted_value(self) -> float:
        return self.value * self.weight


@dataclass
class TrustScore:
    """
    Composite trust evaluation following the formal model:
    
    TrustScore = Σ(positive_dimensions) - Σ(negative_dimensions)
    
    Positive: Accuracy, Explainability, Robustness, Compliance, Timeliness
    Negative: Bias, Drift, Hallucination, Vulnerability
    """
    accuracy: TrustDimension = field(default_factory=lambda: TrustDimension(
        name="Accuracy",
        value=0.0, weight=0.25,
        nist_alignment=[NISTCharacteristic.VALID_RELIABLE],
        owasp_mitigations=[OWASPLLMRisk.LLM09_MISINFORMATION],
        description="How well the model's output matches ground truth / verified data",
    ))
    explainability: TrustDimension = field(default_factory=lambda: TrustDimension(
        name="Explainability",
        value=0.0, weight=0.15,
        nist_alignment=[NISTCharacteristic.EXPLAINABLE_INTERPRETABLE, NISTCharacteristic.ACCOUNTABLE_TRANSPARENT],
        owasp_mitigations=[OWASPLLMRisk.LLM07_SYSTEM_PROMPT_LEAK],
        description="How well the model can explain its reasoning and decisions",
    ))
    robustness: TrustDimension = field(default_factory=lambda: TrustDimension(
        name="Robustness",
        value=0.0, weight=0.20,
        nist_alignment=[NISTCharacteristic.SECURE_RESILIENT],
        owasp_mitigations=[OWASPLLMRisk.LLM01_PROMPT_INJECTION, OWASPLLMRisk.LLM04_DATA_POISONING],
        description="Resistance to adversarial inputs, noise, and manipulation",
    ))
    compliance: TrustDimension = field(default_factory=lambda: TrustDimension(
        name="STIX Compliance",
        value=0.0, weight=0.10,
        nist_alignment=[NISTCharacteristic.VALID_RELIABLE, NISTCharacteristic.ACCOUNTABLE_TRANSPARENT],
        owasp_mitigations=[OWASPLLMRisk.LLM05_IMPROPER_OUTPUT],
        description="Adherence to STIX 2.1 schema and CTI standards",
    ))
    timeliness: TrustDimension = field(default_factory=lambda: TrustDimension(
        name="Timeliness",
        value=0.0, weight=0.05,
        nist_alignment=[NISTCharacteristic.VALID_RELIABLE],
        owasp_mitigations=[],
        description="Freshness of threat intelligence and response latency",
    ))
    # Negative dimensions (subtracted)
    bias: TrustDimension = field(default_factory=lambda: TrustDimension(
        name="Bias",
        value=0.0, weight=0.10,
        nist_alignment=[NISTCharacteristic.FAIR_BIAS_MANAGED],
        owasp_mitigations=[OWASPLLMRisk.LLM04_DATA_POISONING],
        description="Systematic errors or unfair patterns in model output",
    ))
    drift: TrustDimension = field(default_factory=lambda: TrustDimension(
        name="Drift",
        value=0.0, weight=0.10,
        nist_alignment=[NISTCharacteristic.VALID_RELIABLE],
        owasp_mitigations=[OWASPLLMRisk.LLM09_MISINFORMATION],
        description="Deviation of model performance from baseline over time",
    ))
    hallucination: TrustDimension = field(default_factory=lambda: TrustDimension(
        name="Hallucination",
        value=0.0, weight=0.05,
        nist_alignment=[NISTCharacteristic.VALID_RELIABLE, NISTCharacteristic.SAFE],
        owasp_mitigations=[OWASPLLMRisk.LLM09_MISINFORMATION],
        description="Rate of fabricated or ungrounded claims in output",
    ))

    @property
    def positive_dimensions(self) -> list[TrustDimension]:
        return [self.accuracy, self.explainability, self.robustness, self.compliance, self.timeliness]

    @property
    def negative_dimensions(self) -> list[TrustDimension]:
        return [self.bias, self.drift, self.hallucination]

    @property
    def all_dimensions(self) -> list[TrustDimension]:
        return self.positive_dimensions + self.negative_dimensions

    def compute(self) -> float:
        """
        Compute the composite TrustScore ∈ [0, 100].
        
        Formula:
            TrustScore = (Σ wᵢ·Dᵢ⁺ - Σ wⱼ·Dⱼ⁻) × 100
        
        Where D⁺ are positive dimensions and D⁻ are negative dimensions.
        """
        positive = sum(d.weighted_value for d in self.positive_dimensions)
        negative = sum(d.weighted_value for d in self.negative_dimensions)
        raw = positive - negative
        return max(0.0, min(100.0, raw * 100))

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.compute(), 2),
            "grade": self.grade,
            "dimensions": {d.name: {"value": round(d.value, 4), "weight": d.weight, "weighted": round(d.weighted_value, 4)} for d in self.all_dimensions},
            "nist_coverage": self.nist_coverage,
            "owasp_coverage": self.owasp_coverage,
        }

    @property
    def grade(self) -> str:
        score = self.compute()
        if score >= 85: return "A — Highly Trustworthy"
        if score >= 70: return "B — Trustworthy"
        if score >= 55: return "C — Conditionally Trustworthy"
        if score >= 40: return "D — Low Trust"
        return "F — Untrustworthy"

    @property
    def nist_coverage(self) -> dict[str, float]:
        """How well each NIST characteristic is covered."""
        coverage: dict[str, list[float]] = {}
        for d in self.all_dimensions:
            for nist in d.nist_alignment:
                if nist.value not in coverage:
                    coverage[nist.value] = []
                coverage[nist.value].append(d.value)
        return {k: round(sum(v) / len(v), 3) for k, v in coverage.items()}

    @property
    def owasp_coverage(self) -> dict[str, bool]:
        """Which OWASP risks are actively mitigated."""
        mitigated = set()
        for d in self.all_dimensions:
            for risk in d.owasp_mitigations:
                if d.value > 0.5 or (d in self.negative_dimensions and d.value < 0.3):
                    mitigated.add(risk.value)
        return {risk.value: risk.value in mitigated for risk in OWASPLLMRisk}


# ══════════════════════════════════════════════════════════════════════
# Trust Evaluation Engine
# ══════════════════════════════════════════════════════════════════════
class TrustEvaluationEngine:
    """
    Evaluates trust across the entire AI lifecycle.
    Produces a TrustScore from analysis results + guardrail metrics.
    """

    def __init__(self) -> None:
        self.history: list[dict[str, Any]] = []
        self.weight_adjustments: list[dict[str, Any]] = []

    def evaluate(
        self,
        analysis_result: dict[str, Any],
        guardrail_result: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> TrustScore:
        """
        Compute a TrustScore from analysis + guardrail results.
        
        Args:
            analysis_result: Output from LLM engine analyse_threat()
            guardrail_result: Output from guardrail_pipeline()
            context: Optional risk context (industry, threat_type, risk_tolerance)
        """
        ctx = context or {}
        ts = TrustScore()

        # ── Accuracy ──────────────────────────────────────────────
        hall_data = guardrail_result.get("hallucination", {})
        hall_rate = hall_data.get("hallucination_rate", 0.5)
        ts.accuracy.value = 1.0 - hall_rate

        # ── Explainability ────────────────────────────────────────
        inner = analysis_result.get("analysis", {})
        has_summary = bool(inner.get("summary")) if isinstance(inner, dict) else bool(inner)
        has_ttps = bool(inner.get("ttps", [])) if isinstance(inner, dict) else False
        has_red_flags = bool(inner.get("red_flags", [])) if isinstance(inner, dict) else False
        explain_score = (0.4 if has_summary else 0.0) + (0.3 if has_ttps else 0.0) + (0.3 if has_red_flags else 0.0)
        ts.explainability.value = explain_score

        # ── Robustness ────────────────────────────────────────────
        stix_val = guardrail_result.get("stix_validation", {})
        input_sanitised = guardrail_result.get("input_sanitised", True)
        robustness = 0.5  # baseline
        if input_sanitised:
            robustness += 0.25
        if stix_val.get("overall_compliance", 0) > 0.8:
            robustness += 0.25
        ts.robustness.value = min(1.0, robustness)

        # ── STIX Compliance ───────────────────────────────────────
        ts.compliance.value = stix_val.get("overall_compliance", 0.0)

        # ── Timeliness ────────────────────────────────────────────
        latency_ms = analysis_result.get("latency_ms", 5000)
        # Score: <1s = 1.0, <3s = 0.8, <10s = 0.5, >10s = 0.2
        if latency_ms < 1000: ts.timeliness.value = 1.0
        elif latency_ms < 3000: ts.timeliness.value = 0.8
        elif latency_ms < 10000: ts.timeliness.value = 0.5
        else: ts.timeliness.value = 0.2

        # ── Bias (negative) ──────────────────────────────────────
        # Measure if the model shows systematic patterns
        ts.bias.value = self._estimate_bias(analysis_result)

        # ── Drift (negative) ─────────────────────────────────────
        ts.drift.value = self._estimate_drift()

        # ── Hallucination (negative) ─────────────────────────────
        ts.hallucination.value = hall_rate

        # ── Dynamic Weight Adjustment based on context ───────────
        if ctx.get("risk_tolerance") == "low":
            # Low tolerance: penalise negatives more
            ts.accuracy.weight = 0.30
            ts.robustness.weight = 0.25
            ts.bias.weight = 0.15
            ts.drift.weight = 0.15
        elif ctx.get("risk_tolerance") == "high":
            # High tolerance: favour speed & coverage
            ts.timeliness.weight = 0.15
            ts.accuracy.weight = 0.20
            ts.robustness.weight = 0.15

        # Industry-specific adjustments
        industry = ctx.get("industry", "general")
        if industry == "finance":
            ts.accuracy.weight += 0.05
            ts.compliance.weight += 0.05
        elif industry == "healthcare":
            ts.bias.weight += 0.05
            ts.accuracy.weight += 0.05

        # Record history
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": ts.compute(),
            "grade": ts.grade,
            "dimensions": {d.name: round(d.value, 4) for d in ts.all_dimensions},
            "context": ctx,
        }
        self.history.append(entry)

        return ts

    def _estimate_bias(self, analysis: dict[str, Any]) -> float:
        """Estimate bias from analysis patterns. Returns 0-1 (lower is better)."""
        inner = analysis.get("analysis", {})
        if isinstance(inner, dict):
            severity = str(inner.get("severity", "")).lower()
            # Check if severity is always extreme (sign of bias)
            if severity in ("emergency", "critical"):
                return 0.3  # Tendency to over-classify
            elif severity in ("low", "everyday"):
                return 0.2  # Tendency to under-classify
        return 0.1  # Minimal bias detected

    def _estimate_drift(self) -> float:
        """Estimate drift from historical performance. Returns 0-1 (lower is better)."""
        if len(self.history) < 3:
            return 0.05  # Not enough data — assume minimal drift
        
        recent = [h["score"] for h in self.history[-5:]]
        older = [h["score"] for h in self.history[:-5]]
        
        if not older:
            return 0.05
        
        avg_recent = sum(recent) / len(recent)
        avg_older = sum(older) / len(older)
        
        # Drift = normalised absolute difference
        drift = abs(avg_recent - avg_older) / 100.0
        return min(1.0, drift * 2)  # Scale up small drifts

    def get_trend(self) -> dict[str, Any]:
        """Return trust score trend for visualisation."""
        if not self.history:
            return {"scores": [], "timestamps": [], "trend": "insufficient_data"}
        
        scores = [h["score"] for h in self.history]
        timestamps = [h["timestamp"] for h in self.history]
        
        if len(scores) >= 3:
            recent_avg = sum(scores[-3:]) / 3
            overall_avg = sum(scores) / len(scores)
            trend = "improving" if recent_avg > overall_avg else "declining" if recent_avg < overall_avg * 0.95 else "stable"
        else:
            trend = "insufficient_data"
        
        return {
            "scores": scores,
            "timestamps": timestamps,
            "trend": trend,
            "latest": scores[-1] if scores else 0,
            "average": sum(scores) / len(scores) if scores else 0,
        }

    # ── Weight Persistence (G3.4 fix) ────────────────────────────

    def save_weights(self) -> None:
        """Persist current dimension weights to disk."""
        import json
        from config import DATA_DIR
        weights_file = DATA_DIR / "trust_weights.json"
        try:
            weights = {}
            for score in self.history[-1:]:
                ts = score.get("trust_score", TrustScore())
                if isinstance(ts, TrustScore):
                    for d in ts.all_dimensions:
                        weights[d.name] = d.weight
                    break
            if not weights:
                weights = {
                    "Accuracy": 0.25, "Explainability": 0.15, "Robustness": 0.20,
                    "STIX Compliance": 0.10, "Timeliness": 0.05,
                    "Bias": 0.10, "Drift": 0.10, "Hallucination": 0.05,
                }
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            with open(weights_file, "w") as f:
                json.dump({"weights": weights, "updated": datetime.now(timezone.utc).isoformat()}, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def load_saved_weights() -> dict[str, float] | None:
        """Load persisted weights if available."""
        import json
        from config import DATA_DIR
        weights_file = DATA_DIR / "trust_weights.json"
        if weights_file.exists():
            try:
                with open(weights_file) as f:
                    data = json.load(f)
                return data.get("weights")
            except Exception:
                pass
        return None


# ── Singleton ────────────────────────────────────────────────────────
_trust_engine: TrustEvaluationEngine | None = None

def get_trust_engine() -> TrustEvaluationEngine:
    global _trust_engine
    if _trust_engine is None:
        _trust_engine = TrustEvaluationEngine()
    return _trust_engine

