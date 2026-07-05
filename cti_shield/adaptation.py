"""
Input Adaptation & Feedback Loop
==================================
Layer A: Input Adaptation — adjusts model selection, thresholds, strategies
Layer C: Feedback Loop — auto-adjusts based on performance, drift, user feedback

This is the core "dynamic" component that makes CTI-SHIELD adaptive.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any


# ══════════════════════════════════════════════════════════════════════
# LAYER A — Input Adaptation Engine
# ══════════════════════════════════════════════════════════════════════

# Industry-specific threat profiles
INDUSTRY_PROFILES: dict[str, dict[str, Any]] = {
    "finance": {
        "label": "Finance & Banking",
        "icon": "🏦",
        "high_risk_threats": ["phishing", "credential_theft", "insider_threat", "ransomware"],
        "sensitivity_multiplier": 1.3,
        "default_thresholds": {
            "hallucination_max": 0.10,
            "stix_compliance_min": 0.95,
            "token_overlap_min": 0.50,
        },
        "recommended_model_size": "large",
        "compliance_standards": ["PCI-DSS", "SOX", "GLBA"],
    },
    "healthcare": {
        "label": "Healthcare",
        "icon": "🏥",
        "high_risk_threats": ["ransomware", "data_breach", "supply_chain", "insider_threat"],
        "sensitivity_multiplier": 1.4,
        "default_thresholds": {
            "hallucination_max": 0.08,
            "stix_compliance_min": 0.95,
            "token_overlap_min": 0.55,
        },
        "recommended_model_size": "large",
        "compliance_standards": ["HIPAA", "HITECH"],
    },
    "government": {
        "label": "Government & Defence",
        "icon": "🏛️",
        "high_risk_threats": ["apt", "espionage", "supply_chain", "zero_day"],
        "sensitivity_multiplier": 1.5,
        "default_thresholds": {
            "hallucination_max": 0.05,
            "stix_compliance_min": 0.98,
            "token_overlap_min": 0.60,
        },
        "recommended_model_size": "large",
        "compliance_standards": ["NIST 800-53", "FedRAMP", "CMMC"],
    },
    "education": {
        "label": "Education",
        "icon": "🎓",
        "high_risk_threats": ["phishing", "credential_theft", "ransomware"],
        "sensitivity_multiplier": 1.0,
        "default_thresholds": {
            "hallucination_max": 0.20,
            "stix_compliance_min": 0.85,
            "token_overlap_min": 0.35,
        },
        "recommended_model_size": "medium",
        "compliance_standards": ["FERPA"],
    },
    "technology": {
        "label": "Technology & SaaS",
        "icon": "💻",
        "high_risk_threats": ["supply_chain", "zero_day", "apt", "credential_theft"],
        "sensitivity_multiplier": 1.2,
        "default_thresholds": {
            "hallucination_max": 0.12,
            "stix_compliance_min": 0.90,
            "token_overlap_min": 0.45,
        },
        "recommended_model_size": "large",
        "compliance_standards": ["SOC 2", "ISO 27001"],
    },
    "general": {
        "label": "General / Personal",
        "icon": "🌐",
        "high_risk_threats": ["phishing", "malware", "credential_theft"],
        "sensitivity_multiplier": 1.0,
        "default_thresholds": {
            "hallucination_max": 0.25,
            "stix_compliance_min": 0.80,
            "token_overlap_min": 0.30,
        },
        "recommended_model_size": "any",
        "compliance_standards": [],
    },
}

# Threat type profiles
THREAT_PROFILES: dict[str, dict[str, Any]] = {
    "phishing": {
        "label": "Phishing / Social Engineering",
        "icon": "🎣",
        "detection_signals": ["urgency", "payment", "verify", "account", "login", "password", "bank"],
        "mitre_tactics": ["Initial Access"],
        "recommended_analysis": "email_analysis",
        "sensitivity_boost": 0.2,
    },
    "malware": {
        "label": "Malware / Ransomware",
        "icon": "🦠",
        "detection_signals": ["encrypt", "ransom", "payload", "dropper", "c2", "beacon", "persistence"],
        "mitre_tactics": ["Execution", "Persistence", "Impact"],
        "recommended_analysis": "binary_analysis",
        "sensitivity_boost": 0.3,
    },
    "apt": {
        "label": "Advanced Persistent Threat",
        "icon": "🎯",
        "detection_signals": ["nation-state", "espionage", "lateral movement", "exfiltration", "zero-day"],
        "mitre_tactics": ["Initial Access", "Persistence", "Lateral Movement", "Exfiltration"],
        "recommended_analysis": "deep_analysis",
        "sensitivity_boost": 0.4,
    },
    "credential_theft": {
        "label": "Credential Theft / Stuffing",
        "icon": "🔑",
        "detection_signals": ["brute force", "credential", "password spray", "stolen credentials"],
        "mitre_tactics": ["Credential Access"],
        "recommended_analysis": "credential_analysis",
        "sensitivity_boost": 0.15,
    },
    "supply_chain": {
        "label": "Supply Chain Attack",
        "icon": "📦",
        "detection_signals": ["supply chain", "dependency", "upstream", "compromised library"],
        "mitre_tactics": ["Initial Access", "Execution"],
        "recommended_analysis": "supply_chain_analysis",
        "sensitivity_boost": 0.35,
    },
    "insider_threat": {
        "label": "Insider Threat",
        "icon": "🕵️",
        "detection_signals": ["insider", "privileged", "unauthorized access", "data exfiltration"],
        "mitre_tactics": ["Collection", "Exfiltration"],
        "recommended_analysis": "behavioral_analysis",
        "sensitivity_boost": 0.25,
    },
    "auto_detect": {
        "label": "Auto-Detect",
        "icon": "🔍",
        "detection_signals": [],
        "mitre_tactics": [],
        "recommended_analysis": "general_analysis",
        "sensitivity_boost": 0.0,
    },
}

RISK_TOLERANCE_LEVELS = {
    "low": {"label": "Low Risk Tolerance (Strict)", "icon": "🔴", "multiplier": 1.5, "description": "Maximum security — flag everything suspicious"},
    "medium": {"label": "Medium Risk Tolerance", "icon": "🟡", "multiplier": 1.0, "description": "Balanced — standard detection thresholds"},
    "high": {"label": "High Risk Tolerance (Relaxed)", "icon": "🟢", "multiplier": 0.7, "description": "Minimal alerts — only flag critical threats"},
}

DATA_SOURCES = {
    "logs": {"label": "System Logs / SIEM", "icon": "📋", "weight": 0.9},
    "osint": {"label": "OSINT / Open Sources", "icon": "🌐", "weight": 0.7},
    "email": {"label": "Email / Communication", "icon": "📧", "weight": 0.8},
    "network": {"label": "Network Traffic", "icon": "🔌", "weight": 0.85},
    "manual": {"label": "Manual Input / Paste", "icon": "📝", "weight": 0.6},
}


@dataclass
class AdaptationContext:
    """User-defined risk context that drives system adaptation."""
    industry: str = "general"
    threat_type: str = "auto_detect"
    risk_tolerance: str = "medium"
    data_source: str = "manual"

    @property
    def industry_profile(self) -> dict[str, Any]:
        return INDUSTRY_PROFILES.get(self.industry, INDUSTRY_PROFILES["general"])

    @property
    def threat_profile(self) -> dict[str, Any]:
        return THREAT_PROFILES.get(self.threat_type, THREAT_PROFILES["auto_detect"])

    @property
    def risk_config(self) -> dict[str, Any]:
        return RISK_TOLERANCE_LEVELS.get(self.risk_tolerance, RISK_TOLERANCE_LEVELS["medium"])

    @property
    def source_config(self) -> dict[str, Any]:
        return DATA_SOURCES.get(self.data_source, DATA_SOURCES["manual"])

    def compute_thresholds(self) -> dict[str, float]:
        """Compute dynamic detection thresholds based on context."""
        base = self.industry_profile["default_thresholds"].copy()
        risk_mult = self.risk_config["multiplier"]
        sensitivity_boost = self.threat_profile["sensitivity_boost"]
        industry_mult = self.industry_profile["sensitivity_multiplier"]

        # Adjust hallucination threshold (lower = stricter)
        base["hallucination_max"] = max(0.01, base["hallucination_max"] / (risk_mult * industry_mult))

        # Adjust compliance threshold (higher = stricter)
        base["stix_compliance_min"] = min(0.99, base["stix_compliance_min"] * (1 + sensitivity_boost * 0.1))

        # Adjust token overlap (higher = stricter)
        base["token_overlap_min"] = min(0.95, base["token_overlap_min"] + sensitivity_boost * 0.1)

        # Source reliability factor
        source_weight = self.source_config.get("weight", 0.6)
        base["source_reliability"] = source_weight

        return base

    def to_dict(self) -> dict[str, Any]:
        return {
            "industry": self.industry,
            "industry_label": self.industry_profile.get("label"),
            "threat_type": self.threat_type,
            "threat_label": self.threat_profile.get("label"),
            "risk_tolerance": self.risk_tolerance,
            "risk_label": self.risk_config.get("label"),
            "data_source": self.data_source,
            "data_source_label": self.source_config.get("label"),
            "computed_thresholds": self.compute_thresholds(),
            "compliance_standards": self.industry_profile.get("compliance_standards", []),
        }


def auto_detect_threat_type(text: str) -> str:
    """Auto-detect threat type from input text."""
    text_lower = text.lower()
    best_match = "auto_detect"
    best_score = 0

    for threat_id, profile in THREAT_PROFILES.items():
        if threat_id == "auto_detect":
            continue
        signals = profile.get("detection_signals", [])
        score = sum(1 for s in signals if s in text_lower)
        if score > best_score:
            best_score = score
            best_match = threat_id

    return best_match if best_score >= 2 else "auto_detect"


# ══════════════════════════════════════════════════════════════════════
# LAYER C — Feedback Loop System
# ══════════════════════════════════════════════════════════════════════

@dataclass
class FeedbackEntry:
    """A single feedback data point."""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trust_score: float = 0.0
    hallucination_rate: float = 0.0
    false_positive_rate: float = 0.0
    user_rating: int = 0        # 1-5 scale, 0 = no rating
    accuracy_verified: bool = False
    response_useful: bool = True
    context: dict[str, Any] = field(default_factory=dict)


class FeedbackLoop:
    """
    Adaptive feedback loop that adjusts system behavior based on:
    1. Model performance trends (accuracy, hallucination)
    2. Drift detection (performance degradation)
    3. User feedback (ratings, corrections)
    
    Implements EWMA (Exponentially Weighted Moving Average) for smooth adaptation.
    """

    def __init__(self, alpha: float = 0.3) -> None:
        self.alpha = alpha  # EWMA smoothing factor
        self.feedback_history: list[FeedbackEntry] = []
        self.weight_history: list[dict[str, float]] = []
        
        # Current adaptive weights
        self.weights = {
            "accuracy": 0.25,
            "explainability": 0.15,
            "robustness": 0.20,
            "compliance": 0.10,
            "timeliness": 0.05,
            "bias": 0.10,
            "drift": 0.10,
            "hallucination": 0.05,
        }
        
        # Adaptive thresholds
        self.thresholds = {
            "hallucination_warning": 0.20,
            "hallucination_critical": 0.40,
            "drift_warning": 0.15,
            "drift_critical": 0.30,
            "min_trust_score": 40.0,
        }

    def record_feedback(self, entry: FeedbackEntry) -> dict[str, Any]:
        """Record feedback and trigger adaptation."""
        self.feedback_history.append(entry)
        adjustments = self._adapt(entry)
        return adjustments

    def _adapt(self, latest: FeedbackEntry) -> dict[str, Any]:
        """Core adaptation logic using EWMA."""
        adjustments: dict[str, Any] = {"actions": [], "weight_changes": {}, "threshold_changes": {}}

        # ── Hallucination-based adaptation ────────────────────────
        if latest.hallucination_rate > self.thresholds["hallucination_critical"]:
            # Critical: Increase accuracy weight, decrease tolerance
            delta = 0.05
            self.weights["accuracy"] = min(0.40, self.weights["accuracy"] + delta)
            self.weights["hallucination"] = min(0.15, self.weights["hallucination"] + delta)
            self.thresholds["hallucination_warning"] = max(0.05, self.thresholds["hallucination_warning"] - 0.03)
            adjustments["actions"].append("🔴 Critical hallucination rate — increased accuracy weight, tightened thresholds")
        elif latest.hallucination_rate > self.thresholds["hallucination_warning"]:
            delta = 0.02
            self.weights["accuracy"] = min(0.35, self.weights["accuracy"] + delta)
            adjustments["actions"].append("⚠️ Elevated hallucination — slightly increased accuracy weight")

        # ── False positive adaptation ─────────────────────────────
        if latest.false_positive_rate > 0.3:
            # Too many false positives → reduce sensitivity
            self.thresholds["hallucination_warning"] = min(0.35, self.thresholds["hallucination_warning"] + 0.02)
            adjustments["actions"].append("📉 High false positive rate — reduced detection sensitivity")
        elif latest.false_positive_rate < 0.05 and len(self.feedback_history) > 5:
            # Very few FPs → can increase sensitivity
            self.thresholds["hallucination_warning"] = max(0.08, self.thresholds["hallucination_warning"] - 0.01)
            adjustments["actions"].append("📈 Low false positives — slightly increased sensitivity")

        # ── User feedback integration ─────────────────────────────
        if latest.user_rating > 0:
            if latest.user_rating <= 2:
                self.weights["explainability"] = min(0.25, self.weights["explainability"] + 0.02)
                adjustments["actions"].append("👎 Low user rating — boosted explainability weight")
            elif latest.user_rating >= 4:
                adjustments["actions"].append("👍 Positive user feedback — weights validated")

        # ── Drift-based adaptation ────────────────────────────────
        if len(self.feedback_history) >= 5:
            recent_scores = [f.trust_score for f in self.feedback_history[-5:]]
            ewma_score = self._ewma(recent_scores)
            overall_avg = sum(f.trust_score for f in self.feedback_history) / len(self.feedback_history)
            
            drift = abs(ewma_score - overall_avg) / max(overall_avg, 1)
            if drift > self.thresholds["drift_critical"]:
                self.weights["drift"] = min(0.20, self.weights["drift"] + 0.03)
                adjustments["actions"].append(f"🔴 Significant drift detected ({drift:.1%}) — increased drift weight")
            elif drift > self.thresholds["drift_warning"]:
                adjustments["actions"].append(f"⚠️ Mild drift detected ({drift:.1%}) — monitoring")

        # Normalise weights to sum to 1.0
        self._normalise_weights()
        
        adjustments["weight_changes"] = self.weights.copy()
        adjustments["threshold_changes"] = self.thresholds.copy()
        self.weight_history.append(self.weights.copy())

        return adjustments

    def _ewma(self, values: list[float]) -> float:
        """Exponentially Weighted Moving Average."""
        if not values:
            return 0.0
        ewma = values[0]
        for v in values[1:]:
            ewma = self.alpha * v + (1 - self.alpha) * ewma
        return ewma

    def _normalise_weights(self) -> None:
        """Normalise all weights to sum to 1.0."""
        total = sum(self.weights.values())
        if total > 0:
            for k in self.weights:
                self.weights[k] /= total

    def get_current_weights(self) -> dict[str, float]:
        return {k: round(v, 4) for k, v in self.weights.items()}

    def get_adaptation_summary(self) -> dict[str, Any]:
        """Summary of all adaptations made."""
        return {
            "total_feedback_entries": len(self.feedback_history),
            "total_weight_adjustments": len(self.weight_history),
            "current_weights": self.get_current_weights(),
            "current_thresholds": {k: round(v, 4) for k, v in self.thresholds.items()},
            "avg_trust_score": round(sum(f.trust_score for f in self.feedback_history) / max(len(self.feedback_history), 1), 2),
            "avg_hallucination": round(sum(f.hallucination_rate for f in self.feedback_history) / max(len(self.feedback_history), 1), 4),
        }


# ── Singleton ────────────────────────────────────────────────────────
_feedback_loop: FeedbackLoop | None = None

def get_feedback_loop() -> FeedbackLoop:
    global _feedback_loop
    if _feedback_loop is None:
        _feedback_loop = FeedbackLoop()
    return _feedback_loop
