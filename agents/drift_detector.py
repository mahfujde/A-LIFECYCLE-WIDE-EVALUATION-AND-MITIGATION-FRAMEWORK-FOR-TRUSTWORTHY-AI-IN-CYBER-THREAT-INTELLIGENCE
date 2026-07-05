"""
Drift Detector Agent — ADWIN concept drift detection
======================================================
Implements ADWIN (Adaptive Windowing) algorithm for detecting
concept drift in CTI analysis performance.

Monitors false positive rate, trust score, and hallucination rate
to detect when the model's environment has shifted.
"""
from __future__ import annotations
import math, time
from collections import deque
from dataclasses import dataclass, field
from typing import Any
import structlog

log = structlog.get_logger()


@dataclass
class DriftSignal:
    """Signal from the drift detector."""
    type: str = "STABLE"          # STABLE, CONCEPT_DRIFT, COVARIATE_SHIFT, NEW_PATTERN
    severity: float = 0.0         # 0-1
    action: str = "NONE"          # NONE, RECALIBRATE, RETRAIN, ALERT
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""


class ADWINDetector:
    """
    Simplified ADWIN (Adaptive Windowing) implementation.
    Detects statistical changes in a data stream by maintaining
    a variable-length window and detecting distribution changes.
    
    Based on: Bifet & Gavaldà (2007), adapted for CTI metrics.
    """

    def __init__(self, delta: float = 0.002) -> None:
        self.delta = delta
        self.window: deque[float] = deque(maxlen=500)
        self.drift_detected = False
        self.drift_count = 0

    def update(self, value: float) -> bool:
        """Add new value and check for drift."""
        self.window.append(value)
        self.drift_detected = False

        if len(self.window) < 10:
            return False

        # Check for distribution change using sliding subwindows
        n = len(self.window)
        values = list(self.window)

        for split in range(max(5, n // 4), n - max(5, n // 4)):
            w0 = values[:split]
            w1 = values[split:]

            mu0 = sum(w0) / len(w0)
            mu1 = sum(w1) / len(w1)

            n0, n1 = len(w0), len(w1)
            m = 1.0 / n0 + 1.0 / n1

            # Hoeffding bound
            epsilon = math.sqrt(m * math.log(2.0 / self.delta) / 2.0)

            if abs(mu0 - mu1) >= epsilon:
                self.drift_detected = True
                self.drift_count += 1
                # Shrink window to recent data
                self.window = deque(values[split:], maxlen=500)
                log.info("adwin_drift", mu0=mu0, mu1=mu1, epsilon=epsilon)
                return True

        return False


class DriftDetectorAgent:
    """
    Monitors multiple performance streams for concept drift.
    Signals the Command Agent when drift is detected.
    """

    def __init__(self, delta: float = 0.002) -> None:
        self.trust_detector = ADWINDetector(delta)
        self.fp_detector = ADWINDetector(delta)
        self.hallucination_detector = ADWINDetector(delta)

        self.trust_history: deque[float] = deque(maxlen=200)
        self.fp_history: deque[float] = deque(maxlen=200)
        self.hall_history: deque[float] = deque(maxlen=200)

        self.drift_events: list[DriftSignal] = []

    def monitor(self, trust_score: float, fp_rate: float = 0.0,
                hallucination_rate: float = 0.0) -> DriftSignal:
        """Monitor all streams and return drift signal."""
        from datetime import datetime, timezone

        self.trust_history.append(trust_score)
        self.fp_history.append(fp_rate)
        self.hall_history.append(hallucination_rate)

        trust_drift = self.trust_detector.update(trust_score / 100.0)
        fp_drift = self.fp_detector.update(fp_rate)
        hall_drift = self.hallucination_detector.update(hallucination_rate)

        signal = DriftSignal(
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        if trust_drift or fp_drift or hall_drift:
            # Classify drift type
            severity = 0.0
            drift_sources = []

            if trust_drift:
                severity += 0.4
                drift_sources.append("trust_score")
            if fp_drift:
                severity += 0.3
                drift_sources.append("false_positive_rate")
            if hall_drift:
                severity += 0.3
                drift_sources.append("hallucination_rate")

            # Determine drift type
            if severity > 0.5:
                signal.type = "CONCEPT_DRIFT"
                signal.action = "RETRAIN" if severity > 0.7 else "RECALIBRATE"
            else:
                signal.type = "COVARIATE_SHIFT"
                signal.action = "RECALIBRATE"

            signal.severity = min(1.0, severity)
            signal.details = {
                "drift_sources": drift_sources,
                "trust_drift": trust_drift,
                "fp_drift": fp_drift,
                "hall_drift": hall_drift,
                "total_drift_events": len(self.drift_events) + 1,
            }

            self.drift_events.append(signal)
            log.warning("drift_detected", type=signal.type,
                        severity=signal.severity, sources=drift_sources)
        else:
            signal.type = "STABLE"
            signal.action = "NONE"

        return signal

    def get_status(self) -> dict[str, Any]:
        return {
            "total_drift_events": len(self.drift_events),
            "trust_observations": len(self.trust_history),
            "latest_trust": list(self.trust_history)[-1] if self.trust_history else None,
            "trust_drifts": self.trust_detector.drift_count,
            "fp_drifts": self.fp_detector.drift_count,
            "hall_drifts": self.hallucination_detector.drift_count,
            "status": self.drift_events[-1].type if self.drift_events else "STABLE",
        }


_detector: DriftDetectorAgent | None = None
def get_drift_detector() -> DriftDetectorAgent:
    global _detector
    if _detector is None:
        _detector = DriftDetectorAgent()
    return _detector
