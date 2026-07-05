"""
Learning Agent — Feedback → weight recalibration
==================================================
Analyst-in-the-loop learning with:
1. Few-shot prompt library updates from corrections
2. TrustScore weight recalibration via gradient descent
3. Performance tracking for continuous improvement
"""
from __future__ import annotations
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any
import structlog

log = structlog.get_logger()


@dataclass
class AnalystFeedback:
    """Feedback from an analyst or user."""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    query: str = ""
    original_analysis: str = ""
    correction: str = ""
    rating: int = 0                 # 1-5
    is_false_positive: bool = False
    is_false_negative: bool = False
    correct_severity: str = ""
    correct_ttps: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class PromptExample:
    """A few-shot example in the prompt library."""
    query: str
    correct_output: str
    incorrect_output: str = ""
    added: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    use_count: int = 0


class LearningAgent:
    """
    Self-improving agent that:
    1. Maintains a few-shot prompt library from corrections
    2. Recalibrates TrustScore weights based on feedback history
    3. Tracks improvement metrics over time
    """

    def __init__(self) -> None:
        self.prompt_library: list[PromptExample] = []
        self.feedback_history: list[AnalystFeedback] = []
        self.weight_history: list[dict[str, float]] = []
        self.current_weights = {
            "accuracy": 0.25,
            "explainability": 0.20,
            "robustness": 0.20,
            "bias": -0.15,
            "drift": -0.10,
            "hallucination": -0.10,
        }
        self.learning_rate = 0.01
        self.corrections_since_recalibration = 0
        self.recalibration_threshold = 10

    def process_feedback(self, feedback: AnalystFeedback) -> dict[str, Any]:
        """Process analyst feedback and trigger learning."""
        self.feedback_history.append(feedback)
        actions = []

        # Update prompt library if correction provided
        if feedback.correction:
            example = PromptExample(
                query=feedback.query[:500],
                correct_output=feedback.correction[:1000],
                incorrect_output=feedback.original_analysis[:1000],
            )
            self.prompt_library.append(example)
            # Keep library manageable
            if len(self.prompt_library) > 50:
                # Remove least-used examples
                self.prompt_library.sort(key=lambda x: x.use_count, reverse=True)
                self.prompt_library = self.prompt_library[:50]
            
            self.corrections_since_recalibration += 1
            actions.append(f"📝 Added correction to prompt library ({len(self.prompt_library)} examples)")

        # Recalibrate weights if threshold reached
        if self.corrections_since_recalibration >= self.recalibration_threshold:
            weight_changes = self.recalibrate_weights()
            self.corrections_since_recalibration = 0
            actions.append(f"⚖️ Recalibrated TrustScore weights: {weight_changes}")

        # Adjust based on rating
        if feedback.rating > 0:
            if feedback.rating <= 2:
                # Poor quality — increase accuracy and explainability weight
                self._adjust_weight("accuracy", 0.01)
                self._adjust_weight("explainability", 0.01)
                actions.append("📉 Low rating — boosted accuracy and explainability")
            elif feedback.rating >= 4:
                actions.append("👍 Positive feedback — weights validated")

        # Track false positives/negatives
        if feedback.is_false_positive:
            self._adjust_weight("accuracy", 0.005)
            self._adjust_weight("bias", -0.005)
            actions.append("⚠️ False positive recorded — adjusting bias weight")
        if feedback.is_false_negative:
            self._adjust_weight("robustness", 0.005)
            actions.append("⚠️ False negative recorded — adjusting robustness weight")

        log.info("feedback_processed", rating=feedback.rating,
                 has_correction=bool(feedback.correction), actions=len(actions))

        return {"actions": actions, "weights": self.current_weights.copy()}

    def recalibrate_weights(self) -> dict[str, float]:
        """Gradient-descent-inspired weight recalibration."""
        changes: dict[str, float] = {}

        if not self.feedback_history:
            return changes

        recent = self.feedback_history[-self.recalibration_threshold:]

        # Compute feedback signals
        avg_rating = sum(f.rating for f in recent if f.rating > 0) / max(
            sum(1 for f in recent if f.rating > 0), 1)
        fp_count = sum(1 for f in recent if f.is_false_positive)
        fn_count = sum(1 for f in recent if f.is_false_negative)
        correction_count = sum(1 for f in recent if f.correction)

        # Adjust weights based on signals
        if avg_rating < 3.0:
            # Quality is low — increase positive weights
            changes["accuracy"] = self.learning_rate
            changes["explainability"] = self.learning_rate * 0.5

        if fp_count > 3:
            # Too many false positives — reduce sensitivity
            changes["bias"] = -self.learning_rate

        if fn_count > 3:
            # Missing threats — increase robustness
            changes["robustness"] = self.learning_rate

        if correction_count > 5:
            # Many corrections — increase all quality weights
            changes["accuracy"] = changes.get("accuracy", 0) + self.learning_rate * 0.5

        # Apply changes
        for key, delta in changes.items():
            self._adjust_weight(key, delta)

        self.weight_history.append(self.current_weights.copy())
        return changes

    def _adjust_weight(self, key: str, delta: float) -> None:
        """Adjust a single weight with clamping."""
        if key in self.current_weights:
            old = self.current_weights[key]
            if old >= 0:
                self.current_weights[key] = max(0.01, min(0.50, old + delta))
            else:
                self.current_weights[key] = max(-0.50, min(-0.01, old + delta))

    def get_few_shot_examples(self, query: str, k: int = 3) -> list[PromptExample]:
        """Retrieve relevant few-shot examples for a query."""
        if not self.prompt_library:
            return []

        # Simple keyword matching
        query_words = set(query.lower().split())
        scored = []
        for ex in self.prompt_library:
            ex_words = set(ex.query.lower().split())
            overlap = len(query_words & ex_words)
            scored.append((overlap, ex))

        scored.sort(key=lambda x: x[0], reverse=True)
        selected = [ex for _, ex in scored[:k] if _ > 0]

        for ex in selected:
            ex.use_count += 1

        return selected

    def get_summary(self) -> dict[str, Any]:
        return {
            "total_feedback": len(self.feedback_history),
            "prompt_library_size": len(self.prompt_library),
            "weight_recalibrations": len(self.weight_history),
            "current_weights": self.current_weights.copy(),
            "avg_rating": sum(f.rating for f in self.feedback_history if f.rating > 0) / max(
                sum(1 for f in self.feedback_history if f.rating > 0), 1),
        }


_learning: LearningAgent | None = None
def get_learning_agent() -> LearningAgent:
    global _learning
    if _learning is None:
        _learning = LearningAgent()
    return _learning
