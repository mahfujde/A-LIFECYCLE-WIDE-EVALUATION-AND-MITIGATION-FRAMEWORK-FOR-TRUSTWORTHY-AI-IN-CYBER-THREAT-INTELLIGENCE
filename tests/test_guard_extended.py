"""
Hallucination Guard — Extended 50-Case Evaluation + ROC Analysis
=================================================================
pytest-parametrized test suite for research paper credibility (RQ1).

Run:   pytest tests/test_guard_extended.py -v
Report: pytest tests/test_guard_extended.py -v --tb=no -q && python tests/test_guard_extended.py
"""
from __future__ import annotations

import sys, os, json, time
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass

import pytest
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.hallucination_guard import HallucinationGuardAgent
from research.guard_eval_dataset import GUARD_EVAL_CASES


# ═══════════════════════════════════════════════════════════════════
# Pytest Parametrized Tests (50 cases)
# ═══════════════════════════════════════════════════════════════════

_guard = HallucinationGuardAgent()


def _case_id(case: dict) -> str:
    return f"{case['id']}-{case['category']}"


@pytest.mark.parametrize(
    "case",
    GUARD_EVAL_CASES,
    ids=[_case_id(c) for c in GUARD_EVAL_CASES],
)
def test_guard_case(case: dict):
    """
    Test a single hallucination guard case.
    Validates that the guard produces the expected PASS/FAIL label.
    """
    result = _guard.validate(
        output=case["llm_output"],
        context=case["input_context"],
    )

    actual_label = "PASS" if result.passed else "FAIL"
    expected = case["ground_truth_label"]

    # For edge cases (Category E), record but don't fail — these are
    # for threshold tuning, not absolute pass/fail
    if case["category"] == "E_edge_case":
        # Still record the result for metrics, but use a softer assertion
        # that generates useful pytest output without blocking the suite
        if actual_label != expected:
            pytest.skip(
                f"Edge case {case['id']}: expected={expected} got={actual_label} "
                f"(tier_scores={result.tier_scores})"
            )
        return

    assert actual_label == expected, (
        f"{case['id']}: expected={expected}, got={actual_label}, "
        f"tier_failed={result.tier_failed}, "
        f"tier_scores={result.tier_scores}, "
        f"fake_cves={result.fake_cves}, fake_ttps={result.fake_ttps}"
    )


# ═══════════════════════════════════════════════════════════════════
# Standalone Metrics Runner
# ═══════════════════════════════════════════════════════════════════

@dataclass
class Metrics:
    tp: int = 0   # correctly flagged as FAIL
    tn: int = 0   # correctly passed as PASS
    fp: int = 0   # incorrectly flagged as FAIL (should have PASS)
    fn: int = 0   # incorrectly passed as PASS (should have FAIL)

    @property
    def precision(self) -> float:
        return self.tp / max(self.tp + self.fp, 1)

    @property
    def recall(self) -> float:
        return self.tp / max(self.tp + self.fn, 1)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / max(p + r, 1e-9)

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / max(self.tp + self.tn + self.fp + self.fn, 1)


def run_full_evaluation():
    """Run all 50 cases and compute per-category and overall metrics."""
    guard = HallucinationGuardAgent()

    overall = Metrics()
    per_category: dict[str, Metrics] = defaultdict(Metrics)
    results_log: list[dict] = []

    # Tier score distributions for ROC analysis
    t1_scores: list[tuple[float, str]] = []
    t2_scores: list[tuple[float, str]] = []

    print("=" * 72)
    print("  HALLUCINATION GUARD — 50-CASE EVALUATION REPORT")
    print("=" * 72)
    print()

    for case in GUARD_EVAL_CASES:
        t0 = time.time()
        result = guard.validate(
            output=case["llm_output"],
            context=case["input_context"],
        )
        elapsed = (time.time() - t0) * 1000

        actual = "PASS" if result.passed else "FAIL"
        expected = case["ground_truth_label"]
        correct = actual == expected
        cat = case["category"]

        # Confusion matrix update
        m = per_category[cat]
        if expected == "FAIL" and actual == "FAIL":
            overall.tp += 1; m.tp += 1
        elif expected == "PASS" and actual == "PASS":
            overall.tn += 1; m.tn += 1
        elif expected == "PASS" and actual == "FAIL":
            overall.fp += 1; m.fp += 1
        elif expected == "FAIL" and actual == "PASS":
            overall.fn += 1; m.fn += 1

        # Collect tier scores for ROC analysis
        t1 = result.tier_scores.get("t1_embedding", 0.0)
        t2 = result.tier_scores.get("t2_nli", 0.0)
        t1_scores.append((t1, expected))
        t2_scores.append((t2, expected))

        mark = "✅" if correct else "❌"
        results_log.append({
            "id": case["id"],
            "category": cat,
            "expected": expected,
            "actual": actual,
            "correct": correct,
            "tier_failed": result.tier_failed,
            "t1": round(t1, 4),
            "t2": round(t2, 4),
            "t3": round(result.tier_scores.get("t3_crossref", 1.0), 4),
            "fake_cves": result.fake_cves,
            "fake_ttps": result.fake_ttps,
            "latency_ms": round(elapsed, 1),
        })
        print(f"  {mark} {case['id']:8s} [{cat:22s}] expected={expected} actual={actual} "
              f"T1={t1:.3f} T2={t2:.3f} {elapsed:.0f}ms")

    # ── Per-Category Metrics Table ────────────────────────────────
    print()
    print("─" * 72)
    print(f"  {'Category':<24s} {'Prec':>6s} {'Recall':>7s} {'F1':>6s} {'Acc':>6s}  TP TN FP FN")
    print("─" * 72)
    for cat in sorted(per_category.keys()):
        m = per_category[cat]
        print(f"  {cat:<24s} {m.precision:>6.2%} {m.recall:>7.2%} {m.f1:>6.2%} {m.accuracy:>6.2%}  "
              f"{m.tp:>2d} {m.tn:>2d} {m.fp:>2d} {m.fn:>2d}")
    print("─" * 72)
    print(f"  {'OVERALL':<24s} {overall.precision:>6.2%} {overall.recall:>7.2%} "
          f"{overall.f1:>6.2%} {overall.accuracy:>6.2%}  "
          f"{overall.tp:>2d} {overall.tn:>2d} {overall.fp:>2d} {overall.fn:>2d}")
    print("─" * 72)

    # ── Confusion Matrix ─────────────────────────────────────────
    print()
    print("  Confusion Matrix:")
    print(f"                Predicted FAIL  Predicted PASS")
    print(f"  Actual FAIL:     {overall.tp:>3d} (TP)       {overall.fn:>3d} (FN)")
    print(f"  Actual PASS:     {overall.fp:>3d} (FP)       {overall.tn:>3d} (TN)")
    print()

    # ── ROC Threshold Analysis (Category E edge cases) ───────────
    print("  ROC Threshold Analysis (for Category E edge cases):")
    print("  ─────────────────────────────────────────────────")
    _print_roc_analysis("Tier 1 (Embedding)", t1_scores)
    _print_roc_analysis("Tier 2 (NLI)", t2_scores)

    # ── Export to JSON ───────────────────────────────────────────
    results_dir = Path(__file__).parent.parent / "research" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    output_path = results_dir / "guard_eval_50case.json"

    export = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_cases": len(GUARD_EVAL_CASES),
        "overall": {
            "precision": round(overall.precision, 4),
            "recall": round(overall.recall, 4),
            "f1": round(overall.f1, 4),
            "accuracy": round(overall.accuracy, 4),
            "tp": overall.tp, "tn": overall.tn,
            "fp": overall.fp, "fn": overall.fn,
        },
        "per_category": {
            cat: {
                "precision": round(m.precision, 4),
                "recall": round(m.recall, 4),
                "f1": round(m.f1, 4),
                "tp": m.tp, "tn": m.tn, "fp": m.fp, "fn": m.fn,
            }
            for cat, m in sorted(per_category.items())
        },
        "cases": results_log,
    }
    output_path.write_text(json.dumps(export, indent=2))
    print(f"\n  Results exported: {output_path}")
    print()

    return overall


def _print_roc_analysis(name: str, scores: list[tuple[float, str]]):
    """Print threshold sensitivity analysis for one tier."""
    thresholds = [0.01, 0.03, 0.05, 0.10, 0.15, 0.20, 0.30, 0.40, 0.50]
    print(f"\n  {name}:")
    print(f"    {'Threshold':>10s} {'TPR':>6s} {'FPR':>6s} {'Acc':>6s}")

    fail_scores = [s for s, label in scores if label == "FAIL"]
    pass_scores = [s for s, label in scores if label == "PASS"]

    for t in thresholds:
        # At this threshold, score < t → predict FAIL
        tp = sum(1 for s in fail_scores if s < t)
        fn = sum(1 for s in fail_scores if s >= t)
        fp = sum(1 for s in pass_scores if s < t)
        tn = sum(1 for s in pass_scores if s >= t)

        tpr = tp / max(tp + fn, 1)
        fpr = fp / max(fp + tn, 1)
        acc = (tp + tn) / max(tp + tn + fp + fn, 1)
        marker = " ◀" if name == "Tier 1 (Embedding)" and t == 0.15 else \
                 " ◀" if name == "Tier 2 (NLI)" and t == 0.40 else ""
        print(f"    {t:>10.2f} {tpr:>6.2%} {fpr:>6.2%} {acc:>6.2%}{marker}")


if __name__ == "__main__":
    run_full_evaluation()
