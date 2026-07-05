#!/usr/bin/env python3
"""
P4.6: Guard Evaluation Runner — 50-Case Confusion Matrix
==========================================================
Runs the 3-tier HallucinationGuard against all 50 labeled cases
from guard_eval_dataset.py and produces precision/recall/F1.

Run:  python research/guard_eval_runner.py
"""
from __future__ import annotations
import sys, os, json, time
from pathlib import Path

# ── Prevent OpenMP SIGSEGV on macOS ARM64 ────────────────────────────
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

RESULTS_DIR = Path(__file__).resolve().parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# ── Progress helpers ──────────────────────────────────────────────────
TOTAL_CASES = 50

def _progress_bar(current: int, total: int, width: int = 40) -> str:
    """Render a Unicode progress bar."""
    pct = current / max(total, 1)
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {pct:6.1%}"


def _fmt_time(seconds: float) -> str:
    """Format seconds into a human-readable string."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        return f"{seconds / 3600:.1f}h"


def _print(msg: str) -> None:
    """Print with immediate flush so Streamlit captures output in real-time."""
    print(msg, flush=True)


def run_guard_evaluation():
    """Run all 50 cases through the guard and compute confusion matrix."""
    from research.guard_eval_dataset import GUARD_EVAL_CASES
    from agents.hallucination_guard import HallucinationGuardAgent

    _print(f"\n{'═' * 72}")
    _print("  🛡️  HALLUCINATION GUARD EVALUATION — 50 CASES")
    _print(f"{'═' * 72}")
    _print("")
    _print("  ⏳ Loading models (sentence-transformer + NLI cross-encoder)...")

    guard = HallucinationGuardAgent()

    _print("  ✅ Models ready. Starting evaluation...\n")

    # ── Phase 1: Run all cases ────────────────────────────────────
    results = []
    tp = fp = tn = fn = 0
    total = len(GUARD_EVAL_CASES)
    eval_start = time.time()

    _print(f"  {'─' * 68}")
    _print(f"  {'#':>3s}  {'ID':<8s}  {'Category':<22s}  {'Expect':>6s}  {'Got':>6s}  {'Verdict':>7s}  {'ms':>6s}")
    _print(f"  {'─' * 68}")

    for i, case in enumerate(GUARD_EVAL_CASES, 1):
        expected_label = case["ground_truth_label"]  # "PASS" or "FAIL"
        t0 = time.time()

        gr = guard.validate(case["llm_output"], case["input_context"])
        elapsed = (time.time() - t0) * 1000

        predicted = "PASS" if gr.passed else "FAIL"

        # Compute confusion matrix contribution
        if expected_label == "FAIL" and predicted == "FAIL":
            tp += 1; verdict = "TP ✅"
        elif expected_label == "PASS" and predicted == "PASS":
            tn += 1; verdict = "TN ✅"
        elif expected_label == "FAIL" and predicted == "PASS":
            fn += 1; verdict = "FN ❌"  # Missed hallucination
        else:  # expected PASS, predicted FAIL
            fp += 1; verdict = "FP ❌"  # False alarm

        results.append({
            "id": case["id"],
            "category": case["category"],
            "expected": expected_label,
            "predicted": predicted,
            "verdict": verdict[:2],
            "tier_failed": gr.tier_failed or "none",
            "hallucination_rate": round(gr.hallucination_rate, 4),
            "tier_scores": {k: round(v, 4) for k, v in gr.tier_scores.items()},
            "latency_ms": round(elapsed, 1),
        })

        # ── Real-time progress output ────────────────────────────
        mark = "✅" if verdict.endswith("✅") else "❌"
        _print(
            f"  {mark} {i:>3d}/{total}  {case['id']:<8s}  "
            f"[{case['category']:<22s}]  "
            f"expect={expected_label:<4s}  got={predicted:<4s}  "
            f"({verdict[:2]})  tier={gr.tier_failed or 'pass':<12s}  "
            f"h_rate={gr.hallucination_rate:.2f}  {elapsed:.0f}ms"
        )

        # ── Progress bar + ETA ───────────────────────────────────
        elapsed_total = time.time() - eval_start
        avg_per_case = elapsed_total / i
        eta = avg_per_case * (total - i)
        running_acc = (tp + tn) / i

        _print(
            f"         {_progress_bar(i, total)}  "
            f"⏱ {_fmt_time(elapsed_total)}  "
            f"ETA {_fmt_time(eta)}  "
            f"Acc {running_acc:.0%}  "
            f"(TP={tp} FP={fp} TN={tn} FN={fn})"
        )

    total_time = time.time() - eval_start

    # ── Phase 2: Metrics ──────────────────────────────────────────
    accuracy = (tp + tn) / total
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    specificity = tn / max(tn + fp, 1)

    _print(f"\n{'═' * 72}")
    _print("  📊 CONFUSION MATRIX")
    _print(f"{'═' * 72}")
    _print(f"                    Predicted FAIL    Predicted PASS")
    _print(f"  Expected FAIL     TP = {tp:<14d} FN = {fn}")
    _print(f"  Expected PASS     FP = {fp:<14d} TN = {tn}")
    _print("")
    _print(f"  Accuracy:    {accuracy:.4f}  ({tp+tn}/{total})")
    _print(f"  Precision:   {precision:.4f}  (TP/{tp}+FP/{fp})")
    _print(f"  Recall:      {recall:.4f}  (TP/{tp}+FN/{fn})")
    _print(f"  F1 Score:    {f1:.4f}")
    _print(f"  Specificity: {specificity:.4f}  (TN/{tn}+FP/{fp})")
    _print(f"  Total time:  {_fmt_time(total_time)}")
    _print(f"  Avg/case:    {total_time/total*1000:.0f}ms")

    # ── Phase 3: Per-Category Breakdown ───────────────────────────
    _print(f"\n{'─' * 72}")
    _print("  📋 PER-CATEGORY RESULTS")
    _print(f"{'─' * 72}")

    categories = sorted(set(str(r["category"]) for r in results))
    for cat in categories:
        cat_results = [r for r in results if r["category"] == cat]
        correct = sum(1 for r in cat_results if r["verdict"] in ("TP", "TN"))
        cat_total = len(cat_results)
        cat_acc = correct / cat_total
        bar = _progress_bar(correct, cat_total, width=20)
        _print(f"  {cat:<24s}: {correct}/{cat_total} correct  {bar}")

    # ── Phase 4: False Negative Analysis ──────────────────────────
    fn_cases = [r for r in results if r["verdict"] == "FN"]
    if fn_cases:
        _print(f"\n{'─' * 72}")
        _print(f"  ⚠️  FALSE NEGATIVES — {len(fn_cases)} hallucinations missed:")
        _print(f"{'─' * 72}")
        for r in fn_cases:
            _print(f"  ❌ {r['id']}: tier_scores={r['tier_scores']}, h_rate={r['hallucination_rate']}")

    # ── Phase 5: False Positive Analysis ──────────────────────────
    fp_cases = [r for r in results if r["verdict"] == "FP"]
    if fp_cases:
        _print(f"\n{'─' * 72}")
        _print(f"  ⚠️  FALSE POSITIVES — {len(fp_cases)} false alarms:")
        _print(f"{'─' * 72}")
        for r in fp_cases:
            _print(f"  ❌ {r['id']}: tier={r['tier_failed']}, tier_scores={r['tier_scores']}, h_rate={r['hallucination_rate']}")

    # ── Phase 6: Export ───────────────────────────────────────────
    export = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_cases": total,
        "total_time_seconds": round(total_time, 2),
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "specificity": round(specificity, 4),
        },
        "per_category": {
            cat: {
                "correct": sum(1 for r in results if r["category"] == cat and r["verdict"] in ("TP", "TN")),
                "total": sum(1 for r in results if r["category"] == cat),
            }
            for cat in categories
        },
        "false_negatives": fn_cases,
        "false_positives": fp_cases,
        "results": results,
    }

    out_path = RESULTS_DIR / "guard_eval_50case.json"
    out_path.write_text(json.dumps(export, indent=2))
    _print(f"\n✅ Saved: {out_path}")

    # ── Phase 7: Paper-Ready LaTeX ────────────────────────────────
    _print(f"\n{'═' * 72}")
    _print("  📄 PAPER-READY LATEX TABLE")
    _print(f"{'═' * 72}")
    print("\\begin{table}[h]")
    print("\\centering")
    print("\\caption{Hallucination Guard Evaluation (50 cases, 5 categories)}")
    print("\\label{tab:guard_eval}")
    print("\\begin{tabular}{lccc}")
    print("\\toprule")
    print("Category & Correct & Total & Accuracy \\\\")
    print("\\midrule")
    for cat in categories:
        c = sum(1 for r in results if r["category"] == cat and r["verdict"] in ("TP", "TN"))
        t = sum(1 for r in results if r["category"] == cat)
        label = cat.replace("_", " ").title()
        print(f"{label} & {c} & {t} & {c/t:.0%} \\\\")
    print("\\midrule")
    print(f"\\textbf{{Overall}} & \\textbf{{{tp+tn}}} & \\textbf{{{total}}} & \\textbf{{{accuracy:.1%}}} \\\\")
    print("\\bottomrule")
    print("\\end{tabular}")
    print("\\end{table}")

    # ── Final summary ─────────────────────────────────────────────
    _print(f"\n{'═' * 72}")
    _print(f"  🏁 EVALUATION COMPLETE")
    _print(f"  📊 F1={f1:.4f}  Accuracy={accuracy:.1%}  "
           f"Precision={precision:.4f}  Recall={recall:.4f}")
    _print(f"  ⏱  Total: {_fmt_time(total_time)}  "
           f"Avg: {total_time/total*1000:.0f}ms/case")
    _print(f"{'═' * 72}\n")

    return export


if __name__ == "__main__":
    run_guard_evaluation()
