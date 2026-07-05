#!/usr/bin/env python3
"""
Attribution Rate Aggregator + Paired Hallucination Comparison
==============================================================
G3.1: Compute headline attribution rate across all 10 advisories.
G1.3: Paired before/after hallucination rates (No-RAG vs Hybrid).

Run:
    python research/attribution_aggregator.py
"""
from __future__ import annotations
import sys, os, json, time
from pathlib import Path
from typing import Any

# ── Prevent OpenMP SIGSEGV on macOS ARM64 ────────────────────────────
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import numpy as np  # type: ignore[import-not-found]

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

RESULTS_DIR = Path(__file__).resolve().parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def aggregate_attribution_rate():
    """G3.1: Run pipeline on all 10 advisories, compute mean attribution rate."""
    from research.real_eval import REAL_THREAT_REPORTS
    from config import settings, LLMMode, RetrievalMode
    settings.llm.mode = LLMMode.DEMO
    settings.rag.retrieval_mode = RetrievalMode.HYBRID

    from orchestrator import reset_orchestrator, get_orchestrator
    import agents.kg_builder as kgm
    kgm._kg_builder = None
    reset_orchestrator()
    orch = get_orchestrator()

    print(f"\n{'='*64}")
    print("  G3.1: ATTRIBUTION RATE AGGREGATION (10 advisories, Hybrid RAG)")
    print(f"{'='*64}\n")

    rates = []
    per_advisory = []

    for adv in REAL_THREAT_REPORTS:
        try:
            result = orch.run_pipeline(str(adv["text"]))
            attr = result.get("attributed_claims", {})
            rate = attr.get("attribution_rate", 0.0) if isinstance(attr, dict) else 0.0
            total = attr.get("total_claims", 0) if isinstance(attr, dict) else 0
            attributed = attr.get("attributed_claims", 0) if isinstance(attr, dict) else 0

            rates.append(rate)
            per_advisory.append({
                "id": adv["id"], "source": adv["source"],
                "attribution_rate": round(rate, 4),
                "total_claims": total, "attributed_claims": attributed,
            })
            print(f"  {adv['id']}: {rate:.1%} ({attributed}/{total} claims attributed)")
        except Exception as e:
            print(f"  {adv['id']}: ERROR — {e}")
            rates.append(0.0)
            per_advisory.append({"id": adv["id"], "error": str(e)})

    mean_rate = np.mean(rates) if rates else 0.0
    std_rate = np.std(rates) if rates else 0.0

    print(f"\n{'─'*64}")
    print(f"  HEADLINE: Attribution Rate = {mean_rate:.1%} ± {std_rate:.1%}")
    print(f"  (Mean over {len(rates)} advisories, Hybrid RAG condition)")
    print(f"{'─'*64}")

    export = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "condition": "hybrid_rag",
        "n_advisories": len(rates),
        "mean_attribution_rate": round(float(mean_rate), 4),
        "std_attribution_rate": round(float(std_rate), 4),
        "per_advisory": per_advisory,
        "paper_sentence": (
            f"The Hybrid RAG system achieved a mean source attribution rate of "
            f"{mean_rate:.1%} (σ={std_rate:.1%}) across {len(rates)} real-world "
            f"CISA/MITRE advisories, meaning {mean_rate*100:.0f}% of factual claims "
            f"in the LLM output were traceable to verifiable sources."
        ),
    }

    out_path = RESULTS_DIR / "attribution_aggregate.json"
    out_path.write_text(json.dumps(export, indent=2))
    print(f"\n  ✅ Saved: {out_path}")
    return export


def paired_hallucination_comparison():
    """G1.3: Paired before/after hallucination rates on same inputs."""
    from research.real_eval import REAL_THREAT_REPORTS
    from config import settings, LLMMode, RetrievalMode
    settings.llm.mode = LLMMode.DEMO

    from orchestrator import reset_orchestrator, get_orchestrator
    import agents.kg_builder as kgm
    import agents.hybrid_retriever as hr_mod

    print(f"\n{'='*64}")
    print("  G1.3: PAIRED HALLUCINATION COMPARISON (No-RAG vs Hybrid)")
    print(f"{'='*64}\n")

    pairs = []

    for adv in REAL_THREAT_REPORTS:
        row: dict[str, Any] = {"id": adv["id"], "source": adv["source"]}

        for label, mode in [("no_rag", RetrievalMode.NONE), ("hybrid", RetrievalMode.HYBRID)]:
            settings.rag.retrieval_mode = mode
            hr_mod._retriever = None
            kgm._kg_builder = None
            reset_orchestrator()
            orch = get_orchestrator()

            try:
                result = orch.run_pipeline(str(adv["text"]))
                guard = result.get("guard_result", {})
                row[f"{label}_hallucination_rate"] = guard.get("hallucination_rate", 0.0)
                row[f"{label}_guard_passed"] = guard.get("passed", False)
                row[f"{label}_trust_score"] = result.get("trust_value", 0.0)
            except Exception as e:
                row[f"{label}_hallucination_rate"] = 1.0
                row[f"{label}_guard_passed"] = False
                row[f"{label}_error"] = str(e)

        # Compute reduction
        nr = float(row.get("no_rag_hallucination_rate", 0))
        hr = float(row.get("hybrid_hallucination_rate", 0))
        reduction = ((nr - hr) / nr * 100) if nr > 0 else 0.0
        row["reduction_pct"] = round(reduction, 1)

        pairs.append(row)
        print(f"  {adv['id']}: No-RAG={nr:.1%} → Hybrid={hr:.1%} (Δ={reduction:+.1f}%)")

    # Aggregate
    nr_rates = [p["no_rag_hallucination_rate"] for p in pairs]
    hr_rates = [p["hybrid_hallucination_rate"] for p in pairs]
    reductions = [p["reduction_pct"] for p in pairs]

    print(f"\n{'─'*64}")
    print(f"  No-RAG mean hallucination:  {np.mean(nr_rates):.1%}")
    print(f"  Hybrid mean hallucination:  {np.mean(hr_rates):.1%}")
    print(f"  Mean reduction:             {np.mean(reductions):.1f}%")
    print(f"{'─'*64}")

    # Wilcoxon test
    try:
        from scipy.stats import wilcoxon  # type: ignore[import-not-found]
        stat, p = wilcoxon(nr_rates, hr_rates, alternative="greater")
        print(f"  Wilcoxon W={stat:.3f}, p={p:.6f} {'✓ significant' if p < 0.05 else '✗ not significant'}")
    except ImportError:
        p = None
        print("  Wilcoxon: scipy not installed — run: pip install scipy")

    export = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "n_advisories": len(pairs),
        "no_rag_mean": round(float(np.mean(nr_rates)), 4),
        "hybrid_mean": round(float(np.mean(hr_rates)), 4),
        "mean_reduction_pct": round(float(np.mean(reductions)), 1),
        "wilcoxon_p": round(float(p), 6) if p is not None else None,
        "pairs": pairs,
    }

    out_path = RESULTS_DIR / "paired_hallucination.json"
    out_path.write_text(json.dumps(export, indent=2))
    print(f"\n  ✅ Saved: {out_path}")
    return export


if __name__ == "__main__":
    aggregate_attribution_rate()
    paired_hallucination_comparison()
