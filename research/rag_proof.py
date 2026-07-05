#!/usr/bin/env python3
"""
Live-mode RAG proof — isolates the retrieval contribution on a real LLM.
=======================================================================
Why this exists
---------------
The earlier ablation (research/ablation_study.py) ran in deterministic/demo
mode, so the LLM analysis text was identical across retrieval conditions and
the scored metrics could not move (ANOVA p = 1.0). That was a
metric/intervention mismatch, not evidence that retrieval is useless.

This experiment fixes the design so the independent variable (retrieval)
actually drives the dependent variable (generation faithfulness):

  For each advisory, with a LIVE LLM:
    RAG-ON  : retrieve context, generate analysis grounded in it.
    RAG-OFF : generate analysis from the raw advisory only, no retrieval.
  Score BOTH analyses' faithfulness against the SAME retrieved evidence
  (RAGAS NLI entailment), plus per-claim source attribution, answer
  relevancy, and the guard's hallucination rate. Paired Wilcoxon test on
  the per-advisory differences.

The comparison is honest and directional: does grounding generation on
retrieved authoritative evidence make the output measurably more faithful
to that evidence, and more traceable to sources, than ungrounded
generation of the same advisory? Extraction metrics are deliberately NOT
scored here — they are rule-based and RAG-invariant by construction, which
is exactly the confound this experiment removes.

Run (free tier, auto-switching, strict):
  CTI_EVAL_MODE=api CTI_SKIP_OSINT=1 CTI_STRICT_LLM=1 \
      python research/rag_proof.py
"""
from __future__ import annotations

import os
import sys
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

RESULTS_DIR = Path(__file__).resolve().parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def _ungrounded_prompt(advisory: str) -> str:
    """RAG-OFF: analyse from the advisory text alone, no retrieved context."""
    return (
        "Analyse the following threat report as a Cyber Threat Intelligence "
        "analyst. Give a summary, the MITRE ATT&CK techniques involved, any "
        "CVEs, the threat actor if identifiable, and a severity assessment.\n\n"
        f"Threat report:\n{advisory}"
    )


def run() -> dict:
    from config import settings, LLMMode
    from agents.kg_builder import get_kg_builder
    from agents.hybrid_retriever import get_hybrid_retriever
    from cti_shield.llm_engine import get_engine
    from cti_shield.source_attributor import get_source_attributor
    from agents.hallucination_guard import HallucinationGuardAgent
    from research.real_eval import REAL_THREAT_REPORTS
    from research.ragas_evaluator import (
        faithfulness, answer_relevancy, context_recall, context_precision,
    )

    # Force a real backend; refuse to run on demo (would reproduce the null).
    if settings.llm.mode == LLMMode.DEMO:
        raise SystemExit(
            "rag_proof requires a real LLM backend. Set CTI_EVAL_MODE=api "
            "(with an API key) or =ollama. Refusing to run in demo mode.")

    kg = get_kg_builder()
    retriever = get_hybrid_retriever()
    engine = get_engine()
    attributor = get_source_attributor()
    guard = HallucinationGuardAgent()

    model_label = (settings.llm.ollama_model
                   if settings.llm.mode == LLMMode.OLLAMA
                   else settings.llm.api_model)
    print(f"  [rag_proof] backend={settings.llm.mode.value} model={model_label} "
          f"provider={settings.llm.api_provider or 'local'}")

    rows = []
    for adv in REAL_THREAT_REPORTS:
        aid, text = adv["id"], adv["text"]
        gt = adv.get("ground_truth", {})
        print(f"\n[{aid}] retrieving + generating (RAG-ON and RAG-OFF)...")

        # ── Retrieve once; both conditions score against this evidence ──
        retrieval = retriever.retrieve(text, kg_builder=kg)
        ctx = retrieval.merged_context or ""
        rdict = retrieval.to_dict()

        # ── RAG-ON: grounded generation ────────────────────────────────
        grounded = (
            "You are a Cyber Threat Intelligence analyst. Use ONLY the "
            "retrieved context below for factual claims; if the context does "
            "not support a claim, say so.\n\n"
            f"Retrieved context:\n{ctx}\n\n"
            f"Threat report:\n{text}"
        )
        t0 = time.time()
        on = engine.analyse_threat(grounded, text[:2000])
        on_text = str(on.get("analysis", ""))
        on_latency = (time.time() - t0) * 1000

        # ── RAG-OFF: ungrounded generation of the same advisory ────────
        t0 = time.time()
        off = engine.analyse_threat(_ungrounded_prompt(text), "")
        off_text = str(off.get("analysis", ""))
        off_latency = (time.time() - t0) * 1000

        # Guard against contaminated results: if strict mode is off and a
        # call returned error text, skip scoring that advisory.
        if on_text.startswith("API Error") or off_text.startswith("API Error"):
            print(f"  ! {aid}: API error in a condition; excluded from stats.")
            rows.append({"id": aid, "excluded": True,
                         "reason": on_text[:80] or off_text[:80]})
            continue

        # ── Score both analyses against the SAME retrieved evidence ────
        faith_on = faithfulness(on_text, ctx) if ctx else 0.0
        faith_off = faithfulness(off_text, ctx) if ctx else 0.0

        attr_on = attributor.attribute(on_text, rdict).attribution_rate
        attr_off = attributor.attribute(off_text, rdict).attribution_rate

        rel_on = answer_relevancy(on_text, text)
        rel_off = answer_relevancy(off_text, text)

        halluc_on = guard.validate(on_text, ctx or text[:2000]).hallucination_rate
        halluc_off = guard.validate(off_text, ctx or text[:2000]).hallucination_rate

        row = {
            "id": aid, "source": adv.get("source", ""),
            "retrieval": {
                "merged_context_chars": len(ctx),
                "vector_docs": retrieval.vec_results_count,
                "kg_results": retrieval.kg_results_count,
                "context_recall_vs_ground_truth": round(context_recall(ctx, gt), 4),
                "context_precision": round(context_precision(ctx, text), 4),
            },
            "faithfulness": {"rag_on": round(faith_on, 4), "rag_off": round(faith_off, 4),
                             "delta": round(faith_on - faith_off, 4)},
            "attribution_rate": {"rag_on": round(attr_on, 4), "rag_off": round(attr_off, 4),
                                 "delta": round(attr_on - attr_off, 4)},
            "answer_relevancy": {"rag_on": round(rel_on, 4), "rag_off": round(rel_off, 4)},
            "hallucination_rate": {"rag_on": round(halluc_on, 4), "rag_off": round(halluc_off, 4),
                                   "delta": round(halluc_off - halluc_on, 4)},
            "latency_ms": {"rag_on": round(on_latency, 1), "rag_off": round(off_latency, 1)},
            "model_on": getattr(engine, "_last_model", "unknown"),
        }
        rows.append(row)
        print(f"  faithfulness  ON {faith_on:.3f} vs OFF {faith_off:.3f} "
              f"| attribution ON {attr_on:.2f} vs OFF {attr_off:.2f} "
              f"| halluc ON {halluc_on:.3f} vs OFF {halluc_off:.3f}")

    scored = [r for r in rows if not r.get("excluded")]
    summary = _paired_stats(scored)

    # Provenance from the free-model auto-switcher
    try:
        from cti_shield.model_rotator import get_rotator, ROTATION_LOG
        models_used = get_rotator().models_used()
        rotations = list(ROTATION_LOG)
    except Exception:
        models_used, rotations = [], []

    out = {
        "experiment": "live_mode_rag_proof",
        "purpose": ("Isolate retrieval contribution on a real LLM: RAG-on vs "
                    "RAG-off generation, faithfulness scored against retrieved "
                    "evidence. Fixes the demo-mode ablation's metric/intervention "
                    "mismatch."),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "backend": settings.llm.mode.value,
        "llm_model": model_label,
        "llm_provider": settings.llm.api_provider or "local",
        "llm_models_used": models_used,
        "model_rotations": rotations,
        "strict_llm": os.getenv("CTI_STRICT_LLM", "").lower() in ("1", "true", "yes"),
        "n_scored": len(scored),
        "summary": summary,
        "per_advisory": rows,
    }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS_DIR / f"rag_proof_{ts}.json"
    path.write_text(json.dumps(out, indent=2, default=str))
    print(f"\n  Saved: {path}")
    _print_summary(summary, len(scored))
    return out


def _paired_stats(rows: list[dict]) -> dict:
    if not rows:
        return {"error": "no scored advisories"}

    def col(metric, side):
        return np.array([r[metric][side] for r in rows], dtype=float)

    faith_on, faith_off = col("faithfulness", "rag_on"), col("faithfulness", "rag_off")
    attr_on, attr_off = col("attribution_rate", "rag_on"), col("attribution_rate", "rag_off")
    hall_on, hall_off = col("hallucination_rate", "rag_on"), col("hallucination_rate", "rag_off")

    def wilcoxon(a, b):
        try:
            from scipy.stats import wilcoxon as wtest
            diff = a - b
            if np.allclose(diff, 0):
                return {"statistic": 0.0, "p_value": 1.0, "note": "all differences zero"}
            stat, p = wtest(a, b)
            return {"statistic": round(float(stat), 4), "p_value": round(float(p), 5)}
        except Exception as e:
            return {"error": str(e)}

    def cohen_dz(a, b):
        d = a - b
        sd = np.std(d, ddof=1) if len(d) > 1 else 0.0
        return round(float(np.mean(d) / sd), 4) if sd > 0 else 0.0

    return {
        "faithfulness": {
            "rag_on_mean": round(float(np.mean(faith_on)), 4),
            "rag_off_mean": round(float(np.mean(faith_off)), 4),
            "mean_gain": round(float(np.mean(faith_on - faith_off)), 4),
            "wilcoxon": wilcoxon(faith_on, faith_off),
            "cohens_dz": cohen_dz(faith_on, faith_off),
        },
        "attribution_rate": {
            "rag_on_mean": round(float(np.mean(attr_on)), 4),
            "rag_off_mean": round(float(np.mean(attr_off)), 4),
            "mean_gain": round(float(np.mean(attr_on - attr_off)), 4),
            "wilcoxon": wilcoxon(attr_on, attr_off),
            "cohens_dz": cohen_dz(attr_on, attr_off),
        },
        "hallucination_rate": {
            "rag_on_mean": round(float(np.mean(hall_on)), 4),
            "rag_off_mean": round(float(np.mean(hall_off)), 4),
            "mean_reduction": round(float(np.mean(hall_off - hall_on)), 4),
            "wilcoxon": wilcoxon(hall_off, hall_on),
            "cohens_dz": cohen_dz(hall_off, hall_on),
        },
        "context_recall_mean": round(
            float(np.mean([r["retrieval"]["context_recall_vs_ground_truth"] for r in rows])), 4),
    }


def _print_summary(summary: dict, n: int) -> None:
    if "error" in summary:
        print(f"  {summary['error']}")
        return
    f = summary["faithfulness"]; a = summary["attribution_rate"]; h = summary["hallucination_rate"]
    print("=" * 70)
    print(f"  Live-mode RAG proof — {n} advisories, paired")
    print(f"  Faithfulness:  RAG-on {f['rag_on_mean']:.3f} vs RAG-off {f['rag_off_mean']:.3f} "
          f"(gain {f['mean_gain']:+.3f}, Wilcoxon p={f['wilcoxon'].get('p_value')}, dz={f['cohens_dz']})")
    print(f"  Attribution:   RAG-on {a['rag_on_mean']:.3f} vs RAG-off {a['rag_off_mean']:.3f} "
          f"(gain {a['mean_gain']:+.3f}, p={a['wilcoxon'].get('p_value')})")
    print(f"  Hallucination: RAG-on {h['rag_on_mean']:.3f} vs RAG-off {h['rag_off_mean']:.3f} "
          f"(reduction {h['mean_reduction']:+.3f}, p={h['wilcoxon'].get('p_value')})")
    print(f"  Retrieval context recall vs ground truth: {summary['context_recall_mean']:.3f}")
    print("=" * 70)


if __name__ == "__main__":
    run()
