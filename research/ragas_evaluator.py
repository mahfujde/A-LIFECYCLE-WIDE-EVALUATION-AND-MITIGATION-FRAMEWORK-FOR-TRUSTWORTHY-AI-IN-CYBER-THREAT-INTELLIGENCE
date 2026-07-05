#!/usr/bin/env python3
"""
RAGAS-Compatible Evaluation Framework for CTI-Shield
======================================================
RQ1: "Does hybrid RAG reduce hallucination in LLM-generated CTI?"
RQ2: "Does KG+Vector fusion outperform single-source retrieval?"

Implements four RAGAS metrics using LOCAL models (no OpenAI key needed):
  1. Faithfulness     — NLI entailment: claims supported by retrieved context
  2. Answer Relevancy — cosine similarity between answer and question embeddings
  3. Context Recall   — fraction of ground-truth facts covered by retrieved context
  4. Context Precision — fraction of retrieved chunks relevant to the question

Three experimental conditions for ablation:
  A: No RAG       (RetrievalMode.NONE)
  B: Vector-only  (RetrievalMode.VECTOR_ONLY)
  C: Hybrid KG+V  (RetrievalMode.HYBRID)

Usage:
    python research/ragas_evaluator.py              # run all 3 conditions
    python research/ragas_evaluator.py --condition C # single condition
"""
from __future__ import annotations

import json, re, sys, time, os
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── CRITICAL: Set BEFORE any torch/numpy import to prevent OpenMP SIGSEGV ──
# PyTorch's libomp thread pool crashes on macOS ARM64 during long runs.
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("PYTORCH_MPS_FALLBACK", "1")

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings, RetrievalMode, LLMMode
from research.real_eval import REAL_THREAT_REPORTS

RESULTS_DIR = Path(__file__).resolve().parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# ── Lazy-loaded models ───────────────────────────────────────────────
_embed = None
_nli = None


def _get_embed():
    global _embed
    if _embed is None:
        import torch
        torch.set_num_threads(1)  # Prevent OMP SIGSEGV on macOS ARM64
        from sentence_transformers import SentenceTransformer
        _embed = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")
    return _embed


def _get_nli():
    global _nli
    if _nli is None:
        import torch
        torch.set_num_threads(1)  # Prevent OMP SIGSEGV on macOS ARM64
        from sentence_transformers import CrossEncoder
        _nli = CrossEncoder("cross-encoder/nli-deberta-v3-small", device="cpu")
    return _nli


def _softmax(logits):
    e = np.exp(logits - np.max(logits))
    return e / e.sum()


# ═══════════════════════════════════════════════════════════════════════
# RAGAS Metric Implementations (local, no OpenAI)
# ═══════════════════════════════════════════════════════════════════════

def faithfulness(answer: str, context: str) -> float:
    """
    RAGAS Faithfulness: fraction of answer claims entailed by context.
    Uses NLI cross-encoder (nli-deberta-v3-small).
    Score ∈ [0,1], higher = fewer hallucinations.
    """
    claims = [s.strip() for s in re.split(r'[.!?]\s+', answer) if len(s.strip()) > 15]
    if not claims:
        return 1.0

    nli = _get_nli()
    pairs: list[tuple[str, str]] = [(context[:1000], str(claim)) for claim in claims[:20]]
    scores = nli.predict(pairs, show_progress_bar=False, convert_to_numpy=True)  # type: ignore[call-overload]

    grounded = 0
    for raw in scores:
        if isinstance(raw, (list, np.ndarray)) and len(raw) >= 3:
            probs = _softmax(np.array(raw))
            if probs[1] + probs[2] > 0.5:  # non-contradiction
                grounded += 1
        elif float(raw) > 0.5:
            grounded += 1

    return grounded / len(claims)


def answer_relevancy(answer: str, question: str) -> float:
    """
    RAGAS Answer Relevancy: cosine similarity between answer and question.
    Uses sentence-transformers for embedding.
    Score ∈ [0,1], higher = more relevant.
    """
    model = _get_embed()
    embs = model.encode([answer[:1500], question[:1500]], normalize_embeddings=True)
    return max(0.0, float(np.dot(embs[0], embs[1])))


def context_recall(context: str, ground_truth: dict) -> float:
    """
    RAGAS Context Recall: fraction of ground-truth facts found in context.
    Checks CVEs, TTPs, and threat actor names.
    Score ∈ [0,1], higher = better coverage.
    """
    ctx_lower = context.lower()
    total, found = 0, 0

    for cve in ground_truth.get("expected_cves", []):
        total += 1
        if cve.lower() in ctx_lower:
            found += 1

    for ttp in ground_truth.get("expected_ttps", []):
        total += 1
        if ttp.lower() in ctx_lower:
            found += 1

    for actor in ground_truth.get("expected_actors", []):
        total += 1
        if actor.lower() in ctx_lower:
            found += 1

    return found / max(total, 1)


def context_precision(context: str, question: str) -> float:
    """
    RAGAS Context Precision: semantic relevance of retrieved chunks to query.
    Splits context into chunks, computes cosine similarity with query.
    Score ∈ [0,1], higher = more relevant retrieval.
    """
    if not context.strip():
        return 0.0

    chunks = [c.strip() for c in context.split("\n") if len(c.strip()) > 20]
    if not chunks:
        return 0.0

    model = _get_embed()
    q_emb = model.encode([question[:500]], normalize_embeddings=True)
    c_embs = model.encode(chunks[:20], normalize_embeddings=True)
    sims = np.dot(c_embs, q_emb[0])

    # Precision = fraction of chunks with similarity > threshold
    relevant = sum(1 for s in sims if s > 0.25)
    return relevant / len(chunks)


# ═══════════════════════════════════════════════════════════════════════
# Per-Run Evaluation Record
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class EvalRecord:
    advisory_id: str = ""
    condition: str = ""
    faithfulness: float = 0.0
    answer_relevancy: float = 0.0
    context_recall: float = 0.0
    context_precision: float = 0.0
    hallucination_rate: float = 0.0
    trust_score: float = 0.0
    cve_f1: float = 0.0
    ttp_f1: float = 0.0
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {k: round(v, 4) if isinstance(v, float) else v
                for k, v in self.__dict__.items()}


# ═══════════════════════════════════════════════════════════════════════
# Evaluation Harness
# ═══════════════════════════════════════════════════════════════════════

CONDITIONS = {
    "A": ("No RAG (baseline)", RetrievalMode.NONE),
    "B": ("Vector-only RAG", RetrievalMode.VECTOR_ONLY),
    "C": ("Hybrid KG+Vector RAG", RetrievalMode.HYBRID),
}


def _run_pipeline_for_condition(
    report: dict, mode: RetrievalMode,
) -> tuple[dict, str, str]:
    """
    Run the CTI-Shield pipeline with a specific retrieval mode.
    Returns (pipeline_result, analysis_text, retrieved_context).
    """
    from orchestrator import get_orchestrator, reset_orchestrator
    import agents.hybrid_retriever as hr_mod

    # Override retrieval mode
    settings.rag.retrieval_mode = mode
    hr_mod._retriever = None  # reset singleton to pick up new mode
    reset_orchestrator()
    orch = get_orchestrator()

    result = orch.run_pipeline(report["text"])

    # Extract analysis text
    analysis = result.get("analysis", {})
    if isinstance(analysis, dict):
        inner = analysis.get("analysis", {})
        analysis_text = json.dumps(inner) if isinstance(inner, dict) else str(inner)
    else:
        analysis_text = str(analysis)

    # Extract retrieved context
    retrieval = result.get("retrieval_result", {})
    contexts = retrieval.get("contexts", [])
    if contexts:
        ctx_text = "\n".join(c.get("text", "") if isinstance(c, dict) else str(c)
                             for c in contexts)
    else:
        # Fall back to source_attributions text
        attrs = result.get("source_attributions", [])
        ctx_text = "\n".join(a.get("text", "") for a in attrs if isinstance(a, dict))

    return result, analysis_text, ctx_text


def _compute_extraction_f1(found: list[str], expected: list[str]) -> float:
    if not expected:
        return 1.0 if not found else 0.0
    correct = len(set(found) & set(expected))
    p = correct / max(len(found), 1)
    r = correct / max(len(expected), 1)
    return 2 * p * r / max(p + r, 1e-9)


def evaluate_single(
    report: dict, condition_key: str, mode: RetrievalMode,
) -> EvalRecord:
    """Evaluate one advisory under one condition."""
    t0 = time.time()
    gt = report["ground_truth"]

    result, analysis_text, ctx_text = _run_pipeline_for_condition(report, mode)

    # RAGAS metrics
    faith = faithfulness(analysis_text, ctx_text) if ctx_text else 0.0
    relevancy = answer_relevancy(analysis_text, report["text"])
    recall = context_recall(ctx_text, gt) if ctx_text else 0.0
    precision = context_precision(ctx_text, report["text"]) if ctx_text else 0.0

    # Extraction metrics
    found_cves = re.findall(r'CVE-\d{4}-\d{4,7}', report["text"])
    found_ttps = [t["id"] for t in result.get("ttps", [])] if result.get("ttps") else []

    return EvalRecord(
        advisory_id=report["id"],
        condition=condition_key,
        faithfulness=faith,
        answer_relevancy=relevancy,
        context_recall=recall,
        context_precision=precision,
        hallucination_rate=result.get("guard_result", {}).get("hallucination_rate", 0.0),
        trust_score=result.get("trust_value", 0.0),
        cve_f1=_compute_extraction_f1(found_cves, gt.get("expected_cves", [])),
        ttp_f1=_compute_extraction_f1(found_ttps, gt.get("expected_ttps", [])),
        latency_ms=(time.time() - t0) * 1000,
    )


def run_evaluation(
    conditions: list[str] | None = None,
    reports: list[dict] | None = None,
) -> pd.DataFrame:
    """
    Run full RAGAS evaluation across conditions and advisories.
    Returns a DataFrame with one row per (advisory, condition).
    """
    conditions = conditions or list(CONDITIONS.keys())
    reports = reports or REAL_THREAT_REPORTS

    settings.llm.mode = LLMMode.DEMO

    records: list[dict] = []

    for cond_key in conditions:
        label, mode = CONDITIONS[cond_key]
        print(f"\n{'='*60}")
        print(f"  Condition {cond_key}: {label} ({mode.value})")
        print(f"{'='*60}")

        for report in reports:
            report_id = str(report.get("id", ""))
            report_source = str(report.get("source", ""))[:50]
            print(f"  [{report_id}] {report_source}...", end=" ", flush=True)
            try:
                rec = evaluate_single(report, cond_key, mode)
                records.append(rec.to_dict())
                print(f"faith={rec.faithfulness:.2f} rel={rec.answer_relevancy:.2f} "
                      f"recall={rec.context_recall:.2f} prec={rec.context_precision:.2f}")
            except Exception as e:
                print(f"ERROR: {e}")
                records.append(EvalRecord(
                    advisory_id=report_id, condition=cond_key
                ).to_dict())

    df = pd.DataFrame(records)
    return df


def summary_table(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute the statistical summary table for the thesis:
    | Condition | Faithfulness | Answer Rel. | Context Recall | Context Precision |
    with mean ± std across advisories.
    """
    metrics = ["faithfulness", "answer_relevancy", "context_recall", "context_precision",
               "hallucination_rate", "trust_score"]

    rows = []
    for cond in sorted(df["condition"].unique()):
        sub = df[df["condition"] == cond]
        label = CONDITIONS.get(cond, (cond,))[0] if cond in CONDITIONS else cond
        row = {"Condition": f"{cond}: {label}", "N": len(sub)}
        for m in metrics:
            if m in sub.columns:
                mean = sub[m].mean()
                std = sub[m].std()
                row[m] = f"{mean:.4f} ± {std:.4f}"
                row[f"{m}_mean"] = round(mean, 4)
                row[f"{m}_std"] = round(std, 4)
        rows.append(row)

    return pd.DataFrame(rows)


def export_results(df: pd.DataFrame, summary: pd.DataFrame) -> Path:
    """Export raw results + summary to CSV and JSON."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # CSV for thesis tables
    csv_path = RESULTS_DIR / f"ragas_results_{ts}.csv"
    df.to_csv(csv_path, index=False)

    summary_csv = RESULTS_DIR / f"ragas_summary_{ts}.csv"
    summary.to_csv(summary_csv, index=False)

    # JSON for programmatic access
    json_path = RESULTS_DIR / f"ragas_eval_{ts}.json"
    with open(json_path, "w") as f:
        json.dump({
            "metadata": {
                "framework": "CTI-SHIELD v3",
                "evaluator": "ragas_evaluator.py",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metrics": ["faithfulness", "answer_relevancy",
                            "context_recall", "context_precision"],
                "conditions": {k: v[0] for k, v in CONDITIONS.items()},
                "num_advisories": len(REAL_THREAT_REPORTS),
            },
            "per_advisory": df.to_dict(orient="records"),
            "summary": summary.to_dict(orient="records"),
        }, f, indent=2, default=str)

    print(f"\n  Raw results: {csv_path}")
    print(f"  Summary:     {summary_csv}")
    print(f"  Full JSON:   {json_path}")
    return json_path


# ═══════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(description="RAGAS evaluation for CTI-Shield")
    parser.add_argument("--condition", choices=["A", "B", "C"],
                        help="Run single condition (default: all)")
    parser.add_argument("--reports", type=int, default=10,
                        help="Number of reports to evaluate (default: 10)")
    args = parser.parse_args()

    conds = [args.condition] if args.condition else None
    reports = REAL_THREAT_REPORTS[:args.reports]

    print("=" * 60)
    print("  CTI-SHIELD RAGAS EVALUATION")
    print(f"  Conditions: {conds or 'A, B, C (all)'}")
    print(f"  Advisories: {len(reports)}")
    print("=" * 60)

    df = run_evaluation(conditions=conds, reports=reports)
    summary = summary_table(df)

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY (mean ± std)")
    print("=" * 60)
    display_cols = ["Condition", "faithfulness", "answer_relevancy",
                    "context_recall", "context_precision", "hallucination_rate"]
    print(summary[[c for c in display_cols if c in summary.columns]].to_string(index=False))

    export_results(df, summary)


if __name__ == "__main__":
    main()
