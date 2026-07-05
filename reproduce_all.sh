#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# CTI-Shield — Full Research Reproducibility Script
# ═══════════════════════════════════════════════════════════════════
# Runs ALL experimental pipelines and generates thesis-ready results.
#
# Usage:
#   bash reproduce_all.sh                    # Auto-detect LLM (ollama→demo)
#   bash reproduce_all.sh --llm-mode ollama  # Force Ollama backend
#   bash reproduce_all.sh --llm-mode api     # Force LiteLLM API backend
#   bash reproduce_all.sh --llm-mode demo    # Demo mode (synthetic outputs)
#
# Output: research/results/*.json  (8+ result files)
# ═══════════════════════════════════════════════════════════════════

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment if present
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "  ✅ Virtual environment activated: $(which python)"
elif [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    echo "  ✅ Virtual environment activated: $(which python)"
fi

LLM_MODE="${1:---llm-mode}"
LLM_VALUE="${2:-}"

RESULTS_DIR="research/results"
mkdir -p "$RESULTS_DIR"

echo "═══════════════════════════════════════════════════════════════"
echo "  CTI-SHIELD REPRODUCIBILITY PIPELINE"
echo "  Started: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ── Step 0: Environment Check ────────────────────────────────────
echo "▶ Step 0: Environment verification..."
python -c "
import sys
print(f'  Python: {sys.version}')
try:
    import torch; print(f'  PyTorch: {torch.__version__}')
except ImportError: print('  PyTorch: not installed')
try:
    import sentence_transformers; print(f'  sentence-transformers: {sentence_transformers.__version__}')
except ImportError: print('  sentence-transformers: not installed (required)')
try:
    import scipy; print(f'  scipy: {scipy.__version__}')
except ImportError: print('  scipy: not installed (required for stats)')
try:
    import faiss; print(f'  FAISS: available ({faiss.get_num_gpus()} GPUs)')
except ImportError: print('  FAISS: not installed (required)')
try:
    import structlog; print(f'  structlog: {structlog.__version__}')
except ImportError: print('  structlog: not installed (required)')
"
echo ""

# ── Step 1: Build MITRE ATT&CK Corpus ───────────────────────────
echo "▶ Step 1: Building MITRE ATT&CK corpus + FAISS index..."
python -c "
from cti_shield.corpus_builder import build_and_index_corpus
count = build_and_index_corpus()
print(f'  Corpus indexed: {count} chunks')
" 2>&1 | head -20 || echo "  ⚠ Corpus build failed (may already exist)"
echo ""

# ── Step 2: Guard Evaluation (50 cases) ──────────────────────────
echo "▶ Step 2: Running 50-case hallucination guard evaluation..."
python research/guard_eval_runner.py || echo "  ⚠ Guard evaluation failed"
echo ""

# ── Step 3: Adversarial Injection Tests ──────────────────────────
echo "▶ Step 3: Running adversarial hallucination injection tests..."
python -m pytest tests/test_hallucination_injection.py -v --tb=short 2>&1 || true
echo ""

# ── Step 4: Full Ablation Study ──────────────────────────────────
echo "▶ Step 4: Running full ablation study (6 conditions × 10 advisories × 5 runs)..."
if [ -n "$LLM_VALUE" ]; then
    python research/ablation_study.py --llm-mode "$LLM_VALUE" || echo "  ⚠ Ablation study failed"
else
    python research/ablation_study.py || echo "  ⚠ Ablation study failed"
fi
echo ""

# ── Step 5: Attribution Rate Aggregation ─────────────────────────
echo "▶ Step 5: Computing attribution rate across 10 advisories..."
python research/attribution_aggregator.py || echo "  ⚠ Attribution aggregation failed"
echo ""

# ── Step 6: RAGAS Evaluation ─────────────────────────────────────
echo "▶ Step 6: Running RAGAS faithfulness evaluation..."
python research/ragas_evaluator.py 2>&1 || echo "  ⚠ RAGAS evaluation skipped (may require API key)"
echo ""

# ── Step 7: Human Eval Sample Generation ─────────────────────────
echo "▶ Step 7: Generating human evaluation samples..."
python research/human_eval_tool.py generate 2>&1 || echo "  ⚠ Human eval generation skipped"
echo ""

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  REPRODUCIBILITY PIPELINE COMPLETE"
echo "  Finished: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Generated result files:"
ls -la "$RESULTS_DIR"/*.json 2>/dev/null || echo "  (no results generated)"
echo ""
echo "  Next steps:"
echo "    1. Review results in research/results/"
echo "    2. Collect human eval scores: python research/human_eval_tool.py collect"
echo "    3. Analyze human eval: python research/human_eval_tool.py analyse"
echo "    4. Generate LaTeX tables from ablation JSON"
echo ""
