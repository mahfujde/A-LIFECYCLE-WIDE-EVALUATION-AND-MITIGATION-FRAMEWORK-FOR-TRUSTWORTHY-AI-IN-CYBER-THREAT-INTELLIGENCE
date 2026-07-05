# ═══════════════════════════════════════════════════════════════════
# CTI-Shield — Dual-Purpose Dockerfile
# ═══════════════════════════════════════════════════════════════════
# Supports both the Streamlit dashboard and the research pipeline.
#
# Dashboard:
#   docker build -t cti-shield .
#   docker run -p 8501:8501 cti-shield
#
# Research pipeline (all experiments):
#   docker run -it --rm \
#     -v $(pwd)/research/results:/app/research/results \
#     cti-shield bash reproduce_all.sh
#
# For GPU-accelerated embedding models:
#   docker run --gpus all -p 8501:8501 cti-shield
# ═══════════════════════════════════════════════════════════════════

FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy full project
COPY . .

# Create data dirs
RUN mkdir -p data/osint_reports data/faiss_index logs research/results

# Pre-download MITRE ATT&CK corpus for offline use
RUN python -c "from cti_shield.corpus_builder import build_corpus; build_corpus()" 2>/dev/null || true

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default: Streamlit dashboard
ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
