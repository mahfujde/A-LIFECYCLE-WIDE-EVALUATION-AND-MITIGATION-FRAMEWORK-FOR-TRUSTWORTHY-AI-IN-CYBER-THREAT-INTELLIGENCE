#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# CTI-Shield One-Click Setup Script
# Works on macOS, Linux, and Windows (WSL/Git Bash)
# ═══════════════════════════════════════════════════════════════════
set -e

echo ""
echo "🛡️  CTI-Shield Setup"
echo "═══════════════════════════════════════════════"
echo ""

# ── Check Python ──────────────────────────────────────────────────
if command -v python3 &> /dev/null; then
    PYTHON=python3
elif command -v python &> /dev/null; then
    PYTHON=python
else
    echo "❌ Python not found. Please install Python 3.11+"
    echo "   👉 https://www.python.org/downloads/"
    exit 1
fi

PY_VERSION=$($PYTHON --version 2>&1 | awk '{print $2}')
echo "✅ Python found: $PY_VERSION"

# ── Create virtual environment ───────────────────────────────────
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    $PYTHON -m venv venv
fi

# Activate
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
fi
echo "✅ Virtual environment activated"

# ── Install dependencies ─────────────────────────────────────────
echo "📥 Installing dependencies (this may take a few minutes)..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "✅ Dependencies installed"

# ── Create directories ───────────────────────────────────────────
mkdir -p data/osint_reports data/faiss_index logs
echo "✅ Data directories created"

# ── Copy .env if needed ──────────────────────────────────────────
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "✅ Created .env file (edit it to add your API keys)"
fi

# ── Run tests ────────────────────────────────────────────────────
echo ""
echo "🧪 Running tests..."
$PYTHON -m pytest tests/ -v --tb=short 2>&1 || echo "⚠️  Some tests may require additional setup"

# ── Done ─────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════"
echo "🎉 Setup complete!"
echo ""
echo "To start CTI-Shield:"
echo "  source venv/bin/activate"
echo "  streamlit run app.py"
echo ""
echo "Or with Docker:"
echo "  docker compose up --build"
echo ""
echo "Open http://localhost:8501 in your browser"
echo "═══════════════════════════════════════════════"
