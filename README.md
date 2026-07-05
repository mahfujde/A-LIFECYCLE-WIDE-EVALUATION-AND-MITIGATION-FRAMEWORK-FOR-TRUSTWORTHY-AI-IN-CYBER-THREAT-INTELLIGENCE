# 🛡️ CTI-Shield

**AI-Powered Cyber Threat Intelligence Framework**

A lifecycle-wide, self-learning, multi-agent CTI system with RAG-based hallucination mitigation.  
Open source · Free · Deployable by anyone with zero cybersecurity expertise.

# CTI-Shield

Lifecycle-wide evaluation and mitigation framework for trustworthy AI in cyber threat intelligence.

CTI-Shield combines a Streamlit dashboard, an 8-agent orchestrated analysis pipeline, a hybrid retrieval stack, hallucination guardrails, trust scoring, STIX 2.1 output, and a built-in research harness for reproducible evaluation.

## What This Repository Contains

The runnable application lives in this directory. It includes:

- `app.py` for the Streamlit UI
- `orchestrator.py` for the multi-agent pipeline
- `agents/` for agent implementations
- `cti_shield/` for core CTI utilities, guardrails, retrieval, output, and trust logic
- `research/` for evaluation scripts and result artifacts
- `tests/` for the pytest suite
- `data/` for corpora, vector indexes, and sample OSINT reports

## Core Capabilities

- Threat report analysis from raw text, advisories, and OSINT snippets
- CVE, IOC, and TTP extraction with MITRE ATT&CK mapping
- Hybrid RAG with FAISS vector search and knowledge-graph retrieval
- Hallucination detection with a multi-tier guard
- Trust scoring aligned to a structured evaluation rubric
- STIX 2.1 export and markdown reporting
- Personal protection utilities such as hygiene scoring and URL risk checks
- Research scripts for ablation, attribution, baseline comparison, and real-world evaluation

## Repository Layout

```text
.
├── app.py
├── orchestrator.py
├── config.py
├── requirements.txt
├── setup.sh
├── agents/
├── cti_shield/
├── data/
├── research/
└── tests/
```

## Quick Start

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Then open `http://localhost:8501` in your browser.

## Installation Options

### Automated Setup

```bash
chmod +x setup.sh
./setup.sh
```

### Docker

```bash
docker compose up --build
```

Docker brings up the dashboard together with supporting services such as Ollama and Neo4j.

### Manual Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
streamlit run app.py
```

## Operating Modes

| Mode | Description | Best Use |
|---|---|---|
| Demo | No API key required, relaxed thresholds | Fast exploration and demos |
| Local+LLM | Downloads a Hugging Face model locally | Offline use on CPU |
| Ollama | Uses a local Ollama server | Private local inference |
| API | Uses cloud LLM providers through LiteLLM | Hosted model access with strict guards |
| Full | Uses cloud and local models side by side | Comparison and benchmarking |

## Architecture Overview

The pipeline follows a lifecycle-wide flow:

1. Input adaptation and policy classification
2. Preprocessing and IOC extraction
3. Knowledge graph building and NLP TTP mapping
4. OSINT enrichment from live sources
5. Hybrid reasoning with retrieval and LLM generation
6. Hallucination validation and drift detection
7. Trust scoring, source attribution, and lifecycle assessment
8. STIX and markdown output generation

The main orchestration path is implemented in `orchestrator.py`, and the dashboard entry point is `app.py`.

## Research And Evaluation

The repository includes reproducible evaluation workflows under `research/`.

- `ablation_study.py` compares retrieval and reranking configurations
- `ragas_evaluator.py` measures faithfulness and answer relevancy
- `attribution_aggregator.py` measures source traceability
- `guard_eval_dataset.py` and `guard_eval_runner.py` exercise the hallucination guard
- `real_eval.py` runs the live advisory evaluation path
- `human_eval_tool.py` supports blinded human scoring

Outputs are written to `research/results/`.

## Configuration

Copy the example environment file before running API or local-LLM modes:

```bash
cp .env.example .env
```

Common variables include:

- `OPENROUTER_API_KEY`
- `GEMINI_API_KEY`
- `GROQ_API_KEY`
- `CEREBRAS_API_KEY`
- `COHERE_API_KEY`
- `GITHUB_TOKEN`
- `MISTRAL_API_KEY`
- `HF_TOKEN`
- `NVIDIA_API_KEY`
- `SAMBANOVA_API_KEY`
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`

For evaluation runs, the codebase also uses flags such as `CTI_EVAL_MODE`, `CTI_SKIP_OSINT`, and `CTI_STRICT_LLM`.

## Testing

```bash
source venv/bin/activate
python -m pytest tests/ -v
```

Targeted examples:

- `python -m pytest tests/test_guard_integration.py -v`
- `python -m pytest tests/test_source_attributor.py -v`
- `python -m pytest tests/test_stix.py -v`

## Outputs

Common output locations include:

- `data/faiss_index/` for vector store artifacts
- `data/kg_snapshot.json` for knowledge graph snapshots
- `logs/` for runtime logs
- `research/results/` for evaluation JSON, CSV, and report files

## Troubleshooting

- If Ollama mode fails, make sure the Ollama server is running and the selected model is pulled locally.
- If API mode returns errors, verify the provider key in `.env` and confirm that the model is available for your account.
- If the app cannot find its data directories, run the setup script once or start the app from this directory.

## License

See the repository license file if one is added to the GitHub project. If you are publishing this code publicly, make sure the license matches your intended distribution terms.
| SamSam (TA18-106A) | US-CERT | 67% |
| SolarWinds/SUNBURST | NCSC | 67% |
| Scattered Spider (AA23-325A) | CISA | 67% |

---

## 📑 Research Documentation

| Document | Description |
|----------|-------------|
| [RESEARCH.md](RESEARCH.md) | Full architecture, methodology, threat model |
| [research_paper.md](research_paper.md) | Academic paper with 21 references |
| [CTI-SHIELD_Research_Paper.pdf](CTI-SHIELD_Research_Paper.pdf) | PDF version |
| [research/results/](research/results/) | All evaluation data as timestamped JSON |

### Research Objectives

| RO | Question | Key Metric |
|----|----------|------------|
| **RO1** | Does RAG reduce LLM hallucination in CTI? | Hallucination rate, RAGAS Faithfulness |
| **RO2** | Does Hybrid KG+Vector outperform vector-only? | TTP F1, Temporal freshness |
| **RO3** | Can outputs be traced to verifiable sources? | Attribution rate, Citation report |

---

## ❓ Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` inside the venv |
| Port 8501 in use | `streamlit run app.py --server.port 8502` |
| Ollama not connecting | Start Ollama: `ollama serve` or open Ollama.app |
| Neo4j connection refused | Start Neo4j or ignore (falls back to NetworkX) |
| `torch` install fails | Try `pip install torch --index-url https://download.pytorch.org/whl/cpu` |
| FAISS import error on M1 Mac | `pip install faiss-cpu --no-cache-dir` |
| API key not working | Check `.env` file, restart Streamlit after editing |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make changes and add tests
4. Run `python -m pytest tests/ -v` to verify
5. Submit a Pull Request

All contributions welcome — code, docs, translations, bug reports.

---

## 📄 License

MIT License — free for personal and commercial use. See [LICENSE](LICENSE).

---

## ❤️ Built for Humanity

CTI-Shield exists because **everyone deserves to be safe online**.  
Not just experts. Not just corporations. **Everyone.**

⭐ Star this repo if you believe in making cybersecurity accessible.
