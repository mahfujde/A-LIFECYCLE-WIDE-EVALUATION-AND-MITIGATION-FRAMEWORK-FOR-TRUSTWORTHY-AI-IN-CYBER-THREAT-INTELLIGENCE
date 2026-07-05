"""
CTI-Shield — Lifecycle-wide evaluation and mitigation framework
for trustworthy AI in Cyber Threat Intelligence.

This package provides:
- preprocessing: Text cleaning, OSINT loading, deduplication
- rag: FAISS vector store + semantic retrieval with MMR
- hybrid_retriever: KG + Vector fusion with Reciprocal Rank Fusion
- corpus_builder: MITRE ATT&CK knowledge base ingestion and chunking
- llm_engine: Multi-LLM dispatch (Demo / API / Full modes)
- stix_models: Pydantic STIX 2.1 schema validators
- guardrails: Hallucination detection + retry logic
- output: STIX JSON / Markdown / metrics export
- mitre_loader: MITRE ATT&CK technique loader
- feed_updater: Live OSINT feed ingestion
- explainer: Plain-language threat explainer
- personal_shield: Personal protection advisor
"""

__version__ = "1.0.0"
__author__ = "CTI-Shield Contributors"
