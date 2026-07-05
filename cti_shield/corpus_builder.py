"""
Corpus Builder — MITRE ATT&CK Knowledge Base Ingestion
========================================================
Downloads the full MITRE ATT&CK STIX 2.1 bundle (750+ techniques),
chunks technique descriptions into embedding-ready passages with
provenance metadata (technique_id, tactic, source_url), and indexes
them in FAISS for vector retrieval.

This module addresses:
  - G1.3: MITRE KB too small (25 → 750+ techniques)
  - G1.4: No document chunking pipeline
  - G1.5: No source provenance tracking
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import structlog
from config import DATA_DIR, MITRE_JSON, settings

log = structlog.get_logger(__name__)

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

CORPUS_PATH = DATA_DIR / "attack_corpus.json"


def _download_attack_bundle() -> dict:
    """Download the full MITRE ATT&CK Enterprise STIX 2.1 bundle."""
    import requests

    log.info("downloading_attack_bundle", url=ATTACK_STIX_URL)
    try:
        resp = requests.get(ATTACK_STIX_URL, timeout=120)
        resp.raise_for_status()
        bundle = resp.json()
        log.info("attack_bundle_downloaded", objects=len(bundle.get("objects", [])))
        return bundle
    except Exception as e:
        log.warning("attack_download_failed", error=str(e))
        return {}


def _extract_techniques(bundle: dict) -> list[dict[str, Any]]:
    """Extract attack-pattern objects (techniques) from the STIX bundle."""
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Extract technique ID from external references
        tech_id = ""
        source_url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                source_url = ref.get("url", "")
                break

        if not tech_id:
            continue

        # Extract tactic(s) from kill chain phases
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))

        techniques.append({
            "id": tech_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "tactic": ", ".join(tactics) if tactics else "Unknown",
            "platforms": obj.get("x_mitre_platforms", []),
            "source_url": source_url,
            "stix_id": obj.get("id", ""),
            "modified": obj.get("modified", obj.get("created", "")),
        })

    log.info("techniques_extracted", count=len(techniques))
    return techniques


def _chunk_technique(tech: dict, chunk_size: int = 256) -> list[dict]:
    """
    Chunk a technique description into embedding-ready passages.
    Each chunk carries full provenance metadata.
    """
    text = tech.get("description", "")
    if not text:
        return []

    # Prefix with technique identity for better embedding
    prefix = f"[{tech['id']}] {tech['name']} ({tech['tactic']}): "

    # Split into sentences, then group into chunks
    import re
    sentences = re.split(r'(?<=[.!?])\s+', text)

    chunks = []
    current = prefix
    for sent in sentences:
        if len(current.split()) + len(sent.split()) > chunk_size:
            if current.strip() and current != prefix:
                chunks.append({
                    "text": current.strip(),
                    "technique_id": tech["id"],
                    "technique_name": tech["name"],
                    "tactic": tech["tactic"],
                    "source_url": tech["source_url"],
                    "source": "mitre_attack",
                    "modified": tech.get("modified", ""),
                    "chunk_index": len(chunks),
                })
            current = prefix + sent + " "
        else:
            current += sent + " "

    # Final chunk
    if current.strip() and current != prefix:
        chunks.append({
            "text": current.strip(),
            "technique_id": tech["id"],
            "technique_name": tech["name"],
            "tactic": tech["tactic"],
            "source_url": tech["source_url"],
            "source": "mitre_attack",
            "modified": tech.get("modified", ""),
            "chunk_index": len(chunks),
        })

    return chunks


def build_attack_corpus(
    force_download: bool = False,
    chunk_size: int | None = None,
) -> list[dict]:
    """
    Build the full ATT&CK corpus: download → extract → chunk → return.

    If a cached corpus exists and force_download is False, loads from disk.
    Returns a list of chunk dicts ready for FAISS indexing.
    """
    chunk_size = chunk_size or settings.rag.chunk_size

    # Check for cached corpus
    if CORPUS_PATH.exists() and not force_download:
        try:
            with open(CORPUS_PATH) as f:
                corpus = json.load(f)
            if corpus:
                log.info("corpus_loaded_from_cache", chunks=len(corpus))
                return corpus
        except Exception:
            pass

    # Download and build
    bundle = _download_attack_bundle()
    if not bundle:
        # Fallback to existing mitre_attack.json
        log.warning("using_fallback_mitre_json")
        return _build_from_local_json(chunk_size)

    techniques = _extract_techniques(bundle)

    # Also update the local mitre_attack.json with full data
    mitre_data = [
        {"id": t["id"], "name": t["name"], "tactic": t["tactic"],
         "description": t["description"][:500]}
        for t in techniques
    ]
    with open(MITRE_JSON, "w") as f:
        json.dump({"techniques": mitre_data}, f, indent=2)
    log.info("mitre_json_updated", techniques=len(mitre_data))

    # Chunk all techniques
    corpus: list[dict] = []
    for tech in techniques:
        corpus.extend(_chunk_technique(tech, chunk_size))

    # Save corpus cache
    with open(CORPUS_PATH, "w") as f:
        json.dump(corpus, f, indent=2)

    log.info("corpus_built", total_chunks=len(corpus), techniques=len(techniques))
    return corpus


def _build_from_local_json(chunk_size: int) -> list[dict]:
    """Fallback: build corpus from the existing mitre_attack.json."""
    if not MITRE_JSON.exists():
        log.warning("no_mitre_data_available")
        return []

    with open(MITRE_JSON) as f:
        data = json.load(f)

    techniques = data if isinstance(data, list) else data.get("techniques", [])
    corpus: list[dict] = []
    for tech in techniques:
        chunks = _chunk_technique({
            "id": tech.get("id", ""),
            "name": tech.get("name", ""),
            "description": tech.get("description", ""),
            "tactic": tech.get("tactic", "Unknown"),
            "source_url": f"https://attack.mitre.org/techniques/{tech.get('id', '')}/",
        }, chunk_size)
        corpus.extend(chunks)

    log.info("corpus_from_local", total_chunks=len(corpus))
    return corpus


def build_and_index_corpus(force_download: bool = False) -> int:
    """
    Build ATT&CK corpus AND index it in FAISS.
    Returns the number of vectors indexed.
    """
    corpus = build_attack_corpus(force_download=force_download)
    if not corpus:
        log.warning("empty_corpus_nothing_to_index")
        return 0

    from cti_shield.rag import build_and_save
    store = build_and_save(corpus)
    log.info("corpus_indexed_in_faiss", vectors=store.total_vectors)
    return store.total_vectors
