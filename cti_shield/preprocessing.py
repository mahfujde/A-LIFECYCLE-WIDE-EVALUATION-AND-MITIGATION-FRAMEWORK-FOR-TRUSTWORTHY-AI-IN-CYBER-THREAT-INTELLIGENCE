"""
Preprocessing Module
====================
Cleans raw threat intelligence text, loads OSINT reports from disk,
removes duplicates, and splits documents into chunks for embedding.

Think of this as the "kitchen prep" before the AI does its analysis —
raw ingredients (messy text) get washed, chopped, and organised.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Optional

import structlog

from config import OSINT_DIR, settings

logger = structlog.get_logger(__name__)


# ── Text Cleaning ───────────────────────────────────────────────────

def clean_text(text: str) -> str:
    """
    Clean raw CTI text by removing noise while preserving meaning.

    What it does in plain English:
    - Strips extra whitespace and blank lines
    - Removes HTML tags if any leaked in
    - Normalises Unicode characters
    - Keeps IOCs (IPs, hashes, URLs) intact

    Args:
        text: Raw text from a threat report or feed.

    Returns:
        Cleaned text ready for embedding or analysis.
    """
    if not text or not text.strip():
        return ""

    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)

    # Normalise whitespace (but keep paragraph breaks)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    # Remove control characters except newlines
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # Strip leading/trailing whitespace from each line
    lines = [line.strip() for line in text.split("\n")]
    text = "\n".join(lines)

    return text.strip()


def extract_iocs(text: str) -> dict[str, list[str]]:
    """
    Extract Indicators of Compromise (IOCs) from text.

    Finds things like:
    - IP addresses (e.g. 192.168.1.1)
    - URLs (e.g. https://evil.com/malware)
    - MD5/SHA1/SHA256 hashes
    - Email addresses
    - CVE IDs (e.g. CVE-2024-1234)

    Args:
        text: Cleaned CTI text.

    Returns:
        Dictionary mapping IOC types to lists of found values.
    """
    iocs: dict[str, list[str]] = {
        "ipv4": [],
        "urls": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
        "emails": [],
        "cves": [],
        "domains": [],
    }

    # IPv4
    iocs["ipv4"] = list(set(re.findall(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        text
    )))

    # URLs
    iocs["urls"] = list(set(re.findall(
        r"https?://[^\s<>\"']+",
        text
    )))

    # Hashes
    iocs["md5"] = list(set(re.findall(r"\b[a-fA-F0-9]{32}\b", text)))
    iocs["sha1"] = list(set(re.findall(r"\b[a-fA-F0-9]{40}\b", text)))
    iocs["sha256"] = list(set(re.findall(r"\b[a-fA-F0-9]{64}\b", text)))

    # Emails
    iocs["emails"] = list(set(re.findall(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        text
    )))

    # CVEs
    iocs["cves"] = list(set(re.findall(
        r"CVE-\d{4}-\d{4,7}",
        text,
        re.IGNORECASE
    )))

    # Domains (simple heuristic)
    iocs["domains"] = list(set(re.findall(
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|tk)\b",
        text
    )))

    return iocs


# ── Document Loading ─────────────────────────────────────────────────

def load_osint_reports(directory: Optional[Path] = None) -> list[dict[str, str]]:
    """
    Load all text-based threat reports from the OSINT reports folder.

    Each report becomes a dictionary with:
    - 'filename': the original file name
    - 'content': the cleaned text
    - 'hash': SHA256 hash for deduplication

    Args:
        directory: Path to the folder containing .txt reports.
                   Defaults to data/osint_reports/.

    Returns:
        List of report dictionaries, deduplicated by content hash.
    """
    directory = directory or OSINT_DIR
    reports: list[dict[str, str]] = []
    seen_hashes: set[str] = set()

    if not directory.exists():
        logger.warning("OSINT directory not found", path=str(directory))
        return reports

    for filepath in sorted(directory.glob("*.txt")):
        try:
            raw = filepath.read_text(encoding="utf-8", errors="replace")
            cleaned = clean_text(raw)
            if not cleaned:
                continue

            content_hash = hashlib.sha256(cleaned.encode()).hexdigest()

            if content_hash in seen_hashes:
                logger.info("Skipping duplicate report", file=filepath.name)
                continue

            seen_hashes.add(content_hash)
            reports.append({
                "filename": filepath.name,
                "content": cleaned,
                "hash": content_hash,
            })
            logger.info("Loaded report", file=filepath.name, chars=len(cleaned))

        except Exception as e:
            logger.error("Failed to load report", file=filepath.name, error=str(e))

    logger.info("Total reports loaded", count=len(reports))
    return reports


# ── Chunking ─────────────────────────────────────────────────────────

def chunk_text(
    text: str,
    chunk_size: int = 512,
    chunk_overlap: int = 64,
) -> list[str]:
    """
    Split text into overlapping chunks for embedding.

    Why overlapping? So important context at chunk boundaries
    isn't lost — like making sure a sentence about a threat
    actor isn't cut in half.

    Args:
        text: The full document text.
        chunk_size: Maximum characters per chunk.
        chunk_overlap: Number of overlapping characters between chunks.

    Returns:
        List of text chunks.
    """
    if not text:
        return []

    chunks: list[str] = []
    start = 0

    while start < len(text):
        end = start + chunk_size

        # Try to break at a sentence boundary
        if end < len(text):
            # Look back from `end` for a period, question mark, or newline
            break_point = max(
                text.rfind(". ", start, end),
                text.rfind("? ", start, end),
                text.rfind("\n", start, end),
            )
            if break_point > start:
                end = break_point + 1

        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)

        start = end - chunk_overlap
        if start >= len(text):
            break

    return chunks


def deduplicate_chunks(chunks: list[str], threshold: float = 0.95) -> list[str]:
    """
    Remove near-duplicate chunks using simple hash-based dedup.

    Args:
        chunks: List of text chunks.
        threshold: Not used for hash dedup but kept for API consistency.

    Returns:
        Deduplicated list of chunks.
    """
    seen: set[str] = set()
    unique: list[str] = []

    for chunk in chunks:
        h = hashlib.md5(chunk.encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            unique.append(chunk)

    return unique


# ── Pipeline ─────────────────────────────────────────────────────────

def preprocess_pipeline(
    raw_text: Optional[str] = None,
    directory: Optional[Path] = None,
) -> list[dict]:
    """
    Full preprocessing pipeline: load → clean → chunk → dedup.

    Can process either a single raw text or an entire directory.

    Args:
        raw_text: Optional single document to process.
        directory: Optional directory of .txt files to process.

    Returns:
        List of dicts with 'source', 'chunk_index', and 'text'.
    """
    results: list[dict] = []

    if raw_text:
        cleaned = clean_text(raw_text)
        chunks = chunk_text(cleaned, settings.rag.chunk_size, settings.rag.chunk_overlap)
        chunks = deduplicate_chunks(chunks)
        for i, chunk in enumerate(chunks):
            results.append({
                "source": "user_input",
                "chunk_index": i,
                "text": chunk,
            })

    if directory or (not raw_text):
        reports = load_osint_reports(directory)
        for report in reports:
            chunks = chunk_text(
                report["content"],
                settings.rag.chunk_size,
                settings.rag.chunk_overlap,
            )
            chunks = deduplicate_chunks(chunks)
            for i, chunk in enumerate(chunks):
                results.append({
                    "source": report["filename"],
                    "chunk_index": i,
                    "text": chunk,
                })

    logger.info("Preprocessing complete", total_chunks=len(results))
    return results
