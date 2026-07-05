"""
Guardrails Module — Hallucination Detection & Retry Logic
==========================================================
Three-tier validation: STIX compliance, token overlap,
NLI entailment. Auto-retries with corrective prompts.
"""
from __future__ import annotations
import re, time
from typing import Any, Optional, Callable
import numpy as np
import structlog
from config import settings
from cti_shield.stix_models import validate_stix_object, compute_compliance_score

logger = structlog.get_logger(__name__)
_nli_model = None

def _get_nli_model():
    global _nli_model
    if _nli_model is None:
        try:
            import torch
            torch.set_num_threads(1)  # Prevent OMP SIGSEGV on macOS ARM64
            from sentence_transformers import CrossEncoder
            # Force CPU to avoid MPS deadlocks on Apple Silicon
            _nli_model = CrossEncoder(settings.guardrail.nli_model, device="cpu")
        except Exception:
            _nli_model = "unavailable"
    return _nli_model

# ── Tier 1: STIX Validation ─────────────────────────────────────────
def validate_stix(stix_objects: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate a list of STIX objects, return summary."""
    results: dict[str, Any] = {"valid": 0, "invalid": 0, "errors": [], "compliance_scores": []}
    for obj in stix_objects:
        is_valid, errors, _ = validate_stix_object(obj)
        score = compute_compliance_score(obj)
        results["compliance_scores"].append(score)
        if is_valid:
            results["valid"] += 1
        else:
            results["invalid"] += 1
            results["errors"].extend(errors)
    total = results["valid"] + results["invalid"]
    overall = (
        float(sum(results["compliance_scores"])) / len(results["compliance_scores"])
        if results["compliance_scores"] else 0.0
    )
    results["overall_compliance"] = overall
    results["pass"] = overall >= settings.guardrail.stix_compliance_minimum
    return results

# ── Tier 2a: Token Overlap ───────────────────────────────────────────
def token_overlap_score(claim: str, context: str) -> float:
    """
    Fast hallucination check: what fraction of claim tokens
    appear in the retrieved context?
    """
    if not claim or not context:
        return 0.0
    claim_tokens = set(re.findall(r"\w+", claim.lower()))
    context_tokens = set(re.findall(r"\w+", context.lower()))
    if not claim_tokens:
        return 0.0
    overlap = claim_tokens & context_tokens
    return len(overlap) / len(claim_tokens)

# ── Tier 2b: NLI Entailment ─────────────────────────────────────────
def nli_entailment_score(claim: str, context: str) -> float:
    """
    Accurate hallucination check using NLI cross-encoder.
    Returns entailment probability (0-1).
    """
    model = _get_nli_model()
    if model == "unavailable":
        return token_overlap_score(claim, context)
    try:
        scores = model.predict([(context, claim)])
        # CrossEncoder returns [contradiction, neutral, entailment]
        if isinstance(scores[0], (list, np.ndarray)):
            return float(scores[0][2])  # entailment score
        return float(scores[0])
    except Exception as e:
        logger.warning("NLI fallback to token overlap", error=str(e))
        return token_overlap_score(claim, context)

# ── Tier 2c: CVE/TTP Verification ───────────────────────────────────
def verify_cve_references(cves: list[str]) -> dict[str, bool]:
    """Check CVE IDs against known format (offline check)."""
    results = {}
    cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,7}$")
    for cve in cves:
        results[cve] = bool(cve_pattern.match(cve))
    return results

def verify_ttp_references(ttps: list[str], mitre_techniques: dict[str, Any] | None = None) -> dict[str, bool]:
    """Check TTP IDs against MITRE ATT&CK (if loaded)."""
    results = {}
    ttp_pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    for ttp in ttps:
        if mitre_techniques:
            results[ttp] = ttp in mitre_techniques
        else:
            results[ttp] = bool(ttp_pattern.match(ttp))
    return results

# ── Combined Hallucination Score ─────────────────────────────────────
def compute_hallucination_rate(
    claims: list[str],
    context: str,
    use_nli: bool = True,
) -> dict[str, Any]:
    """
    Compute hallucination rate across all claims.
    hallucination_rate = 1 - (grounded_claims / total_claims)
    """
    if not claims:
        return {"hallucination_rate": 0.0, "grounded": 0, "total": 0, "details": []}
    
    grounded = 0
    details = []
    threshold = settings.guardrail.token_overlap_threshold
    
    for claim in claims:
        tok_score = token_overlap_score(claim, context)
        nli_score = nli_entailment_score(claim, context) if use_nli else tok_score
        combined = 0.4 * tok_score + 0.6 * nli_score
        is_grounded = combined >= threshold
        if is_grounded:
            grounded += 1
        details.append({
            "claim": claim[:100],
            "token_overlap": round(tok_score, 3),
            "nli_score": round(nli_score, 3),
            "combined": round(combined, 3),
            "grounded": is_grounded,
        })
    
    return {
        "hallucination_rate": round(1 - grounded / len(claims), 3),
        "grounded": grounded,
        "total": len(claims),
        "details": details,
    }

# ── Extract Claims from LLM Output ──────────────────────────────────
def extract_claims(text: str) -> list[str]:
    """Split LLM output into individual claims/sentences."""
    sentences = re.split(r"(?<=[.!?])\s+", text)
    return [s.strip() for s in sentences if len(s.strip()) > 10]

# ── Retry Logic with Corrective Prompting ────────────────────────────
def guardrail_pipeline(
    llm_output: str,
    context: str,
    stix_objects: list[dict[str, Any]] | None = None,
    retry_fn: Callable[[str], str] | None = None,
    max_retries: int | None = None,
) -> dict[str, Any]:
    """
    Full guardrail pipeline with auto-retry.
    Returns validation results and final output.
    """
    max_retries = max_retries or settings.guardrail.max_retries
    current_output = llm_output
    attempt = 0
    results: dict[str, Any] = {"attempt": 1, "output": current_output, "passed": False}
    
    while attempt <= max_retries:
        results = {"attempt": attempt + 1, "output": current_output}
        
        # Tier 1: STIX validation
        if stix_objects:
            stix_result = validate_stix(stix_objects)
            results["stix_validation"] = stix_result
        
        # Tier 2: Hallucination check
        claims = extract_claims(current_output)
        hall_result = compute_hallucination_rate(claims, context)
        results["hallucination"] = hall_result
        
        # Check pass conditions
        stix_pass = results.get("stix_validation", {}).get("pass", True)
        hall_pass = hall_result["hallucination_rate"] <= (1 - settings.guardrail.token_overlap_threshold)
        results["passed"] = stix_pass and hall_pass
        
        if results["passed"] or attempt >= max_retries:
            if not results["passed"] and settings.guardrail.escalation_enabled:
                results["escalated"] = True
                results["escalation_reason"] = "Guardrail checks failed after max retries"
                logger.warning("Escalating to human review", attempt=attempt + 1)
            return results
        
        # Retry with corrective prompt
        if retry_fn:
            corrections = []
            if not stix_pass:
                corrections.append(f"Fix STIX errors: {results['stix_validation']['errors'][:3]}")
            if not hall_pass:
                ungrounded = [d["claim"] for d in hall_result["details"] if not d["grounded"]]
                corrections.append(f"These claims lack evidence: {ungrounded[:3]}")
            
            correction_prompt = (
                f"Your previous response had issues:\n"
                + "\n".join(f"- {c}" for c in corrections)
                + "\n\nPlease regenerate with corrections. Use ONLY the provided context."
            )
            current_output = retry_fn(correction_prompt)
        
        attempt += 1
    
    return results
