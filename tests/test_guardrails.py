"""Tests for guardrails module."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cti_shield.guardrails import (
    token_overlap_score, extract_claims, compute_hallucination_rate,
    verify_cve_references, verify_ttp_references, validate_stix,
)

class TestTokenOverlap:
    def test_perfect_overlap(self):
        score = token_overlap_score("hello world", "hello world foo bar")
        assert score == 1.0

    def test_partial_overlap(self):
        score = token_overlap_score("hello world", "hello foo")
        assert 0 < score < 1

    def test_no_overlap(self):
        score = token_overlap_score("alpha beta", "gamma delta")
        assert score == 0.0

    def test_empty_input(self):
        assert token_overlap_score("", "hello") == 0.0
        assert token_overlap_score("hello", "") == 0.0

class TestExtractClaims:
    def test_splits_sentences(self):
        text = "This is claim one. This is claim two. And this is three."
        claims = extract_claims(text)
        assert len(claims) >= 2

    def test_filters_short(self):
        text = "Hi. OK. This is a real sentence with enough words."
        claims = extract_claims(text)
        assert all(len(c) > 10 for c in claims)

class TestHallucinationRate:
    def test_all_grounded(self):
        claims = ["the sky is blue", "water is wet"]
        context = "the sky is blue and water is wet and grass is green"
        result = compute_hallucination_rate(claims, context, use_nli=False)
        assert result["hallucination_rate"] <= 0.5

    def test_empty_claims(self):
        result = compute_hallucination_rate([], "context")
        assert result["hallucination_rate"] == 0.0
        assert result["total"] == 0

class TestCVEVerification:
    def test_valid_cve(self):
        result = verify_cve_references(["CVE-2024-1234"])
        assert result["CVE-2024-1234"] is True

    def test_invalid_cve(self):
        result = verify_cve_references(["NOT-A-CVE"])
        assert result["NOT-A-CVE"] is False

class TestTTPVerification:
    def test_valid_ttp_format(self):
        result = verify_ttp_references(["T1566", "T1059.001"])
        assert result["T1566"] is True
        assert result["T1059.001"] is True

    def test_invalid_ttp(self):
        result = verify_ttp_references(["INVALID"])
        assert result["INVALID"] is False

class TestSTIXValidation:
    def test_valid_stix_objects(self):
        import uuid
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        objects = [{
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": "Test Actor",
        }]
        result = validate_stix(objects)
        assert result["valid"] == 1
        assert result["invalid"] == 0

    def test_invalid_stix_object(self):
        result = validate_stix([{"type": "threat-actor", "id": "bad-id"}])
        assert result["invalid"] >= 1
