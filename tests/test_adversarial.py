"""Tests for adversarial inputs and edge cases."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cti_shield.preprocessing import clean_text, extract_iocs
from cti_shield.guardrails import token_overlap_score, extract_claims
from cti_shield.personal_shield import check_risk
from cti_shield.explainer import translate_jargon, determine_severity
from config import SeverityLevel

class TestAdversarialInputs:
    def test_xss_injection(self):
        """Ensure HTML/JS is stripped."""
        malicious = '<script>alert("xss")</script>Normal text'
        result = clean_text(malicious)
        assert "<script>" not in result
        assert "Normal text" in result

    def test_sql_injection(self):
        """SQL injection strings should be treated as plain text."""
        sql = "'; DROP TABLE users; --"
        result = clean_text(sql)
        assert "DROP TABLE" in result  # Preserved as text, not executed

    def test_extremely_long_input(self):
        """Handle very long inputs without crashing."""
        long_text = "A" * 1_000_000
        result = clean_text(long_text)
        assert len(result) == 1_000_000

    def test_unicode_bypass(self):
        """Handle Unicode tricks."""
        text = "pаypal.com"  # Cyrillic 'а' instead of Latin 'a'
        result = clean_text(text)
        assert len(result) > 0

    def test_null_bytes(self):
        """Null bytes should be stripped."""
        text = "Hello\x00World"
        result = clean_text(text)
        assert "\x00" not in result

    def test_empty_ioc_extraction(self):
        """No crash on text without IOCs."""
        iocs = extract_iocs("This is a normal sentence with no indicators.")
        assert all(len(v) == 0 for v in iocs.values())

class TestRiskCheckerAdversarial:
    def test_obvious_phishing(self):
        result = check_risk("URGENT: Your account will be suspended! Click here immediately: http://m1cr0soft-login.tk/verify")
        assert result["risk_score"] >= 50

    def test_safe_content(self):
        result = check_risk("Hello, how are you doing today?")
        assert result["risk_score"] < 30

    def test_ip_based_url(self):
        result = check_risk("Visit http://192.168.1.1/admin")
        assert result["risk_score"] > 0

class TestExplainerEdgeCases:
    def test_empty_analysis(self):
        sev = determine_severity({})
        assert isinstance(sev, SeverityLevel)

    def test_jargon_translation(self):
        result = translate_jargon("The APT used a RAT for C2.")
        assert "Advanced Persistent Threat" in result or "APT" in result

class TestTokenOverlapEdgeCases:
    def test_special_characters(self):
        score = token_overlap_score("CVE-2024-1234!!!", "CVE-2024-1234 is critical")
        assert score > 0

    def test_case_insensitive(self):
        score = token_overlap_score("HELLO WORLD", "hello world")
        assert score == 1.0
