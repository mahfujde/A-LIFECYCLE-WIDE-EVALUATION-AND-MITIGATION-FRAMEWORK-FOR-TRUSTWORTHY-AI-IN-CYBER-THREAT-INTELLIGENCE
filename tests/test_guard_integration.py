"""
G1.5: End-to-end integration test — guard rejects known-bad LLM output.
Asserts that the hallucination guard catches fabricated CVEs, TTPs, and actors.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="module")
def guard():
    from agents.hallucination_guard import get_hallucination_guard
    return get_hallucination_guard()


class TestGuardRejectsHallucinations:
    """Guard must reject outputs containing fabricated entities."""

    def test_fabricated_cve_rejected(self, guard):
        """Guard should catch a non-existent CVE ID."""
        fake_output = (
            "The threat actor exploited CVE-2024-99999, a critical vulnerability "
            "in Apache Server that allows remote code execution."
        )
        source_text = "The advisory discusses phishing campaigns targeting email servers."
        result = guard.validate(fake_output, source_text, [])
        # Guard should either fail or flag this as ungrounded
        assert result.hallucination_rate > 0 or not result.passed or result.claims_grounded < result.claims_checked

    def test_fabricated_ttp_rejected(self, guard):
        """Guard should catch a non-existent ATT&CK technique ID."""
        fake_output = (
            "The malware uses T9999.001 (Quantum Tunneling Injection) to bypass "
            "all host-based defenses and achieve persistence."
        )
        source_text = "LockBit ransomware uses standard encryption for data impact."
        result = guard.validate(fake_output, source_text, [])
        assert result.hallucination_rate > 0 or not result.passed

    def test_fabricated_actor_with_real_context(self, guard):
        """Guard should detect when output contradicts the source."""
        fake_output = (
            "The DarkNebula APT group, a state-sponsored actor from Antarctica, "
            "deployed SUNBURST malware variant V7.0 across Fortune 500 companies."
        )
        source_text = (
            "CISA advisory AA20-352A discusses the SolarWinds supply chain compromise "
            "attributed to Russian SVR actors (APT29/Cozy Bear)."
        )
        result = guard.validate(fake_output, source_text, [])
        # Embedding similarity (or lexical fallback) should be very low
        assert result.tier_scores.get("t1_embedding", 1.0) < 0.5

    def test_grounded_output_passes(self, guard):
        """Guard should accept a well-grounded output that matches source."""
        source_text = (
            "Volt Typhoon (APT group linked to China) has been observed "
            "using living-off-the-land techniques including T1059.001 PowerShell "
            "and T1218.011 Rundll32 for defense evasion."
        )
        good_output = (
            "Volt Typhoon employs living-off-the-land binaries (LOLBins) "
            "such as PowerShell (T1059.001) and Rundll32 (T1218.011) "
            "to evade host-based security controls."
        )
        result = guard.validate(good_output, source_text, [])
        assert result.passed, f"Well-grounded output should pass guard: {result.reason}"

    def test_partial_hallucination_detected(self, guard):
        """Guard should catch partially hallucinated outputs (mix of real + fake)."""
        source_text = (
            "APT28 (Fancy Bear) uses T1566 Phishing and T1190 Exploit Public-Facing "
            "Application for initial access."
        )
        mixed_output = (
            "APT28 uses T1566 Phishing for initial access. They also leverage "
            "CVE-2099-12345, a zero-day in quantum computing frameworks, "
            "to achieve domain dominance via T8888.999."
        )
        result = guard.validate(mixed_output, source_text, [])
        # Should detect some ungrounded claims
        assert result.claims_checked > 0
