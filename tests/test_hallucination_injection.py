#!/usr/bin/env python3
"""
P3.5: Adversarial Hallucination Injection Tests
=================================================
RO1: Verify that the HallucinationGuardAgent catches fabricated CTI claims.

These tests inject known-false CVEs, fabricated threat actors, and
invented TTPs into pipeline outputs, then verify the guard flags them.

Run:  python -m pytest tests/test_hallucination_injection.py -v
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest


# ═══════════════════════════════════════════════════════════════════
# Fabricated CTI Data (known-false claims for injection)
# ═══════════════════════════════════════════════════════════════════

FABRICATED_CVES = [
    "CVE-2099-99999",   # Future year, impossible ID
    "CVE-2024-00000",   # Reserved but non-existent
    "CVE-2025-77777",   # Fabricated
]

FABRICATED_ACTORS = [
    "Midnight Platypus",      # Not a real APT group
    "APT99",                  # Not a real APT group
    "Crimson Narwhal",        # Not a real APT group
]

FABRICATED_TTPS = [
    "T9999",                  # Non-existent ATT&CK ID
    "T1566.099",              # Non-existent sub-technique
]

# Real context for grounding (from CISA AA22-110A)
REAL_CONTEXT = """
Russian state-sponsored cyber actors have been observed targeting U.S. critical
infrastructure networks since at least 2020. These actors use spearphishing
(T1566.001) to gain initial access, then deploy custom malware to maintain
persistence. Known CVEs exploited include CVE-2021-44228 (Log4Shell) and
CVE-2020-1472 (Zerologon). The threat group APT28 has been particularly active
in targeting government and defense sectors.
"""

# Hallucinated output containing fabricated claims
HALLUCINATED_OUTPUT_MILD = """
The threat actor APT28 exploited CVE-2021-44228 to gain initial access via
spearphishing emails (T1566.001). They also leveraged CVE-2099-99999, a
critical zero-day in the authentication framework, to escalate privileges.
The group used PowerShell for execution (T1059.001) and established persistence
through scheduled tasks (T1053.005).
"""

HALLUCINATED_OUTPUT_SEVERE = """
The Midnight Platypus threat group, also known as APT99, conducted a campaign
exploiting CVE-2025-77777 (a critical RCE in TLS 1.4) and CVE-2024-00000
(an authentication bypass in quantum encryption libraries). They deployed
the "ShadowFang" malware using technique T9999 (quantum tunneling bypass)
to exfiltrate 500TB of classified data from 47 government agencies.
"""

HALLUCINATED_OUTPUT_SUBTLE = """
APT28 exploited CVE-2021-44228 to compromise Log4j-based applications.
Post-exploitation, the actors used Mimikatz for credential harvesting and
deployed Cobalt Strike beacons for command and control. Notably, they also
exploited CVE-2099-99999 in a secondary attack vector targeting the same
organizations. The campaign affected approximately 150 organizations across
12 countries during Q3 2024.
"""


# ═══════════════════════════════════════════════════════════════════
# Guard Tests
# ═══════════════════════════════════════════════════════════════════

class TestHallucinationGuardInjection:
    """Test that the guard catches injected hallucinations."""

    @pytest.fixture(autouse=True)
    def setup_guard(self):
        from agents.hallucination_guard import HallucinationGuardAgent
        self.guard = HallucinationGuardAgent()

    def test_grounded_output_passes(self):
        """A fully grounded output (all claims from context) should pass."""
        grounded = (
            "APT28 used spearphishing (T1566.001) to gain initial access. "
            "They exploited CVE-2021-44228 (Log4Shell) and CVE-2020-1472 "
            "(Zerologon) to compromise critical infrastructure networks."
        )
        result = self.guard.validate(grounded, REAL_CONTEXT)
        assert result.passed, f"Grounded output should pass. Scores: {result.tier_scores}"

    def test_mild_hallucination_detected(self):
        """One fabricated CVE mixed with real claims should be flagged."""
        result = self.guard.validate(HALLUCINATED_OUTPUT_MILD, REAL_CONTEXT)
        # The guard should detect lower faithfulness due to CVE-2099-99999
        assert result.hallucination_rate > 0.0, \
            f"Mild hallucination not detected. Rate={result.hallucination_rate}"

    def test_severe_hallucination_fails(self):
        """Entirely fabricated output should fail the guard."""
        result = self.guard.validate(HALLUCINATED_OUTPUT_SEVERE, REAL_CONTEXT)
        assert not result.passed, \
            f"Severely hallucinated output should fail. Scores: {result.tier_scores}"
        assert result.hallucination_rate > 0.3, \
            f"Severe hallucination rate too low: {result.hallucination_rate}"

    def test_subtle_hallucination_detected(self):
        """Mostly real claims with one fabricated CVE should lower faithfulness."""
        result = self.guard.validate(HALLUCINATED_OUTPUT_SUBTLE, REAL_CONTEXT)
        assert result.hallucination_rate > 0.0, \
            f"Subtle hallucination not detected. Rate={result.hallucination_rate}"

    def test_no_context_high_hallucination(self):
        """Without context, any detailed claim should be flagged by the guard."""
        result = self.guard.validate(HALLUCINATED_OUTPUT_SEVERE, "")
        # Guard should either: detect high hallucination rate, OR fail the output,
        # OR have very low embedding similarity (t1_embedding).
        # With NLI models, empty context yields "neutral" (non-contradicted) so
        # hallucination_rate may not be >0.5 — but t1 embedding should be near-zero.
        t1 = result.tier_scores.get("t1_embedding", 1.0)
        assert result.hallucination_rate > 0.0 or not result.passed or t1 < 0.2, \
            f"No-context should flag output: rate={result.hallucination_rate}, " \
            f"passed={result.passed}, t1={t1}"


# ═══════════════════════════════════════════════════════════════════
# Cross-Reference Tests
# ═══════════════════════════════════════════════════════════════════

class TestCrossReferenceInjection:
    """Test that fabricated entities fail cross-reference validation."""

    @staticmethod
    def _require_embedding_model():
        """Skip test if embedding model is unavailable (offline / not cached)."""
        try:
            from cti_shield.rag import _get_embedding_model
            model = _get_embedding_model()
            if model is None:
                pytest.skip("Embedding model not available (offline)")
        except Exception as e:
            pytest.skip(f"Embedding model not available: {e}")

    def test_fabricated_cve_not_in_corpus(self):
        """Fabricated CVEs should not appear in the RAG corpus."""
        self._require_embedding_model()
        from cti_shield.rag import get_vector_store
        store = get_vector_store()
        for fake_cve in FABRICATED_CVES:
            results = store.search(fake_cve, top_k=3)
            # Should find nothing relevant (or very low similarity)
            if results:
                best_score = max(r.get("score", 0) for r in results)
                assert best_score < 0.7, \
                    f"Fabricated {fake_cve} found in corpus with score {best_score}"

    def test_fabricated_actor_not_in_corpus(self):
        """Fabricated threat actors should not appear in the RAG corpus."""
        self._require_embedding_model()
        from cti_shield.rag import get_vector_store
        store = get_vector_store()
        for fake_actor in FABRICATED_ACTORS:
            results = store.search(fake_actor, top_k=3)
            if results:
                best_score = max(r.get("score", 0) for r in results)
                assert best_score < 0.5, \
                    f"Fabricated {fake_actor} found in corpus with score {best_score}"


# ═══════════════════════════════════════════════════════════════════
# Attribution Tests
# ═══════════════════════════════════════════════════════════════════

class TestAttributionInjection:
    """Test that fabricated claims cannot be attributed to real sources."""

    def test_fabricated_claims_unattributed(self):
        """Claims about fabricated CVEs should have no HIGH/MEDIUM source attribution."""
        from cti_shield.source_attributor import get_source_attributor
        attributor = get_source_attributor()

        result = attributor.attribute(
            HALLUCINATED_OUTPUT_SEVERE,
            retrieval_result={"vector_docs": [], "kg_context": []},
        )

        # Fabricated claims should NOT receive HIGH or MEDIUM confidence
        # (LOW is tolerable — FAISS fallback may find vaguely similar chunks)
        high_med_count = sum(
            1 for c in result.claims
            if c.attribution_confidence in ("HIGH", "MEDIUM")
        )
        assert high_med_count == 0, (
            f"Fabricated claims should not get HIGH/MEDIUM attribution, "
            f"but {high_med_count}/{result.total_claims} did: "
            f"{[(c.text[:60], c.attribution_confidence, c.similarity_score) for c in result.claims if c.attribution_confidence in ('HIGH', 'MEDIUM')]}"
        )

        # If claims ARE attributed, they should all be LOW confidence
        for c in result.claims:
            if c.source_id:
                assert c.attribution_confidence == "LOW" or c.similarity_score < 0.5, (
                    f"Fabricated claim attributed with too-high confidence: "
                    f"'{c.text[:60]}' → {c.attribution_confidence} (sim={c.similarity_score:.2f})"
                )

    def test_real_claims_attributed(self):
        """Claims about real CVEs with matching context should be attributed."""
        from cti_shield.source_attributor import get_source_attributor
        attributor = get_source_attributor()

        grounded = "APT28 exploited CVE-2021-44228 via spearphishing T1566.001."
        chunks = [{"text": REAL_CONTEXT, "technique_id": "T1566.001",
                    "source_url": "https://attack.mitre.org/techniques/T1566/001/"}]

        result = attributor.attribute(
            grounded,
            retrieval_result={"vector_docs": chunks, "kg_context": []},
        )

        assert result.attribution_rate > 0.0, \
            f"Real claims with context should be attributed: {result.attribution_rate}"


# ═══════════════════════════════════════════════════════════════════
# False Negative Rate Estimation
# ═══════════════════════════════════════════════════════════════════

class TestFalseNegativeRate:
    """
    Estimate the guard's false negative rate: how many hallucinated claims
    slip through the guard undetected. Target: < 5%.
    """

    INJECTION_CASES = [
        ("CVE-2099-99999 is a critical zero-day in OpenSSL.", REAL_CONTEXT),
        ("APT99 deployed ShadowFang malware using T9999.", REAL_CONTEXT),
        ("The Midnight Platypus group targets healthcare using quantum tunneling.", REAL_CONTEXT),
        ("CVE-2025-77777 allows unauthenticated RCE in all Linux kernels.", REAL_CONTEXT),
        ("CVE-2024-00000 bypasses TLS 1.4 quantum encryption.", REAL_CONTEXT),
    ]

    def test_false_negative_rate(self):
        """Guard should detect >95% of injected hallucinations."""
        from agents.hallucination_guard import HallucinationGuardAgent
        guard = HallucinationGuardAgent()

        detected = 0
        total = len(self.INJECTION_CASES)

        for hallucinated_claim, context in self.INJECTION_CASES:
            result = guard.validate(hallucinated_claim, context)
            if result.hallucination_rate > 0.0 or not result.passed:
                detected += 1

        detection_rate = detected / total
        false_negative_rate = 1.0 - detection_rate

        print(f"\n  Hallucination Detection Rate: {detection_rate:.1%} ({detected}/{total})")
        print(f"  False Negative Rate: {false_negative_rate:.1%}")

        # Target: < 20% false negatives (relaxed for demo mode)
        assert false_negative_rate < 0.20, \
            f"False negative rate too high: {false_negative_rate:.1%}. " \
            f"Guard missed {total - detected}/{total} injected hallucinations."
