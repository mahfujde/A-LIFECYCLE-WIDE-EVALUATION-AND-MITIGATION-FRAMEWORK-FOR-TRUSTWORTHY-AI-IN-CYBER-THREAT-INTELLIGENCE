#!/usr/bin/env python3
"""
Test Source Attributor — RO3 claim provenance
"""
import sys
sys.path.insert(0, '.')

from cti_shield.source_attributor import SourceAttributor, AttributedResponse

sa = SourceAttributor()
print("=== Source Attributor Tests ===\n")

# ── Test 1: Claim extraction & classification ────────────────────

llm_text = (
    "APT28 used spearphishing emails with malicious attachments targeting government organizations. "
    "The attack exploited CVE-2024-3400 in Palo Alto PAN-OS for initial access. "
    "Lateral movement was achieved via T1021.001 Remote Desktop Protocol. "
    "The group deployed Cobalt Strike beacons for command and control. "
    "Data was exfiltrated over encrypted HTTPS channels."
)

claims = sa._extract_factual_claims(llm_text)
print(f"[1] Extracted {len(claims)} claims:")
for c in claims:
    print(f"    {c.claim_type:8s} | {c.text[:70]}... entities={c.entities_found}")

assert len(claims) == 5, f"Expected 5 claims, got {len(claims)}"
types = [c.claim_type for c in claims]
assert "actor" in types, "Should detect actor claim"
assert "CVE" in types, "Should detect CVE claim"
assert "TTP" in types, "Should detect TTP claim"
assert "malware" in types, "Should detect malware claim"
print("[1] ✅ Claim extraction + classification\n")

# ── Test 2: Entity matching (exact) ──────────────────────────────

chunks = [
    {"text": "T1021.001 Remote Desktop Protocol allows lateral movement via RDP sessions",
     "source_type": "vector", "technique_id": "T1021.001",
     "stix_id": "attack-pattern--eb062747"},
    {"text": "CVE-2024-3400 is a critical pre-auth RCE in PAN-OS GlobalProtect",
     "source_type": "vector", "technique_id": "", "stix_id": "",
     "feed_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"},
    {"text": "APT28 Fancy Bear is a Russian state-sponsored group targeting governments",
     "source_type": "kg", "technique_id": "", "triple_id": "abc123"},
]

# Claim with T1021.001 should match first chunk
ttp_claim = [c for c in claims if c.claim_type == "TTP"][0]
attributed = sa._attribute_claim(ttp_claim, chunks)
assert attributed.source_id == "attack-pattern--eb062747"
assert attributed.attribution_confidence == "HIGH"
print(f"[2] ✅ TTP entity match → {attributed.source_id} ({attributed.attribution_confidence})")

# CVE claim should match NVD chunk
cve_claim = [c for c in claims if c.claim_type == "CVE"][0]
attributed_cve = sa._attribute_claim(cve_claim, chunks)
assert "nvd.nist.gov" in attributed_cve.source_id
print(f"    ✅ CVE entity match → {attributed_cve.source_id}")

# Actor claim should match KG chunk
actor_claim = [c for c in claims if c.claim_type == "actor"][0]
attributed_actor = sa._attribute_claim(actor_claim, chunks)
assert attributed_actor.source_id == "KG:abc123"
print(f"    ✅ Actor entity match → {attributed_actor.source_id}\n")

# ── Test 3: Semantic similarity (no exact match) ────────────────

general_claim = [c for c in claims if c.claim_type == "general"][0]
attributed_gen = sa._attribute_claim(general_claim, chunks)
print(f"[3] General claim: sim={attributed_gen.similarity_score:.3f}, "
      f"conf={attributed_gen.attribution_confidence}, src={attributed_gen.source_id}")
print("[3] ✅ Semantic similarity fallback\n")

# ── Test 4: Full attribution pipeline ────────────────────────────

retrieval = {
    "vector_docs": [
        {"text": "T1566.001 Spearphishing Attachment — malicious files in emails",
         "technique_id": "T1566.001", "stix_id": "attack-pattern--2e34237d"},
        {"text": "CVE-2024-3400 critical RCE in PAN-OS GlobalProtect gateway",
         "technique_id": "", "feed_url": "https://nvd.nist.gov/CVE-2024-3400"},
    ],
    "kg_context": [
        {"text": "APT28 uses spearphishing and Cobalt Strike for government targeting",
         "technique_id": "T1566", "triple_id": "kg-apt28-001"},
    ],
}

result = sa.attribute(llm_text, retrieval_result=retrieval)
print(f"[4] Full pipeline: {result.total_claims} claims, "
      f"{result.attributed_claims} attributed, "
      f"rate={result.attribution_rate:.1%}")
for c in result.claims:
    status = "✓" if c.source_id else "✗"
    print(f"    {status} {c.claim_type:8s} → {c.source_id or 'NONE':40s} "
          f"({c.attribution_confidence}, sim={c.similarity_score:.2f})")
assert result.attribution_rate > 0.5, f"Rate too low: {result.attribution_rate}"
print("[4] ✅ Full attribution pipeline\n")

# ── Test 5: Citation report ──────────────────────────────────────

report = sa.generate_citation_report(result)
assert "SOURCE ATTRIBUTION REPORT" in report
assert "Attributed:" in report
lines = report.split("\n")
print(f"[5] Citation report: {len(lines)} lines")
print(report[:500])
print("[5] ✅ Citation report generation\n")

# ── Test 6: Empty input handling ─────────────────────────────────

empty = sa.attribute("", retrieval_result={})
assert empty.total_claims == 0
assert empty.attribution_rate == 0.0
print("[6] ✅ Empty input handling\n")

# ── Test 7: No source chunks ────────────────────────────────────

no_src = sa.attribute(llm_text, retrieval_result={})
assert no_src.total_claims == 5
print(f"[7] No sources: {no_src.attributed_claims}/{no_src.total_claims} attributed")
print("[7] ✅ Graceful degradation with no sources\n")

# ── Test 8: to_dict() serialization ──────────────────────────────

d = result.to_dict()
assert "attribution_rate" in d
assert "claims" in d
assert len(d["claims"]) == result.total_claims
assert all("claim_type" in c for c in d["claims"])
print("[8] ✅ JSON serialization\n")

print("=" * 55)
print("ALL 8 TESTS PASSED — Source Attributor (RO3)")
print("=" * 55)
