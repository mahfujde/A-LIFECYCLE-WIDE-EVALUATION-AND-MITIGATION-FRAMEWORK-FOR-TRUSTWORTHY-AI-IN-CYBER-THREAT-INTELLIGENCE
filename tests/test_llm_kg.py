#!/usr/bin/env python3
"""Test LLM-assisted KG extraction."""
import sys, json
sys.path.insert(0, '.')

from agents.kg_builder import KGBuilderAgent, Triple, ATTACK_TECHNIQUE_MAP

kb = KGBuilderAgent()
print("=== LLM-Assisted KG Extraction Test ===\n")

# 1. Clean JSON
p1 = kb._parse_llm_json('{"triples": [{"subject": "APT28", "predicate": "uses", "object": "CS", "technique_id": "T1071.001", "confidence": 0.9}]}')
assert p1 and len(p1["triples"]) == 1
print("[1] OK: Clean JSON")

# 2. Markdown fenced
fenced = "```json\n" + '{"triples": [{"subject": "A", "predicate": "uses", "object": "B"}]}' + "\n```"
p2 = kb._parse_llm_json(fenced)
assert p2 and len(p2["triples"]) == 1
print("[2] OK: Markdown fenced")

# 3. Preamble
p3 = kb._parse_llm_json('Here:\n{"triples": [{"subject": "X", "predicate": "exploits", "object": "Y"}]}')
assert p3 and len(p3["triples"]) == 1
print("[3] OK: Preamble")

# 4. Valid triple
src = "APT28 used Cobalt Strike beacons for lateral movement."
v = kb._validate_llm_triple({"subject": "APT28", "predicate": "uses", "object": "Cobalt Strike", "technique_id": "T1071.001", "confidence": 0.9}, src)
assert v and v.technique_id == "T1071.001" and v.technique_name == "Web Protocols"
print(f"[4] OK: Valid triple [{v.technique_id}]")

# 5. Hallucinated T-code
h = kb._validate_llm_triple({"subject": "APT28", "predicate": "uses", "object": "Cobalt Strike", "technique_id": "T9999", "confidence": 0.9}, src)
assert h and h.technique_id == ""
print("[5] OK: Hallucinated T9999 discarded")

# 6. Ungrounded entities
u = kb._validate_llm_triple({"subject": "QuantumHacker", "predicate": "uses", "object": "MetaverseExploit"}, src)
assert u is None
print("[6] OK: Ungrounded rejected")

# 7. Missing fields
m = kb._validate_llm_triple({"subject": "", "predicate": "uses", "object": "X"}, src)
assert m is None
print("[7] OK: Missing fields rejected")

# 8. Merge with enrichment
regex_t = [Triple(subject="APT28", predicate="uses", obj="Cobalt Strike", confidence=0.6, source="regex")]
llm_t = [Triple(subject="APT28", predicate="uses", obj="Cobalt Strike", technique_id="T1071.001", technique_name="Web Protocols", confidence=0.9, source="llm")]
merged = kb._merge_triples(regex_t, llm_t)
assert len(merged) == 1 and merged[0].technique_id == "T1071.001" and merged[0].source == "llm_enriched"
print(f"[8] OK: LLM enriches regex → {merged[0].source}")

# 9. No collision
llm_t2 = [Triple(subject="APT28", predicate="exploits", obj="CVE-2024-1234", technique_id="T1190", confidence=0.85, source="llm")]
m2 = kb._merge_triples(regex_t, llm_t2)
assert len(m2) == 2
print("[9] OK: No collision → 2 triples")

# 10. Full pipeline with mock LLM
class MockLLM:
    def generate_response(self, prompt, context=""):
        return json.dumps({"triples": [
            {"subject": "APT28", "predicate": "uses", "object": "Cobalt Strike", "technique_id": "T1071.001", "confidence": 0.9},
            {"subject": "APT28", "predicate": "exploits", "object": "CVE-2024-12345", "technique_id": "T1190", "confidence": 0.85},
            {"subject": "InventedActor", "predicate": "uses", "object": "FakeToolXYZ", "technique_id": "T9999", "confidence": 0.5},
        ]})

kb2 = KGBuilderAgent()
text = "APT28 used Cobalt Strike beacons for lateral movement and exploited CVE-2024-12345 for initial access."
triples = kb2.extract_triples_llm(text, MockLLM(), merge_with_regex=True)
llm_src = [t for t in triples if "llm" in t.source]
regex_src = [t for t in triples if t.source == "regex"]
print(f"[10] OK: Pipeline: {len(triples)} merged ({len(llm_src)} LLM, {len(regex_src)} regex)")
for t in triples[:5]:
    print(f"     {t.source:15s} | {t.subject} --{t.predicate}--> {t.obj} [{t.technique_id}]")

# 11. Fallback on failure
class BrokenLLM:
    def generate_response(self, prompt, context=""):
        raise RuntimeError("LLM unavailable")

kb3 = KGBuilderAgent()
fallback = kb3.extract_triples_llm(text, BrokenLLM(), merge_with_regex=False)
assert len(fallback) > 0  # should fallback to regex
print(f"[11] OK: Fallback on LLM failure → {len(fallback)} regex triples")

# 12. Prompt templates
assert "JSON" in kb._LLM_EXTRACTION_SYSTEM
assert "{text}" in kb._LLM_EXTRACTION_USER
print("[12] OK: Prompt templates validated")

print(f"\n{'='*55}")
print("ALL 12 TESTS PASSED — LLM-Assisted KG Extraction")
print(f"{'='*55}")
