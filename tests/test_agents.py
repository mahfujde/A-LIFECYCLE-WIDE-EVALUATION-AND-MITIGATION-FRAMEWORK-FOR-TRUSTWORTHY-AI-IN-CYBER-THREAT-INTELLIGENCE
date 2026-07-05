"""Tests for all 7 agents + orchestrator."""
import pytest
from agents.command_agent import CommandAgent, PipelineState, ActionType, EscalationLevel
from agents.kg_builder import KGBuilderAgent, Triple
from agents.hallucination_guard import HallucinationGuardAgent
from agents.drift_detector import DriftDetectorAgent, ADWINDetector
from agents.learning_agent import LearningAgent, AnalystFeedback
from agents.threat_reasoner import ThreatReasonerAgent


class TestCommandAgent:
    def setup_method(self):
        self.agent = CommandAgent()

    def test_classify_query(self):
        assert self.agent.classify_action("What is APT-28?") == ActionType.QUERY

    def test_classify_alert(self):
        assert self.agent.classify_action("ALERT: breach detected in network") == ActionType.ALERT

    def test_create_state(self):
        state = self.agent.create_state("test input")
        assert state.raw_input == "test input"
        assert len(state.audit_log) == 1
        assert state.audit_log[0].agent == "CommandAgent"

    def test_policy_low_confidence(self):
        state = PipelineState(confidence=0.40, analysis={"analysis": {}})
        state = self.agent.enforce_policy(state)
        assert state.escalation == EscalationLevel.WARNING

    def test_policy_critical_escalation(self):
        state = PipelineState(confidence=0.90,
                              analysis={"analysis": {"severity": "CRITICAL"}})
        state = self.agent.enforce_policy(state)
        assert state.escalation == EscalationLevel.HUMAN_REQUIRED

    def test_should_retry(self):
        state = PipelineState(guard_passed=False, guard_retries=1)
        assert self.agent.should_retry_reasoning(state) is True
        state.guard_retries = 3
        assert self.agent.should_retry_reasoning(state) is False


class TestKGBuilder:
    def setup_method(self):
        self.agent = KGBuilderAgent()

    def test_extract_entities(self):
        text = "APT-28 uses Emotet to exploit CVE-2024-1234"
        entities = self.agent.extract_entities(text)
        assert "threat_actor" in entities
        assert "malware" in entities
        assert "cve" in entities

    def test_extract_triples(self):
        text = "APT-28 uses Emotet malware via T1566.001 spearphishing"
        triples = self.agent.extract_triples(text)
        assert len(triples) > 0
        # Should have ATT&CK mapping
        mapped = [t for t in triples if t.technique_id]
        assert len(mapped) > 0

    def test_triple_id_unique(self):
        t1 = Triple(subject="A", predicate="uses", obj="B")
        t2 = Triple(subject="A", predicate="uses", obj="C")
        assert t1.id != t2.id

    def test_semantic_search(self):
        self.agent.extract_triples("APT-28 uses Emotet for phishing attacks via T1566.001")
        results = self.agent.semantic_search("Emotet phishing", k=3)
        assert len(results) > 0

    def test_graph_stats(self):
        self.agent.extract_triples("Lazarus group deploys TrickBot via CVE-2023-5678")
        stats = self.agent.get_graph_stats()
        assert stats["total_triples"] > 0
        assert isinstance(stats["entity_counts"], dict)

    def test_attack_mapping(self):
        text = "The attacker used T1059.001 PowerShell and T1003 credential dumping"
        triples = self.agent.extract_triples(text)
        tech_ids = {t.technique_id for t in triples if t.technique_id}
        assert len(tech_ids) > 0


class TestKGBuilderNLPExpanded:
    """Regression tests for the 5 CISA advisories that previously failed."""

    def setup_method(self):
        self.agent = KGBuilderAgent()

    def _extract_ids(self, text: str) -> set[str]:
        ttps = self.agent.extract_nlp_ttps(text)
        return {t["id"] for t in ttps}

    # ── LockBit (AA23-136A) — was missing LOtL → T1218 ──────────
    def test_lockbit_living_off_the_land(self):
        text = ("LockBit affiliates use living-off-the-land techniques and "
                "Cobalt Strike beacons for lateral movement.")
        ids = self._extract_ids(text)
        assert "T1218" in ids, f"Expected T1218 (LOtL), got {ids}"

    def test_lockbit_exfil_rclone(self):
        text = "Before encryption, actors exfiltrate data using rclone and MEGA cloud storage."
        ids = self._extract_ids(text)
        assert "T1567" in ids, f"Expected T1567 (Web Service Exfil), got {ids}"

    # ── Black Basta (AA24-131A) — was missing encryption → T1486 ─
    def test_black_basta_chacha20(self):
        text = "The ransomware uses ChaCha20 encryption T1486."
        ids = self._extract_ids(text)
        assert "T1486" in ids, f"Expected T1486 (Data Encrypted), got {ids}"

    def test_black_basta_credential_dump(self):
        text = "They use tools like Mimikatz for credential dumping T1003.001."
        ids = self._extract_ids(text)
        assert "T1003.001" in ids or "T1003" in ids, f"Expected T1003*, got {ids}"

    def test_black_basta_winscp_exfil(self):
        text = "Before deploying ransomware they exfiltrate data using WinSCP."
        ids = self._extract_ids(text)
        assert "T1048" in ids or "T1041" in ids, f"Expected exfil technique, got {ids}"

    # ── SolarWinds (SUNBURST) — was missing supply chain → T1195.002
    def test_solarwinds_supply_chain(self):
        text = ("The SolarWinds supply chain compromise affected 18,000 organizations. "
                "The threat actor inserted malicious code called SUNBURST into "
                "SolarWinds Orion software updates.")
        ids = self._extract_ids(text)
        assert "T1195.002" in ids, f"Expected T1195.002 (Supply Chain), got {ids}"

    def test_solarwinds_saml_forgery(self):
        text = "Actors moved laterally via forged SAML tokens."
        ids = self._extract_ids(text)
        assert "T1606.002" in ids or "T1003" in ids, f"Expected SAML forgery technique, got {ids}"

    # ── Scattered Spider (AA23-325A) — was missing SIM swap → T1598.002
    def test_scattered_spider_sim_swap(self):
        text = "Scattered Spider uses SIM swapping to take over victim phone numbers."
        ids = self._extract_ids(text)
        assert "T1598.002" in ids, f"Expected T1598.002 (SIM swap), got {ids}"

    def test_scattered_spider_remote_access(self):
        text = "They install remote monitoring tools like AnyDesk and ConnectWise."
        ids = self._extract_ids(text)
        assert "T1219" in ids, f"Expected T1219 (Remote Access), got {ids}"

    # ── SamSam — was missing RDP → T1021.001 ────────────────────
    def test_samsam_rdp_lateral(self):
        text = ("SamSam actors exploited Windows servers via Remote Desktop Protocol "
                "to gain persistent access.")
        ids = self._extract_ids(text)
        assert "T1021.001" in ids or "T1133" in ids, f"Expected RDP technique, got {ids}"

    def test_samsam_psexec(self):
        text = "After gaining access they used PsExec to escalate privileges."
        ids = self._extract_ids(text)
        assert "T1569.002" in ids, f"Expected T1569.002 (PsExec), got {ids}"

    # ── New tactic coverage ─────────────────────────────────────
    def test_defense_evasion_disable_av(self):
        text = "The attacker disabled antivirus software and cleared event logs."
        ids = self._extract_ids(text)
        assert "T1562.001" in ids or "T1070.001" in ids

    def test_collection_screenshot(self):
        text = "Malware captures screenshots and clipboard data."
        ids = self._extract_ids(text)
        assert "T1113" in ids or "T1115" in ids

    def test_resource_development_domain(self):
        text = "The group registered domains and developed custom malware."
        ids = self._extract_ids(text)
        assert "T1583.001" in ids or "T1587.001" in ids

    def test_pattern_count_above_95(self):
        """Verify we have at least 95 NLP patterns (target: ~100)."""
        from agents.kg_builder import NLP_TTP_MAP
        assert len(NLP_TTP_MAP) >= 95, f"Only {len(NLP_TTP_MAP)} patterns, need ≥95"


class TestHallucinationGuard:
    def setup_method(self):
        self.guard = HallucinationGuardAgent()

    def test_pass_grounded_output(self):
        output = "This phishing attack uses social engineering email"
        context = "phishing attack social engineering email campaign"
        result = self.guard.validate(output, context)
        assert result.passed is True

    def test_fail_ungrounded_output(self):
        output = "The quantum blockchain zero-day exploits the metaverse infrastructure"
        context = "simple phishing email with suspicious link"
        result = self.guard.validate(output, context)
        # Should fail or have high hallucination rate
        assert result.hallucination_rate > 0.3

    def test_tier3_fake_cve(self):
        fakes = self.guard._check_cve_refs("Exploiting CVE-1990-9999")
        assert len(fakes) > 0

    def test_tier3_valid_ttp(self):
        fakes = self.guard._check_ttp_refs("Uses T1566.001 phishing")
        assert len(fakes) == 0  # T1566 is valid

    def test_tier3_fake_ttp(self):
        fakes = self.guard._check_ttp_refs("Uses T9999 fake technique")
        assert len(fakes) > 0

    def test_claim_extraction(self):
        text = "The attacker used phishing. They exploited a zero-day. Data was exfiltrated."
        claims = self.guard._extract_claims(text)
        assert len(claims) >= 2

    def test_stats(self):
        self.guard.validate("test", "test context")
        stats = self.guard.get_stats()
        assert stats["total_checks"] >= 1


class TestDriftDetector:
    def setup_method(self):
        self.detector = DriftDetectorAgent()

    def test_stable_signal(self):
        signal = self.detector.monitor(trust_score=80.0, fp_rate=0.1)
        assert signal.type == "STABLE"

    def test_status(self):
        self.detector.monitor(trust_score=75.0)
        status = self.detector.get_status()
        assert status["trust_observations"] == 1
        assert status["status"] == "STABLE"

    def test_adwin_basic(self):
        adwin = ADWINDetector(delta=0.1)
        # Feed stable data
        for _ in range(20):
            adwin.update(0.5)
        assert adwin.drift_detected is False


class TestLearningAgent:
    def setup_method(self):
        self.learner = LearningAgent()

    def test_process_feedback_with_correction(self):
        fb = AnalystFeedback(
            query="test query",
            correction="correct analysis",
            original_analysis="wrong analysis",
            rating=2,
        )
        result = self.learner.process_feedback(fb)
        assert len(result["actions"]) > 0
        assert len(self.learner.prompt_library) == 1

    def test_process_feedback_false_positive(self):
        fb = AnalystFeedback(is_false_positive=True, rating=1)
        result = self.learner.process_feedback(fb)
        assert any("False positive" in a for a in result["actions"])

    def test_weight_adjustment(self):
        old_acc = self.learner.current_weights["accuracy"]
        self.learner._adjust_weight("accuracy", 0.05)
        assert self.learner.current_weights["accuracy"] == old_acc + 0.05

    def test_weight_clamping(self):
        self.learner._adjust_weight("accuracy", 100.0)
        assert self.learner.current_weights["accuracy"] <= 0.50

    def test_few_shot_retrieval(self):
        fb = AnalystFeedback(query="phishing attack", correction="correct")
        self.learner.process_feedback(fb)
        examples = self.learner.get_few_shot_examples("phishing email")
        assert len(examples) > 0

    def test_summary(self):
        summary = self.learner.get_summary()
        assert "total_feedback" in summary
        assert "current_weights" in summary


class TestThreatReasoner:
    def test_init(self):
        reasoner = ThreatReasonerAgent()
        assert reasoner.analysis_count == 0

    def test_confidence_estimation(self):
        reasoner = ThreatReasonerAgent()
        analysis = {"analysis": {"summary": "test", "red_flags": ["flag1"],
                                 "iocs": {"ips": ["1.2.3.4"]}}}
        from agents.hybrid_retriever import RetrievalResult
        retrieval = RetrievalResult(mode="test")
        conf = reasoner._estimate_confidence(analysis, [], [{"id": "T1566"}], retrieval)
        assert 0.0 < conf <= 1.0

    def test_hybrid_retrieve(self):
        """Test that _hybrid_retrieve returns a RetrievalResult."""
        from agents.kg_builder import KGBuilderAgent
        reasoner = ThreatReasonerAgent()
        kg = KGBuilderAgent()
        kg.extract_triples("APT-28 uses Emotet for phishing via T1566.001")
        result = reasoner._hybrid_retrieve("APT-28 phishing", kg)
        assert result is not None
