"""Tests for STIX 2.1 models."""
import sys, uuid
from pathlib import Path
from datetime import datetime, timezone
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from cti_shield.stix_models import (
    ThreatActor, Malware, AttackPattern, Indicator, Vulnerability,
    Relationship, STIXBundle, validate_stix_object, compute_compliance_score,
)

NOW = datetime.now(timezone.utc).isoformat()

class TestThreatActor:
    def test_valid(self):
        ta = ThreatActor(
            id=f"threat-actor--{uuid.uuid4()}", created=NOW, modified=NOW,
            name="APT1", threat_actor_types=["nation-state"],
        )
        assert ta.name == "APT1"

    def test_invalid_id(self):
        with pytest.raises(Exception):
            ThreatActor(id="bad", created=NOW, modified=NOW, name="Test")

class TestMalware:
    def test_valid(self):
        m = Malware(
            id=f"malware--{uuid.uuid4()}", created=NOW, modified=NOW,
            name="TestRAT", malware_types=["trojan"], is_family=True,
        )
        assert m.is_family is True

class TestAttackPattern:
    def test_valid(self):
        ap = AttackPattern(
            id=f"attack-pattern--{uuid.uuid4()}", created=NOW, modified=NOW,
            name="Phishing",
        )
        assert ap.name == "Phishing"

class TestRelationship:
    def test_valid_refs(self):
        src = f"threat-actor--{uuid.uuid4()}"
        tgt = f"malware--{uuid.uuid4()}"
        r = Relationship(
            id=f"relationship--{uuid.uuid4()}", created=NOW, modified=NOW,
            relationship_type="uses", source_ref=src, target_ref=tgt,
        )
        assert r.relationship_type == "uses"

    def test_invalid_ref(self):
        with pytest.raises(Exception):
            Relationship(
                id=f"relationship--{uuid.uuid4()}", created=NOW, modified=NOW,
                relationship_type="uses", source_ref="bad", target_ref="bad",
            )

class TestValidateFunction:
    def test_valid_object(self):
        obj = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{uuid.uuid4()}",
            "created": NOW,
            "modified": NOW,
            "name": "Test",
        }
        valid, errors, parsed = validate_stix_object(obj)
        assert valid is True
        assert len(errors) == 0

    def test_unknown_type(self):
        valid, errors, _ = validate_stix_object({"type": "unknown-type"})
        assert valid is False

class TestComplianceScore:
    def test_full_compliance(self):
        obj = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{uuid.uuid4()}",
            "created": NOW,
            "modified": NOW,
            "name": "Test",
        }
        score = compute_compliance_score(obj)
        assert score >= 0.8

    def test_missing_fields(self):
        score = compute_compliance_score({"type": "threat-actor"})
        assert score < 1.0

    def test_unknown_type(self):
        score = compute_compliance_score({"type": "nonexistent"})
        assert score == 0.0
