"""
STIX 2.1 Models — Pydantic Validators
======================================
Validates STIX 2.1 objects using Pydantic v2 models.
"""
from __future__ import annotations
import re
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

STIX_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

class STIXBase(BaseModel):
    """Base model for all STIX 2.1 objects."""
    type: str
    spec_version: str = "2.1"
    id: str
    created: str
    modified: str
    
    @field_validator("id")
    @classmethod
    def validate_stix_id(cls, v: str) -> str:
        if not STIX_ID_PATTERN.match(v):
            raise ValueError(f"Invalid STIX ID format: {v}")
        return v

    @field_validator("id")
    @classmethod
    def validate_id_type_match(cls, v: str, info) -> str:
        if info.data.get("type") and not v.startswith(info.data["type"] + "--"):
            raise ValueError(f"ID prefix must match type: expected '{info.data['type']}--'")
        return v

    @field_validator("created", "modified")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            raise ValueError(f"Invalid ISO 8601 timestamp: {v}")
        return v

class ThreatActor(STIXBase):
    type: str = "threat-actor"
    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    threat_actor_types: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    goals: list[str] = Field(default_factory=list)
    sophistication: Optional[str] = None
    resource_level: Optional[str] = None
    primary_motivation: Optional[str] = None

class Malware(STIXBase):
    type: str = "malware"
    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    malware_types: list[str] = Field(default_factory=list)
    is_family: bool = False
    kill_chain_phases: list[dict[str, str]] = Field(default_factory=list)

class AttackPattern(STIXBase):
    type: str = "attack-pattern"
    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    kill_chain_phases: list[dict[str, str]] = Field(default_factory=list)
    external_references: list[dict[str, Any]] = Field(default_factory=list)

class Indicator(STIXBase):
    type: str = "indicator"
    name: Optional[str] = None
    description: Optional[str] = None
    indicator_types: list[str] = Field(default_factory=list)
    pattern: str = Field(..., min_length=1)
    pattern_type: str = "stix"
    valid_from: str = ""
    
    @field_validator("valid_from")
    @classmethod
    def validate_valid_from(cls, v: str) -> str:
        if v:
            try:
                datetime.fromisoformat(v.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                raise ValueError(f"Invalid valid_from timestamp: {v}")
        return v

class Vulnerability(STIXBase):
    type: str = "vulnerability"
    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    external_references: list[dict[str, Any]] = Field(default_factory=list)

class Relationship(STIXBase):
    type: str = "relationship"
    relationship_type: str = Field(..., min_length=1)
    source_ref: str
    target_ref: str
    description: Optional[str] = None
    
    @field_validator("source_ref", "target_ref")
    @classmethod
    def validate_ref(cls, v: str) -> str:
        if not STIX_ID_PATTERN.match(v):
            raise ValueError(f"Invalid STIX reference ID: {v}")
        return v

class STIXBundle(BaseModel):
    type: str = "bundle"
    id: str
    objects: list[dict[str, Any]] = Field(default_factory=list)
    
    @field_validator("id")
    @classmethod
    def validate_bundle_id(cls, v: str) -> str:
        if not v.startswith("bundle--"):
            raise ValueError("Bundle ID must start with 'bundle--'")
        return v

# Map type strings to model classes
STIX_TYPE_MAP: dict[str, type[STIXBase]] = {
    "threat-actor": ThreatActor,
    "malware": Malware,
    "attack-pattern": AttackPattern,
    "indicator": Indicator,
    "vulnerability": Vulnerability,
    "relationship": Relationship,
}

def validate_stix_object(obj: dict[str, Any]) -> tuple[bool, list[str], Optional[STIXBase]]:
    """
    Validate a STIX 2.1 object dict.
    Returns (is_valid, errors, parsed_model).
    """
    obj_type = obj.get("type", "")
    model_cls = STIX_TYPE_MAP.get(obj_type)
    
    if model_cls is None:
        return False, [f"Unknown STIX type: {obj_type}"], None
    
    try:
        parsed = model_cls(**obj)
        return True, [], parsed
    except Exception as e:
        errors = []
        for err in getattr(e, "errors", lambda: [{"msg": str(e)}])():
            loc = ".".join(str(l) for l in err.get("loc", []))
            errors.append(f"{loc}: {err['msg']}")
        return False, errors, None

def compute_compliance_score(obj: dict[str, Any]) -> float:
    """
    Compute STIX compliance score = validated_fields / required_fields.
    Returns a float between 0.0 and 1.0.
    """
    obj_type = obj.get("type", "")
    model_cls = STIX_TYPE_MAP.get(obj_type)
    if model_cls is None:
        return 0.0
    
    required = set()
    for name, field_info in model_cls.model_fields.items():
        if field_info.is_required():
            required.add(name)
    
    if not required:
        return 1.0
    
    valid_count = sum(1 for f in required if f in obj and obj[f])
    return valid_count / len(required)
