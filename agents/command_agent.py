"""
Command Agent — Orchestrator: route + policy enforcement
==========================================================
Based on AgentSOC (IEEE 2026, arxiv 2604.20134) — multi-agent
sense-reason-act loop for SOC automation.

Routes queries to appropriate agents and enforces NIST AI RMF policies.
"""
from __future__ import annotations
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Literal
from enum import Enum
import structlog

log = structlog.get_logger()


class ActionType(str, Enum):
    QUERY = "query"
    ALERT = "alert"
    FEEDBACK = "feedback"
    INGEST = "ingest"


class EscalationLevel(str, Enum):
    NONE = "none"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    HUMAN_REQUIRED = "human_required"


@dataclass
class AgentAction:
    """Audit log entry for every agent action."""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent: str = ""
    action: str = ""
    input_summary: str = ""
    output_summary: str = ""
    duration_ms: float = 0.0
    success: bool = True
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineState:
    """Shared state passed through the agent pipeline."""
    # Input
    raw_input: str = ""
    action_type: ActionType = ActionType.QUERY
    
    # Processing
    cleaned_text: str = ""
    iocs: dict[str, list] = field(default_factory=dict)
    kg_triples: list[dict] = field(default_factory=list)
    
    # Analysis
    analysis: dict[str, Any] = field(default_factory=dict)
    ttps: list[dict] = field(default_factory=list)
    stix_objects: list[dict] = field(default_factory=list)
    
    # Guard
    guard_result: dict[str, Any] = field(default_factory=dict)
    guard_passed: bool = False
    guard_retries: int = 0
    max_guard_retries: int = 3
    
    # Trust & Drift
    trust_score: float = 0.0
    drift_signal: str = "STABLE"
    confidence: float = 0.0
    
    # Output
    explanation: dict[str, Any] = field(default_factory=dict)
    escalation: EscalationLevel = EscalationLevel.NONE
    
    # Audit
    audit_log: list[AgentAction] = field(default_factory=list)
    
    # Context
    context: dict[str, Any] = field(default_factory=dict)
    model_used: str = ""
    latency_ms: float = 0.0
    
    def log_action(self, agent: str, action: str, **kwargs) -> None:
        entry = AgentAction(agent=agent, action=action, **kwargs)
        self.audit_log.append(entry)
        log.info("agent_action", agent=agent, action=action, 
                 success=entry.success, duration_ms=entry.duration_ms)


class CommandAgent:
    """
    Central orchestrator implementing AgentSOC sense-reason-act loop.
    Routes queries, enforces policies, manages escalation.
    """

    # NIST AI RMF policy constraints
    CONFIDENCE_THRESHOLD = 0.60
    CRITICAL_REQUIRES_HUMAN = True
    MAX_GUARD_RETRIES = 3

    def __init__(self) -> None:
        self.total_queries = 0
        self.escalations = 0

    def classify_action(self, text: str) -> ActionType:
        """Classify incoming input to determine routing."""
        text_l = text.lower()
        alert_signals = ["alert", "incident", "breach", "compromised", "detected"]
        if any(s in text_l for s in alert_signals):
            return ActionType.ALERT
        return ActionType.QUERY

    def create_state(self, raw_input: str, context: dict | None = None) -> PipelineState:
        """Initialize pipeline state for a new request."""
        self.total_queries += 1
        action_type = self.classify_action(raw_input)
        
        state = PipelineState(
            raw_input=raw_input,
            action_type=action_type,
            context=context or {},
        )
        state.log_action("CommandAgent", "initialize",
                         input_summary=raw_input[:100],
                         metadata={"action_type": action_type.value})
        return state

    def enforce_policy(self, state: PipelineState) -> PipelineState:
        """Apply NIST AI RMF policy constraints after analysis."""
        # Policy 1: Low confidence → append uncertainty flag
        if state.confidence < self.CONFIDENCE_THRESHOLD:
            state.escalation = EscalationLevel.WARNING
            if isinstance(state.analysis.get("analysis"), dict):
                state.analysis["analysis"]["uncertainty_flag"] = True
                state.analysis["analysis"]["confidence_note"] = (
                    f"⚠️ Confidence {state.confidence:.0%} is below threshold. "
                    "Results should be verified by a human analyst."
                )
            state.log_action("CommandAgent", "policy_low_confidence",
                             metadata={"confidence": state.confidence})

        # Policy 2: Critical threats → require human confirmation
        severity = ""
        inner = state.analysis.get("analysis", {})
        if isinstance(inner, dict):
            severity = str(inner.get("severity", "")).lower()
        
        if severity in ("emergency", "critical") and self.CRITICAL_REQUIRES_HUMAN:
            state.escalation = EscalationLevel.HUMAN_REQUIRED
            self.escalations += 1
            state.log_action("CommandAgent", "policy_critical_escalation",
                             metadata={"severity": severity})

        # Policy 3: Guard failures → escalate
        if not state.guard_passed and state.guard_retries >= self.MAX_GUARD_RETRIES:
            state.escalation = EscalationLevel.HUMAN_REQUIRED
            state.log_action("CommandAgent", "policy_guard_exhausted",
                             metadata={"retries": state.guard_retries})

        return state

    def should_retry_reasoning(self, state: PipelineState) -> bool:
        """Check if we should retry the Threat Reasoner after guard failure."""
        return (not state.guard_passed and 
                state.guard_retries < self.MAX_GUARD_RETRIES)

    def route_drift_action(self, state: PipelineState) -> str:
        """Decide action based on drift signal."""
        if state.drift_signal == "NEW_PATTERN":
            return "kg_build"  # Urgent KG update
        elif state.drift_signal == "DEGRADED":
            return "recalibrate"  # Weight recalibration
        return "output"  # Normal flow

    def get_audit_summary(self) -> dict[str, Any]:
        return {
            "total_queries": self.total_queries,
            "total_escalations": self.escalations,
        }


# Singleton
_command_agent: CommandAgent | None = None
def get_command_agent() -> CommandAgent:
    global _command_agent
    if _command_agent is None:
        _command_agent = CommandAgent()
    return _command_agent
