"""
MITRE ATT&CK Loader
=====================
Loads and provides access to MITRE ATT&CK techniques.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Optional
import structlog
from config import MITRE_JSON, DATA_DIR

logger = structlog.get_logger(__name__)

# Default MITRE ATT&CK subset for demo/offline use
DEFAULT_TECHNIQUES: list[dict[str, Any]] = [
    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "description": "Adversaries may send phishing messages to gain access to victim systems."},
    {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access", "description": "Adversaries send spearphishing emails with a malicious attachment."},
    {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access", "description": "Adversaries send spearphishing emails with a malicious link."},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Adversaries may abuse command and script interpreters to execute commands."},
    {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "description": "Adversaries may abuse PowerShell for execution."},
    {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution", "description": "Adversaries may abuse the Windows command shell for execution."},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "description": "Adversaries may communicate using application layer protocols."},
    {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control", "description": "Adversaries may communicate using HTTP/HTTPS."},
    {"id": "T1005", "name": "Data from Local System", "tactic": "Collection", "description": "Adversaries may search local system sources for data."},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "description": "Adversaries may obfuscate payloads."},
    {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Execution", "description": "Adversaries may abuse task scheduling to execute malicious code."},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Persistence", "description": "Adversaries may obtain and abuse valid credentials."},
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "description": "Adversaries may use brute force to crack passwords."},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Adversaries may encrypt data on target systems (ransomware)."},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "description": "Adversaries may exploit vulnerabilities in internet-facing applications."},
    {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "description": "Adversaries may use remote services to move laterally."},
    {"id": "T1047", "name": "Windows Management Instrumentation", "tactic": "Execution", "description": "Adversaries may abuse WMI for execution."},
    {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "description": "Adversaries may steal data via non-standard protocols."},
    {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion", "description": "Adversaries may inject code into processes."},
    {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "description": "Adversaries may attempt to get detailed OS and hardware info."},
    {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "description": "Adversaries may enumerate files and directories."},
    {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence", "description": "Adversaries may manipulate accounts to maintain access."},
    {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "description": "Adversaries may transfer tools from external systems."},
    {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence", "description": "Adversaries may configure persistence via autostart."},
    {"id": "T1569", "name": "System Services", "tactic": "Execution", "description": "Adversaries may abuse system services for execution."},
]

class MITRELoader:
    """Loads and queries MITRE ATT&CK techniques."""
    
    def __init__(self) -> None:
        self.techniques: dict[str, dict[str, Any]] = {}
        self.tactics: dict[str, list[str]] = {}
        self._loaded = False
    
    def load(self, filepath: Path | None = None) -> None:
        """Load techniques from JSON file or use built-in defaults."""
        filepath = filepath or MITRE_JSON
        
        if filepath.exists():
            try:
                with open(filepath) as f:
                    data = json.load(f)
                techs = data if isinstance(data, list) else data.get("techniques", data.get("objects", []))
                for t in techs:
                    tid = t.get("id", t.get("external_id", ""))
                    if tid:
                        self.techniques[tid] = t
                        tactic = t.get("tactic", "Unknown")
                        self.tactics.setdefault(tactic, []).append(tid)
                logger.info("MITRE loaded from file", count=len(self.techniques))
                self._loaded = True
                return
            except Exception as e:
                logger.warning("Failed to load MITRE file, using defaults", error=str(e))
        
        # Use defaults
        for t in DEFAULT_TECHNIQUES:
            self.techniques[t["id"]] = t
            self.tactics.setdefault(t["tactic"], []).append(t["id"])
        self._loaded = True
        logger.info("MITRE loaded from defaults", count=len(self.techniques))
    
    def save_defaults(self) -> None:
        """Save default techniques to the data directory."""
        MITRE_JSON.parent.mkdir(parents=True, exist_ok=True)
        with open(MITRE_JSON, "w") as f:
            json.dump({"techniques": DEFAULT_TECHNIQUES}, f, indent=2)
    
    def get_technique(self, technique_id: str) -> dict[str, Any] | None:
        if not self._loaded: self.load()
        return self.techniques.get(technique_id)
    
    def search_techniques(self, query: str) -> list[dict[str, Any]]:
        if not self._loaded: self.load()
        q = query.lower()
        return [t for t in self.techniques.values() if q in t.get("name", "").lower() or q in t.get("description", "").lower() or q in t.get("id", "").lower()]
    
    def get_tactics(self) -> list[str]:
        if not self._loaded: self.load()
        return sorted(self.tactics.keys())
    
    def get_by_tactic(self, tactic: str) -> list[dict[str, Any]]:
        if not self._loaded: self.load()
        ids = self.tactics.get(tactic, [])
        return [self.techniques[tid] for tid in ids if tid in self.techniques]
    
    def generate_navigator_layer(self, highlighted: list[str] | None = None, name: str = "CTI-Shield") -> dict[str, Any]:
        """Generate ATT&CK Navigator layer JSON."""
        if not self._loaded: self.load()
        techniques = []
        for tid, t in self.techniques.items():
            entry = {"techniqueID": tid, "score": 0, "color": ""}
            if highlighted and tid in highlighted:
                entry["score"] = 1
                entry["color"] = "#ff6666"
            techniques.append(entry)
        return {
            "name": name, "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack", "description": f"Generated by {name}",
            "techniques": techniques, "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 1},
        }

# Singleton
_loader: MITRELoader | None = None

def get_mitre_loader() -> MITRELoader:
    global _loader
    if _loader is None:
        _loader = MITRELoader()
        _loader.load()
    return _loader
