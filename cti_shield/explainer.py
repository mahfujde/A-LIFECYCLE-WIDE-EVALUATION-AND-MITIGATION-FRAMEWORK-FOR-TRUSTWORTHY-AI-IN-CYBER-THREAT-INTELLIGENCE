"""
Plain-Language Explainer
=========================
Translates technical threat reports into language anyone can understand.
"""
from __future__ import annotations
from typing import Any
from config import SeverityLevel

SEVERITY_MAP = {
    "low": SeverityLevel.EVERYDAY,
    "medium": SeverityLevel.MODERATE,
    "high": SeverityLevel.SERIOUS,
    "critical": SeverityLevel.EMERGENCY,
}

JARGON_TRANSLATIONS = {
    "APT": "Advanced Persistent Threat (a well-funded hacker group that targets specific organisations)",
    "C2": "Command and Control (the hacker's remote control server)",
    "C&C": "Command and Control (the hacker's remote control server)",
    "RAT": "Remote Access Trojan (malware that lets hackers control your computer)",
    "phishing": "a trick email designed to steal your information",
    "spear-phishing": "a targeted trick email aimed specifically at you or your organisation",
    "ransomware": "malware that locks your files and demands payment",
    "zero-day": "a brand-new security flaw that hasn't been fixed yet",
    "exploit": "a method hackers use to take advantage of a security flaw",
    "payload": "the harmful part of malware that does the actual damage",
    "lateral movement": "when hackers spread from one computer to others on the same network",
    "exfiltration": "stealing and sending data out of your network",
    "IOC": "Indicator of Compromise (a clue that a hack happened)",
    "TTP": "Tactics, Techniques, and Procedures (how hackers operate)",
    "CVE": "Common Vulnerabilities and Exposures (a catalogue of known security flaws)",
    "DDoS": "Distributed Denial of Service (flooding a website to take it down)",
    "botnet": "a network of hacked computers controlled by attackers",
    "rootkit": "hidden malware that gives hackers deep access to your system",
    "keylogger": "software that secretly records everything you type",
    "credential stuffing": "trying stolen passwords on many websites",
    "brute force": "trying every possible password until one works",
    "SQL injection": "a hack that tricks a website's database into revealing data",
    "XSS": "Cross-Site Scripting (a hack that injects malicious code into websites)",
    "MFA": "Multi-Factor Authentication (using a second code beyond your password)",
    "2FA": "Two-Factor Authentication (using a second code beyond your password)",
}

def translate_jargon(text: str) -> str:
    """Replace technical jargon with plain-English explanations."""
    result = text
    for term, explanation in sorted(JARGON_TRANSLATIONS.items(), key=lambda x: -len(x[0])):
        if term.lower() in result.lower():
            result = result.replace(term, f"**{term}** ({explanation})")
    return result

def determine_severity(analysis: dict[str, Any]) -> SeverityLevel:
    """Determine human-readable severity from analysis results."""
    # Check top-level first, then nested 'analysis' dict
    severity_str = ""
    if "severity" in analysis:
        severity_str = str(analysis["severity"]).lower()
    else:
        inner = analysis.get("analysis", {})
        if isinstance(inner, dict):
            severity_str = str(inner.get("severity", "")).lower()
    
    if not severity_str:
        severity_str = "medium"
    
    for key, level in SEVERITY_MAP.items():
        if key in severity_str:
            return level
    
    # Also check "serious" and "emergency" directly
    if "serious" in severity_str:
        return SeverityLevel.SERIOUS
    if "emergency" in severity_str:
        return SeverityLevel.EMERGENCY
    
    score = analysis.get("risk_score", analysis.get("score", 50))
    if isinstance(score, (int, float)):
        if score >= 80: return SeverityLevel.EMERGENCY
        if score >= 60: return SeverityLevel.SERIOUS
        if score >= 40: return SeverityLevel.MODERATE
    return SeverityLevel.EVERYDAY

def generate_action_steps(severity: SeverityLevel, context: dict[str, Any] | None = None) -> list[str]:
    """Generate prioritised action steps based on severity."""
    base_actions = {
        SeverityLevel.EVERYDAY: [
            "Keep your software and apps updated",
            "Use strong, unique passwords for each account",
            "Be cautious of unexpected emails and links",
            "Back up your important files regularly",
        ],
        SeverityLevel.MODERATE: [
            "⚠️ Update all software and operating systems NOW",
            "⚠️ Enable two-factor authentication on important accounts",
            "⚠️ Scan your devices with antivirus software",
            "⚠️ Review recent account activity for anything suspicious",
            "Change passwords on your most important accounts",
        ],
        SeverityLevel.SERIOUS: [
            "🔴 IMMEDIATELY update all software and devices",
            "🔴 Change passwords on ALL accounts, starting with email and banking",
            "🔴 Enable two-factor authentication everywhere possible",
            "🔴 Run a full antivirus scan on all devices",
            "🔴 Monitor your bank accounts and credit cards for unusual activity",
            "Contact your IT department or a tech-savvy friend for help",
        ],
        SeverityLevel.EMERGENCY: [
            "🚨 STOP using affected devices immediately",
            "🚨 Disconnect from the internet if you suspect infection",
            "🚨 Change ALL passwords from a DIFFERENT, clean device",
            "🚨 Contact your bank to alert them of potential fraud",
            "🚨 File a report with your local cybercrime authority",
            "🚨 Consider professional incident response help",
            "🚨 Warn family members and colleagues who may be affected",
        ],
    }
    return base_actions.get(severity, base_actions[SeverityLevel.EVERYDAY])

def _extract_summary(analysis: dict[str, Any]) -> str:
    """
    Safely extract a human-readable summary string from the analysis result.
    Handles both flat string responses and nested dict structures.
    """
    inner = analysis.get("analysis", analysis.get("summary", "No analysis available."))
    
    # If the analysis value is a dict, extract the summary key
    if isinstance(inner, dict):
        return str(inner.get("summary", inner.get("description", str(inner.get("name", "Threat detected")))))
    
    # If it's already a string, use it directly
    if isinstance(inner, str):
        return inner
    
    return str(inner)

def explain_threat(analysis: dict[str, Any], audience: str = "general") -> dict[str, Any]:
    """
    Transform a technical threat analysis into a plain-language explanation.
    
    Args:
        analysis: The technical analysis dict from the LLM engine.
        audience: 'general', 'family', or 'business'.
    
    Returns:
        Plain-language explanation with severity, actions, and context.
    """
    severity = determine_severity(analysis)
    raw_summary = _extract_summary(analysis)
    plain_summary = translate_jargon(raw_summary)
    actions = generate_action_steps(severity, analysis)
    
    # "What does this mean for me?" section
    if audience == "family":
        personal_impact = _family_impact(severity)
    elif audience == "business":
        personal_impact = _business_impact(severity)
    else:
        personal_impact = _general_impact(severity)
    
    return {
        "severity": severity.value,
        "plain_summary": plain_summary,
        "what_it_means": personal_impact,
        "action_steps": actions,
        "audience": audience,
    }

def _general_impact(sev: SeverityLevel) -> str:
    impacts = {
        SeverityLevel.EVERYDAY: "This is a common type of threat. With basic precautions, you're likely safe.",
        SeverityLevel.MODERATE: "This threat could affect you if you're not careful. Take the recommended actions soon.",
        SeverityLevel.SERIOUS: "This is a significant threat. You should act on the recommendations today.",
        SeverityLevel.EMERGENCY: "This is an active, serious threat. Take immediate action to protect yourself.",
    }
    return impacts.get(sev, impacts[SeverityLevel.EVERYDAY])

def _family_impact(sev: SeverityLevel) -> str:
    impacts = {
        SeverityLevel.EVERYDAY: "Your family's devices are probably fine, but it's a good time to check everyone's passwords.",
        SeverityLevel.MODERATE: "Have a quick family meeting about not clicking strange links in emails or messages.",
        SeverityLevel.SERIOUS: "Help everyone in your family update their devices and change their important passwords today.",
        SeverityLevel.EMERGENCY: "This could affect your family's accounts and devices. Help everyone take protective steps right now.",
    }
    return impacts.get(sev, impacts[SeverityLevel.EVERYDAY])

def _business_impact(sev: SeverityLevel) -> str:
    impacts = {
        SeverityLevel.EVERYDAY: "Standard business security measures should be sufficient.",
        SeverityLevel.MODERATE: "Alert your IT team and ensure all business systems are patched.",
        SeverityLevel.SERIOUS: "This could impact business operations. Escalate to security leadership immediately.",
        SeverityLevel.EMERGENCY: "Potential business disruption. Activate your incident response plan now.",
    }
    return impacts.get(sev, impacts[SeverityLevel.EVERYDAY])
