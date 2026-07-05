"""
Personal Shield — Personal Protection Advisor
===============================================
Daily threat briefings, digital hygiene scoring,
risk checking, and family protection mode.
"""
from __future__ import annotations
import hashlib, json, re
from datetime import datetime, timezone
from typing import Any, Optional
import structlog
from config import settings

logger = structlog.get_logger(__name__)

# ── Digital Hygiene Questions ────────────────────────────────────────
HYGIENE_QUESTIONS = [
    {"id": "password_strength", "question": "Do you use unique, strong passwords (12+ characters) for each account?", "weight": 15, "tip": "Use a password manager like Bitwarden (free) to generate and store unique passwords."},
    {"id": "mfa_enabled", "question": "Do you have two-factor authentication (2FA) on your email and banking?", "weight": 15, "tip": "Enable 2FA in your account settings — use an authenticator app, not SMS."},
    {"id": "software_updates", "question": "Are your devices and apps up to date?", "weight": 12, "tip": "Turn on automatic updates for your OS, browser, and apps."},
    {"id": "email_phishing_awareness", "question": "Do you check sender addresses before clicking links in emails?", "weight": 10, "tip": "Hover over links to see the real URL. When in doubt, go directly to the website."},
    {"id": "network_security", "question": "Do you use a secure Wi-Fi network with a strong password?", "weight": 10, "tip": "Change your router's default password. Use WPA3 if available."},
    {"id": "data_backup", "question": "Do you back up important files regularly?", "weight": 8, "tip": "Use the 3-2-1 rule: 3 copies, 2 different media, 1 offsite (cloud)."},
    {"id": "social_engineering_awareness", "question": "Are you cautious about sharing personal info online?", "weight": 8, "tip": "Be careful on social media — attackers use personal details for targeted attacks."},
    {"id": "browser_security", "question": "Do you use a modern browser with security extensions?", "weight": 8, "tip": "Use an ad blocker (uBlock Origin) and HTTPS Everywhere."},
    {"id": "device_encryption", "question": "Is your device's storage encrypted?", "weight": 7, "tip": "Enable FileVault (Mac), BitLocker (Windows), or full-disk encryption (Linux)."},
    {"id": "privacy_settings", "question": "Have you reviewed privacy settings on your accounts recently?", "weight": 7, "tip": "Check Google, Facebook, and Apple privacy dashboards quarterly."},
]

def compute_hygiene_score(answers: dict[str, bool]) -> dict[str, Any]:
    """
    Compute a digital hygiene score (0-100) based on user answers.
    
    Args:
        answers: Dict mapping question IDs to True (yes) / False (no).
    
    Returns:
        Score, grade, and improvement tips.
    """
    total_weight = sum(int(q["weight"]) for q in HYGIENE_QUESTIONS)
    earned = sum(int(q["weight"]) for q in HYGIENE_QUESTIONS if answers.get(str(q["id"]), False))
    score = round((earned / total_weight) * 100) if total_weight else 0
    
    if score >= 90: grade, emoji = "Excellent", "🛡️"
    elif score >= 70: grade, emoji = "Good", "✅"
    elif score >= 50: grade, emoji = "Needs Improvement", "⚠️"
    else: grade, emoji = "At Risk", "🚨"
    
    tips = [str(q["tip"]) for q in HYGIENE_QUESTIONS if not answers.get(str(q["id"]), False)]
    
    return {"score": score, "grade": grade, "emoji": emoji, "max_score": 100, "tips": tips[:5], "answered": len(answers), "total_questions": len(HYGIENE_QUESTIONS)}

def get_hygiene_questions(family_mode: bool = False) -> list[dict[str, str]]:
    """Return hygiene questions, optionally simplified for family mode."""
    if not family_mode:
        return [{"id": str(q["id"]), "question": str(q["question"])} for q in HYGIENE_QUESTIONS]
    simplified = {
        "password_strength": "Does everyone in your family use different passwords?",
        "mfa_enabled": "Do your important accounts ask for a code from your phone when you log in?",
        "software_updates": "Do your devices install updates automatically?",
        "email_phishing_awareness": "Does your family know not to click links in suspicious emails?",
        "network_security": "Did you change the password on your home Wi-Fi router?",
        "data_backup": "Do you save copies of important photos and documents somewhere safe?",
        "social_engineering_awareness": "Is your family careful about what they share online?",
        "browser_security": "Does everyone use a modern web browser (Chrome, Firefox, Safari)?",
        "device_encryption": "Are your devices protected with a PIN or password?",
        "privacy_settings": "Have you checked privacy settings on your family's accounts?",
    }
    return [{"id": str(q["id"]), "question": str(simplified.get(str(q["id"]), q["question"]))} for q in HYGIENE_QUESTIONS]

# ── Risk Checker ─────────────────────────────────────────────────────
def check_risk(content: str) -> dict[str, Any]:
    """
    Check if a URL, email, or news article might be risky.
    Returns risk assessment with explanation.
    """
    content_lower = content.lower().strip()
    risk_indicators = []
    risk_score = 0
    
    # URL checks
    urls = re.findall(r"https?://[^\s]+", content_lower)
    for url in urls:
        if any(s in url for s in [".tk", ".ml", ".ga", ".cf", ".gq"]):
            risk_indicators.append("🔴 Suspicious domain extension (commonly used for scams)")
            risk_score += 30
        if any(s in url for s in ["login", "verify", "confirm", "update-account", "secure-"]):
            risk_indicators.append("🟡 URL contains words commonly used in phishing")
            risk_score += 20
        if len(url) > 100:
            risk_indicators.append("🟡 Unusually long URL (may be obfuscated)")
            risk_score += 10
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            risk_indicators.append("🔴 URL uses an IP address instead of a domain name")
            risk_score += 25
    
    # Email indicators
    if any(phrase in content_lower for phrase in ["urgent action required", "verify your account", "click here immediately", "you have won", "your account will be suspended", "act now or", "limited time offer"]):
        risk_indicators.append("🔴 Contains urgent/pressure language (common phishing tactic)")
        risk_score += 25
    
    if any(phrase in content_lower for phrase in ["dear customer", "dear user", "dear valued"]):
        risk_indicators.append("🟡 Generic greeting (legitimate companies usually use your name)")
        risk_score += 10
    
    # Grammar/spelling indicators
    if re.search(r"[A-Z]{5,}", content):
        risk_indicators.append("🟡 Excessive capitalisation (used to create urgency)")
        risk_score += 5
    
    if not risk_indicators:
        risk_indicators.append("✅ No obvious risk indicators found")
    
    risk_score = min(risk_score, 100)
    
    if risk_score >= 60: level = "High Risk"
    elif risk_score >= 30: level = "Medium Risk"
    else: level = "Low Risk"
    
    return {"risk_score": risk_score, "risk_level": level, "indicators": risk_indicators, "recommendation": _risk_recommendation(risk_score)}

def _risk_recommendation(score: int) -> str:
    if score >= 60:
        return "🚨 Do NOT click any links or provide personal information. This is likely malicious."
    elif score >= 30:
        return "⚠️ Be cautious. Verify the source independently before taking any action."
    else:
        return "✅ This appears relatively safe, but always stay vigilant."

# ── Daily Briefing ───────────────────────────────────────────────────
def generate_daily_briefing(threats: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Generate a plain-English daily threat briefing."""
    today = datetime.now(timezone.utc).strftime("%A, %B %d, %Y")
    
    if not threats:
        threats = [
            {"title": "Phishing emails increasing", "severity": "Medium", "tip": "Double-check sender addresses before clicking any links."},
            {"title": "Software update reminder", "severity": "Low", "tip": "Install pending updates on all your devices today."},
            {"title": "New data breach reported", "severity": "High", "tip": "Check haveibeenpwned.com to see if your email was affected."},
        ]
    
    tips = [
        "Never reuse passwords across different websites.",
        "Enable two-factor authentication on your email account.",
        "Be suspicious of emails creating urgency or fear.",
        "Keep your browser and operating system updated.",
        "Review app permissions on your phone quarterly.",
        "Use a VPN on public Wi-Fi networks.",
        "Back up important files to the cloud or external drive.",
    ]
    import random
    tip_of_day = random.choice(tips)
    
    return {"date": today, "greeting": f"Good day! Here's your security briefing for {today}.", "threats": threats, "tip_of_the_day": tip_of_day, "total_threats": len(threats)}

# ── Community Threat Sharing ─────────────────────────────────────────
def anonymise_threat_pattern(pattern: dict[str, Any]) -> dict[str, Any]:
    """Anonymise a threat pattern for community sharing."""
    anon = {
        "pattern_hash": hashlib.sha256(json.dumps(pattern, sort_keys=True).encode()).hexdigest()[:16],
        "type": pattern.get("type", "unknown"),
        "severity": pattern.get("severity", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    for field in ["name", "email", "ip", "organisation", "user"]:
        if field in pattern:
            del pattern[field]
    return anon
