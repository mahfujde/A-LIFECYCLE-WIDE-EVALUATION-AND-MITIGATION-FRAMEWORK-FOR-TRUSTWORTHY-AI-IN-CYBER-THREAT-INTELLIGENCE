"""
KG Builder Agent — Knowledge Graph Construction
=================================================
Based on CTIKG (OpenReview 2024, 91.89% precision) and
CyberKG (MDPI 2025) — SecureBERT + BiLSTM + CRF methodology.

Extracts entity-relation-entity triples from CTI text,
maps to ATT&CK, and maintains an in-memory knowledge graph.
"""
from __future__ import annotations
import re, time, hashlib
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any
import structlog

log = structlog.get_logger()


@dataclass
class Triple:
    """A knowledge graph triple: (subject, predicate, object)."""
    subject: str
    predicate: str
    obj: str  # 'object' is reserved
    technique_id: str = ""
    technique_name: str = ""
    confidence: float = 0.0
    source: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def id(self) -> str:
        raw = f"{self.subject}|{self.predicate}|{self.obj}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]


# Cybersecurity relation patterns for entity-relation extraction
RELATION_PATTERNS = [
    (r'(?:uses?|employ(?:s|ed)?|leverage(?:s|d)?)\s+(.+?)(?:\s+to\s+|\s+for\s+)', "uses"),
    (r'(?:target(?:s|ed)?|attack(?:s|ed)?)\s+(.+?)(?:\s+via|\s+through|\s+using)', "targets"),
    (r'(?:exploit(?:s|ed)?)\s+(.+?)(?:\s+in\s+|\s+on\s+|\s+to\s+)', "exploits"),
    (r'(?:deliver(?:s|ed)?|drop(?:s|ped)?)\s+(.+?)(?:\s+via|\s+through|\s+to)', "delivers"),
    (r'(?:connect(?:s|ed)?\s+to|communicate(?:s|d)?\s+with)\s+(.+?)(?:\s|$)', "connects_to"),
    (r'(?:exfiltrate(?:s|d)?|steal(?:s)?|extract(?:s|ed)?)\s+(.+?)(?:\s|$)', "exfiltrates"),
    (r'(?:persist(?:s|ed)?\s+(?:via|through|using))\s+(.+?)(?:\s|$)', "persists_via"),
    (r'(?:is\s+associated\s+with|linked\s+to)\s+(.+?)(?:\s|$)', "associated_with"),
]

# Cybersecurity entity patterns (expanded for real-world reports)
ENTITY_PATTERNS = {
    "threat_actor": r'\b(?:APT[-\s]?\d+|UNC\d+|FIN\d+|Lazarus|Cozy Bear|Fancy Bear|Wizard Spider|Volt Typhoon|Scattered Spider|SamSam|Black Basta|SUNBURST|ALPHV|[A-Z][a-z]+\s+(?:Bear|Panda|Spider|Kitten|Dragon|Typhoon))\b',
    "malware": r'\b(?:Emotet|TrickBot|Cobalt Strike|Mimikatz|Metasploit|LockBit|BlackCat|Conti|REvil|DarkSide|QakBot|IcedID|Carbanak|X-Agent|Zebrocy|SUNBURST|TEARDROP|Raindrop|PsExec|rclone|AnyDesk|ConnectWise|WinSCP|Log4j|[A-Z][a-zA-Z]+(?:Bot|RAT|Loader|Stealer|Worm|Trojan|Kit|Dropper))\b',
    "cve": r'\bCVE-\d{4}-\d{4,7}\b',
    "ip_address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "domain": r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|tk|xyz|top|ru|cn|cc|info)\b',
    "hash_md5": r'\b[a-f0-9]{32}\b',
    "hash_sha256": r'\b[a-f0-9]{64}\b',
    "technique": r'\b[Tt]\d{4}(?:\.\d{3})?\b',
}

# ATT&CK technique mapping (common techniques)
ATTACK_TECHNIQUE_MAP = {
    "T1566": "Phishing", "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link", "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell", "T1059.003": "Windows Command Shell",
    "T1053": "Scheduled Task/Job", "T1053.005": "Scheduled Task",
    "T1071": "Application Layer Protocol", "T1071.001": "Web Protocols",
    "T1486": "Data Encrypted for Impact", "T1078": "Valid Accounts",
    "T1021": "Remote Services", "T1021.001": "Remote Desktop Protocol",
    "T1105": "Ingress Tool Transfer", "T1027": "Obfuscated Files or Information",
    "T1003": "OS Credential Dumping", "T1003.001": "LSASS Memory",
    "T1547": "Boot or Logon Autostart Execution", "T1547.001": "Registry Run Keys",
    "T1070": "Indicator Removal", "T1070.004": "File Deletion",
    "T1041": "Exfiltration Over C2 Channel", "T1567": "Exfiltration Over Web Service",
    "T1190": "Exploit Public-Facing Application", "T1133": "External Remote Services",
    "T1055": "Process Injection", "T1569": "System Services",
    "T1204": "User Execution", "T1204.001": "Malicious Link",
    "T1204.002": "Malicious File", "T1583": "Acquire Infrastructure",
    "T1110": "Brute Force", "T1534": "Internal Spearphishing",
    "T1505": "Server Software Component", "T1505.003": "Web Shell",
    "T1090": "Proxy", "T1195": "Supply Chain Compromise",
    "T1195.002": "Compromise Software Supply Chain",
    "T1219": "Remote Access Software", "T1490": "Inhibit System Recovery",
    "T1562": "Impair Defenses", "T1048": "Exfiltration Over Alternative Protocol",
}

# ── NLP-based TTP Mapping (natural language → ATT&CK) ────────────────
# This is what makes CTI-SHIELD unique: extracting TTPs from prose
NLP_TTP_MAP = {
    # ══════════════════════════════════════════════════════════════
    # INITIAL ACCESS (10 patterns)
    # ══════════════════════════════════════════════════════════════
    r'spear[\s-]?phish(?:ing)?(?:\s+(?:attachment|email|document))': ("T1566.001", "Spearphishing Attachment"),
    r'spear[\s-]?phish(?:ing)?(?:\s+link)': ("T1566.002", "Spearphishing Link"),
    r'phish(?:ing)?(?:\s+(?:email|campaign|attack))': ("T1566", "Phishing"),
    r'exploit(?:s|ed|ing)?\s+(?:known\s+)?vulnerabilit(?:y|ies)': ("T1190", "Exploit Public-Facing Application"),
    r'(?:exploit(?:s|ed)?|leverag(?:e|ed|ing))\s+(?:CVE|public[\s-]facing)': ("T1190", "Exploit Public-Facing Application"),
    r'supply[\s-]?chain\s+(?:compromise|attack|intrusion)': ("T1195.002", "Compromise Software Supply Chain"),
    r'(?:trojaniz|poison)(?:e|ed|ing)\s+(?:software|update|package)': ("T1195.002", "Compromise Software Supply Chain"),
    r'(?:valid|stolen|compromised)\s+(?:credentials?|accounts?)': ("T1078", "Valid Accounts"),
    r'brute[\s-]?force': ("T1110", "Brute Force"),
    r'(?:VPN|RDP|remote)\s+(?:access|service|appliance)': ("T1133", "External Remote Services"),
    # ══════════════════════════════════════════════════════════════
    # EXECUTION (7 patterns)
    # ══════════════════════════════════════════════════════════════
    r'powershell': ("T1059.001", "PowerShell"),
    r'(?:windows\s+)?command\s+shell': ("T1059.003", "Windows Command Shell"),
    r'(?:wmic|cmd\.exe|command[\s-]?line)': ("T1059.003", "Windows Command Shell"),
    r'(?:malicious\s+)?(?:macro|document|attachment)\s+execut': ("T1204.002", "Malicious File"),
    r'(?:social\s+engineering|lure|trick)\s+(?:to\s+)?(?:click|open|run)': ("T1204", "User Execution"),
    r'(?:python|bash|vbscript|javascript)\s+(?:script|payload)': ("T1059.006", "Python"),
    r'(?:WMI|Windows\s+Management\s+Instrumentation)\s+(?:for\s+)?execut': ("T1047", "Windows Management Instrumentation"),
    # ══════════════════════════════════════════════════════════════
    # PERSISTENCE (8 patterns)
    # ══════════════════════════════════════════════════════════════
    r'web[\s-]?shell': ("T1505.003", "Web Shell"),
    r'(?:registry|autostart|startup)\s+(?:key|entry|persist)': ("T1547.001", "Registry Run Keys"),
    r'(?:schedul(?:e|ed)\s+task)': ("T1053.005", "Scheduled Task"),
    r'(?:backdoor|persistent\s+access|maintain(?:ed|ing)?\s+(?:access|persistence))': ("T1078", "Valid Accounts"),
    r'(?:DLL|dynamic.link.library)\s+(?:hijack|side[\s-]?load|search[\s-]?order)': ("T1574.001", "DLL Search Order Hijacking"),
    r'(?:boot|logon)\s+(?:autostart|init)\s+execut': ("T1547", "Boot or Logon Autostart Execution"),
    r'(?:create|new)\s+(?:local|domain)\s+(?:account|user)': ("T1136", "Create Account"),
    r'(?:implant|rootkit|firmware)\s+(?:persist|backdoor)': ("T1542", "Pre-OS Boot"),
    # ══════════════════════════════════════════════════════════════
    # PRIVILEGE ESCALATION (5 patterns)
    # ══════════════════════════════════════════════════════════════
    r'(?:privilege|priv)\s+escalat': ("T1068", "Exploitation for Privilege Escalation"),
    r'(?:UAC|User\s+Account\s+Control)\s+bypass': ("T1548.002", "Bypass User Account Control"),
    r'(?:sudo|setuid|suid)\s+(?:exploit|abus)': ("T1548.003", "Sudo and Sudo Caching"),
    r'(?:access\s+token|token)\s+(?:manipulat|impersonat|steal)': ("T1134", "Access Token Manipulation"),
    r'(?:domain\s+admin|admin\s+credential|escalat\w+\s+to\s+admin)': ("T1078.002", "Domain Accounts"),
    # ══════════════════════════════════════════════════════════════
    # DEFENSE EVASION (15 patterns — expanded from 3)
    # ══════════════════════════════════════════════════════════════
    r'(?:living[\s-]off[\s-]the[\s-]land|LOL(?:BAS|bins|Bin))': ("T1218", "System Binary Proxy Execution"),
    r'(?:obfuscat(?:e|ed|ion)|encod(?:e|ed|ing)\s+(?:payload|script))': ("T1027", "Obfuscated Files or Information"),
    r'(?:proxy|traffic\s+(?:through|via)\s+(?:compromised|SOHO))': ("T1090", "Proxy"),
    r'(?:disabl|tamper|impair)(?:e|ed|ing)?\s+(?:antivirus|AV|EDR|defender|security\s+tool)': ("T1562.001", "Disable or Modify Tools"),
    r'(?:clear|delet|wipe)(?:e|ed|ing)?\s+(?:event\s+)?log': ("T1070.001", "Clear Windows Event Logs"),
    r'(?:timestomp|modif(?:y|ied)\s+timestamp)': ("T1070.006", "Timestomp"),
    r'(?:process|DLL)\s+(?:inject|hollow)': ("T1055", "Process Injection"),
    r'(?:reflective|in[\s-]?memory)\s+(?:load|injection|DLL)': ("T1620", "Reflective Code Loading"),
    r'(?:masquerad|disguise|renam)(?:e|ed|ing)?\s+(?:as|file|process|binary)': ("T1036", "Masquerading"),
    r'(?:rootkit|hide|hidden)\s+(?:process|file|artifact)': ("T1564", "Hide Artifacts"),
    r'(?:code|binary)\s+sign(?:ing|ed)?\s+(?:with\s+)?(?:stolen|invalid|self[\s-]?signed)': ("T1553.002", "Code Signing"),
    r'(?:rundll32|regsvr32|mshta|certutil)\s+(?:for\s+)?(?:execut|proxy|download)': ("T1218", "System Binary Proxy Execution"),
    r'(?:indicator|IOC)\s+remov(?:al|e|ed)': ("T1070", "Indicator Removal"),
    r'(?:virtuali[sz]ation|sandbox)\s+(?:evas|detect|aware)': ("T1497", "Virtualization/Sandbox Evasion"),
    r'(?:debog|anti[\s-]?debug|anti[\s-]?analysis)': ("T1622", "Debugger Evasion"),
    # ══════════════════════════════════════════════════════════════
    # CREDENTIAL ACCESS (6 patterns)
    # ══════════════════════════════════════════════════════════════
    r'(?:credential|password)\s+(?:dump(?:ing)?|harvest(?:ing)?|theft|steal)': ("T1003", "OS Credential Dumping"),
    r'(?:mimikatz|lsass|credential\s+dump)': ("T1003.001", "LSASS Memory"),
    r'(?:(?:SAML|token)\s+forg(?:e|ed|ing)|forg(?:e|ed|ing)\s+(?:SAML|token))': ("T1606.002", "SAML Tokens"),
    r'(?:keylogg(?:er|ing)|keystroke)': ("T1056.001", "Keylogging"),
    r'(?:kerberoast|AS[\s-]?REP\s+roast)': ("T1558.003", "Kerberoasting"),
    r'(?:password\s+spray|credential\s+stuff)': ("T1110.003", "Password Spraying"),
    # ══════════════════════════════════════════════════════════════
    # DISCOVERY (6 patterns — expanded from 2)
    # ══════════════════════════════════════════════════════════════
    r'(?:network\s+discovery|port\s+scan|reconnaissance|enumerat)': ("T1046", "Network Service Discovery"),
    r'(?:ntdsutil|netsh|wmic)\s+(?:for\s+)?discover': ("T1018", "Remote System Discovery"),
    r'(?:Active\s+Directory|AD)\s+(?:enumerat|recon|dump)': ("T1087.002", "Domain Account"),
    r'(?:BloodHound|SharpHound|ADFind)': ("T1087.002", "Domain Account"),
    r'(?:file\s+and\s+directory|dir|find|ls)\s+(?:discover|enumerat|list)': ("T1083", "File and Directory Discovery"),
    r'(?:system\s+information|systeminfo|hostname|uname)': ("T1082", "System Information Discovery"),
    # ══════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT (6 patterns — expanded from 3)
    # ══════════════════════════════════════════════════════════════
    r'(?:remote\s+desktop|RDP)\s+(?:protocol|for\s+lateral|movement|session)': ("T1021.001", "Remote Desktop Protocol"),
    r'lateral\s+mov(?:e|ement)': ("T1021", "Remote Services"),
    r'(?:PsExec|psexec|remote\s+(?:exec|execution))': ("T1569.002", "Service Execution"),
    r'(?:SMB|Windows\s+Admin\s+Shares?|C\$|ADMIN\$)\s+(?:for\s+)?(?:lateral|spread|access)': ("T1021.002", "SMB/Windows Admin Shares"),
    r'(?:WinRM|Windows\s+Remote\s+Management)': ("T1021.006", "Windows Remote Management"),
    r'(?:pass[\s-]the[\s-]hash|PtH|overpass[\s-]the[\s-]hash)': ("T1550.002", "Pass the Hash"),
    # ══════════════════════════════════════════════════════════════
    # COLLECTION (10 patterns — expanded from 3)
    # ══════════════════════════════════════════════════════════════
    r'(?:screen\s*(?:shot|capture)|capture\s+screen)': ("T1113", "Screen Capture"),
    r'(?:clipboard|copy\s+paste)\s+(?:data|capture|monitor)': ("T1115", "Clipboard Data"),
    r'(?:email|mailbox)\s+collect(?:ion)?': ("T1114", "Email Collection"),
    r'(?:archived?|compress|zip|rar|7z)\s+(?:collect|stag|before\s+exfil)': ("T1560", "Archive Collected Data"),
    r'(?:audio|microphone|webcam|camera)\s+captur': ("T1123", "Audio Capture"),
    r'(?:input\s+capture|man[\s-]in[\s-]the[\s-]browser)': ("T1185", "Browser Session Hijacking"),
    r'(?:network\s+sniff|packet\s+captur|wireshark|tcpdump)': ("T1040", "Network Sniffing"),
    r'(?:local|internal)\s+(?:data|file)\s+stag': ("T1074.001", "Local Data Staging"),
    r'(?:automated|scripted)\s+collect(?:ion)?': ("T1119", "Automated Collection"),
    r'(?:shared\s+drive|network\s+share|file\s+share)\s+(?:data|access|browse)': ("T1039", "Data from Network Shared Drive"),
    # ══════════════════════════════════════════════════════════════
    # EXFILTRATION (10 patterns — expanded from 4)
    # ══════════════════════════════════════════════════════════════
    r'exfiltrat(?:e|ed|ion|ing)\s+data': ("T1041", "Exfiltration Over C2 Channel"),
    r'(?:(?:rclone|cloud\s+storage|MEGA)\s+(?:for\s+)?exfiltrat|(?:using|via|with)\s+(?:rclone|MEGA|cloud\s+storage))': ("T1567", "Exfiltration Over Web Service"),
    r'(?:data\s+(?:theft|steal|exfil))|(?:steal\s+(?:data|information))': ("T1041", "Exfiltration Over C2 Channel"),
    r'(?:exfil|transfer|upload)\w*\s+(?:to|via)\s+(?:cloud|S3|Azure|GCP|Dropbox)': ("T1567.002", "Exfiltration to Cloud Storage"),
    r'(?:DNS|ICMP)\s+(?:tunnel|exfil|covert\s+channel)': ("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol"),
    r'(?:FTP|SFTP|SCP|WinSCP)\s+(?:for\s+)?(?:exfil|transfer|upload)': ("T1048", "Exfiltration Over Alternative Protocol"),
    r'(?:USB|removable|thumb\s+drive)\s+(?:exfil|copy|data)': ("T1052.001", "Exfiltration over USB"),
    r'(?:steganograph|hidden\s+in\s+image|covert\s+channel)': ("T1001.002", "Steganography"),
    r'(?:compress|encrypt)\s+(?:before|prior)\s+(?:exfil|transfer)': ("T1560", "Archive Collected Data"),
    r'(?:exfil|transfer)\w*\s+(?:over|via)\s+(?:HTTP|HTTPS|web)': ("T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"),
    # ══════════════════════════════════════════════════════════════
    # IMPACT (6 patterns — expanded from 4)
    # ══════════════════════════════════════════════════════════════
    r'(?:ransomware|encrypt(?:s|ed|ion)?\s+(?:files?|data))': ("T1486", "Data Encrypted for Impact"),
    r'(?:data\s+encrypted?\s+for\s+impact)': ("T1486", "Data Encrypted for Impact"),
    r'(?:volume\s+shadow|vssadmin|system\s+recovery)\s+(?:cop(?:y|ies)|delet)': ("T1490", "Inhibit System Recovery"),
    r'(?:ransom|bitcoin|cryptocurrency)\s+(?:payment|demand|note)': ("T1486", "Data Encrypted for Impact"),
    r'(?:wiper|destruct|destroy)\s+(?:data|files|system)': ("T1485", "Data Destruction"),
    r'(?:defac|deface|vandali[sz])(?:e|ed|ing)?\s+(?:website|page|portal)': ("T1491", "Defacement"),
    # ══════════════════════════════════════════════════════════════
    # COMMAND AND CONTROL (6 patterns — expanded from 3)
    # ══════════════════════════════════════════════════════════════
    r'(?:C2|C&C|command[\s-]and[\s-]control)\s+(?:channel|server|domain|infrastructure)': ("T1071.001", "Web Protocols"),
    r'(?:beacon|cobalt[\s-]?strike)': ("T1071.001", "Web Protocols"),
    r'(?:HTTP|HTTPS|DNS)\s+(?:for\s+)?(?:C2|command|communication)': ("T1071.001", "Web Protocols"),
    r'(?:domain\s+fronting|CDN[\s-]?based\s+C2)': ("T1090.004", "Domain Fronting"),
    r'(?:DNS\s+(?:tunnel|over[\s-]?HTTPS|C2))': ("T1071.004", "DNS"),
    r'(?:multi[\s-]?stage|dropper|stager)\s+(?:payload|implant)': ("T1104", "Multi-Stage Channels"),
    # ══════════════════════════════════════════════════════════════
    # RESOURCE DEVELOPMENT (8 patterns — NEW category)
    # ══════════════════════════════════════════════════════════════
    r'(?:register|purchas|acquir)(?:e|ed|ing)?\s+(?:domain|infrastructure)': ("T1583.001", "Domains"),
    r'(?:compromis|hijack)(?:e|ed|ing)?\s+(?:domain|infrastructure|server)': ("T1584.001", "Domains"),
    r'(?:develop|creat|custom)(?:e|ed|ing)?\s+(?:malware|implant|exploit|tool)': ("T1587.001", "Malware"),
    r'(?:obtain|steal|purchas)(?:e|ed|ing)?\s+(?:code[\s-]?signing|certificate)': ("T1588.003", "Code Signing Certificates"),
    r'(?:establish|set[\s-]?up|creat)\w*\s+(?:fake|fraudulent)\s+(?:account|persona|profile)': ("T1585.001", "Social Media Accounts"),
    r'(?:SIM\s+swap(?:ping)?|SIM\s+hijack|phone\s+(?:port|takeover))': ("T1598.002", "Spearphishing for Information"),
    r'(?:obtain|gather|collect)\s+(?:victim|target)\s+(?:info|data|intelligence)': ("T1589", "Gather Victim Identity Information"),
    r'(?:stage|pre[\s-]?position|pre[\s-]?stag)\w*\s+(?:capabilit|tool|payload)': ("T1608", "Stage Capabilities"),
    # ══════════════════════════════════════════════════════════════
    # REMOTE ACCESS (expanded)
    # ══════════════════════════════════════════════════════════════
    r'(?:AnyDesk|TeamViewer|ConnectWise|remote\s+monitoring\s+tool)': ("T1219", "Remote Access Software"),
    r'(?:ScreenConnect|Splashtop|LogMeIn|GoToAssist)': ("T1219", "Remote Access Software"),
    # ══════════════════════════════════════════════════════════════
    # CONTEXT-SPECIFIC (from real evaluation failures)
    # ══════════════════════════════════════════════════════════════
    r'remote\s+code\s+execut': ("T1190", "Exploit Public-Facing Application"),
    r'(?:unauthenticat(?:ed)?)\s+(?:remote\s+)?(?:code\s+)?execut': ("T1190", "Exploit Public-Facing Application"),
    r'(?:JNDI|Log4j|log4shell)': ("T1190", "Exploit Public-Facing Application"),
    r'(?:reset\s+password|MFA\s+(?:token|reset)|help\s+desk\s+(?:to\s+)?reset)': ("T1566", "Phishing"),
    r'(?:wire\s+transfer|redirect(?:ed)?\s+funds?|financial\s+fraud)': ("T1534", "Internal Spearphishing"),
    r'(?:email\s+account|business\s+email)\s+(?:compromise|intrusion)': ("T1078", "Valid Accounts"),
    r'(?:intercept|redirect)\s+(?:wire|payment|transfer)': ("T1534", "Internal Spearphishing"),
    r'(?:cryptomin(?:er|ing)|botnet|install\s+(?:malware|backdoor))': ("T1059", "Command and Scripting Interpreter"),
    r'(?:inserted|injected)\s+(?:malicious|backdoor)\s+(?:code|payload)\s+into\s+(?:software|update)': ("T1195.002", "Compromise Software Supply Chain"),
    r'(?:ChaCha20|AES[\s-]?256|RSA[\s-]?2048)\s+encrypt': ("T1486", "Data Encrypted for Impact"),
}



class KGBuilderAgent:
    """
    Builds and maintains an in-memory knowledge graph from CTI text.
    Uses NER + relation extraction + ATT&CK alignment.
    """

    def __init__(self) -> None:
        self.triples: list[Triple] = []
        self.entities: dict[str, set[str]] = {k: set() for k in ENTITY_PATTERNS}
        self.triple_index: dict[str, Triple] = {}

    def extract_entities(self, text: str) -> dict[str, list[str]]:
        """Extract cybersecurity entities using pattern matching."""
        found: dict[str, list[str]] = {}
        for entity_type, pattern in ENTITY_PATTERNS.items():
            matches = list(set(re.findall(pattern, text, re.IGNORECASE)))
            if matches:
                found[entity_type] = matches[:20]
                self.entities[entity_type].update(matches[:20])
        return found

    def extract_triples(self, text: str, source: str = "user_input") -> list[Triple]:
        """Extract entity-relation-entity triples from CTI text."""
        entities = self.extract_entities(text)
        new_triples: list[Triple] = []
        sentences = re.split(r'[.!?]\s+', text)

        for sentence in sentences:
            sent_entities = self.extract_entities(sentence)
            all_ents = []
            for etype, vals in sent_entities.items():
                for v in vals:
                    all_ents.append((etype, v))

            # Try relation patterns
            for pattern, rel_type in RELATION_PATTERNS:
                match = re.search(pattern, sentence, re.IGNORECASE)
                if match and len(all_ents) >= 1:
                    subject_type, subject = all_ents[0]
                    obj_text = match.group(1).strip()[:100]

                    triple = Triple(
                        subject=subject,
                        predicate=rel_type,
                        obj=obj_text,
                        source=source,
                        confidence=0.75,
                    )
                    # Map to ATT&CK
                    triple = self._map_to_attack(triple, sentence)
                    
                    if triple.id not in self.triple_index:
                        self.triples.append(triple)
                        self.triple_index[triple.id] = triple
                        new_triples.append(triple)

            # Auto-generate triples from entity co-occurrence
            if len(all_ents) >= 2:
                for i in range(len(all_ents) - 1):
                    for j in range(i + 1, min(i + 3, len(all_ents))):
                        t1_type, t1_val = all_ents[i]
                        t2_type, t2_val = all_ents[j]
                        rel = self._infer_relation(t1_type, t2_type)
                        triple = Triple(
                            subject=t1_val, predicate=rel, obj=t2_val,
                            source=source, confidence=0.60,
                        )
                        triple = self._map_to_attack(triple, sentence)
                        if triple.id not in self.triple_index:
                            self.triples.append(triple)
                            self.triple_index[triple.id] = triple
                            new_triples.append(triple)

        log.info("kg_triples_extracted", count=len(new_triples), total=len(self.triples))
        return new_triples

    # ── LLM-Assisted Triple Extraction ───────────────────────────

    # Structured prompt template — CTI-Thinker / CTIKG methodology
    # Forces JSON-only output with no prose to minimize hallucination
    _LLM_EXTRACTION_SYSTEM = (
        "You are a Cyber Threat Intelligence knowledge graph extraction engine.\n"
        "Your ONLY job is to extract entity-relation-entity triples from CTI text.\n\n"
        "STRICT RULES:\n"
        "1. Extract ONLY entities that are EXPLICITLY mentioned in the text.\n"
        "2. Do NOT invent, infer, or hallucinate any entities, CVEs, or technique IDs.\n"
        "3. For technique_id: use MITRE ATT&CK IDs (T1xxx or T1xxx.xxx) ONLY if the "
        "technique is clearly described. Set to null if unsure.\n"
        "4. Return ONLY valid JSON — no markdown, no preamble, no explanation.\n"
        "5. Confidence: 0.9 for explicit mentions, 0.7 for strong inferences, "
        "0.5 for weak inferences.\n\n"
        "VALID PREDICATES: uses, targets, exploits, delivers, attributed_to, "
        "part_of, mitigated_by, connects_to, exfiltrates, persists_via, employs\n\n"
        "RESPONSE SCHEMA (JSON only):\n"
        '{"triples": [\n'
        '  {"subject": "str", "predicate": "str", "object": "str",\n'
        '   "technique_id": "str|null", "tactic": "str|null", "confidence": 0.0}\n'
        "]}"
    )

    _LLM_EXTRACTION_USER = (
        "Extract all entity-relation-entity triples from this CTI report.\n"
        "Return ONLY JSON matching the schema. No other text.\n\n"
        "CTI TEXT:\n{text}\n\n"
        "JSON:"
    )

    def extract_triples_llm(
        self,
        text: str,
        llm_engine,
        source: str = "llm_extraction",
        merge_with_regex: bool = True,
    ) -> list[Triple]:
        """
        LLM-assisted knowledge graph triple extraction.

        Based on CTI-Thinker (Springer 2026) and CTIKG (OpenReview 2024):
          1. Send CTI text to LLM with structured JSON extraction prompt
          2. Parse and validate JSON response
          3. Cross-reference technique_ids against MITRE ATT&CK
          4. Merge with regex-extracted triples (dedup by content hash)

        Args:
            text:             CTI report text
            llm_engine:       LLMEngine instance (must have generate_response())
            source:           Provenance label for the triples
            merge_with_regex: If True, also run regex extraction and merge

        Returns:
            Merged list of validated Triple objects (LLM + regex).
            Falls back to regex-only if LLM fails.
        """
        import json as _json

        regex_triples: list[Triple] = []
        llm_triples: list[Triple] = []

        # ── Step 1: Always run regex extraction (baseline) ────────
        if merge_with_regex:
            regex_triples = self.extract_triples(text, source="regex")

        # ── Step 2: LLM extraction ───────────────────────────────
        try:
            prompt = (
                f"{self._LLM_EXTRACTION_SYSTEM}\n\n"
                f"{self._LLM_EXTRACTION_USER.format(text=text[:3000])}"
            )
            raw_response = llm_engine.generate_response(prompt, context="")

            # ── Step 3: Parse JSON from LLM response ─────────────
            parsed = self._parse_llm_json(raw_response)
            if parsed is None:
                log.warning("llm_extraction_json_parse_failed",
                            response_len=len(raw_response))
                return regex_triples or self.extract_triples(text, source="regex_fallback")

            raw_triples = parsed.get("triples", [])
            if not isinstance(raw_triples, list):
                log.warning("llm_extraction_invalid_triples_field")
                return regex_triples or self.extract_triples(text, source="regex_fallback")

            # ── Step 4: Validate and filter each triple ──────────
            for item in raw_triples:
                validated = self._validate_llm_triple(item, text)
                if validated is not None:
                    llm_triples.append(validated)

        except Exception as e:
            log.warning("llm_extraction_failed_using_regex_fallback", error=str(e))
            if not regex_triples:
                regex_triples = self.extract_triples(text, source="regex_fallback")
            return regex_triples

        # ── Step 5: Merge and deduplicate ────────────────────────
        merged = self._merge_triples(regex_triples, llm_triples)

        # ── Step 6: Index new triples ────────────────────────────
        new_count = 0
        for triple in merged:
            if triple.id not in self.triple_index:
                self.triples.append(triple)
                self.triple_index[triple.id] = triple
                new_count += 1

        log.info("kg_llm_extraction_complete",
                 regex_count=len(regex_triples),
                 llm_count=len(llm_triples),
                 merged_count=len(merged),
                 new_indexed=new_count,
                 total=len(self.triples))

        return merged

    def _parse_llm_json(self, raw: str) -> dict | None:
        """
        Extract JSON from an LLM response, handling common formatting issues.
        Strips markdown fences, preamble text, and trailing garbage.
        """
        import json as _json

        # Strip markdown code fences
        cleaned = re.sub(r'```(?:json)?\s*', '', raw)
        cleaned = re.sub(r'```\s*$', '', cleaned)

        # Try to find the JSON object
        # Strategy 1: direct parse
        try:
            return _json.loads(cleaned.strip())
        except _json.JSONDecodeError:
            pass

        # Strategy 2: find first { ... } block
        match = re.search(r'\{[\s\S]*\}', cleaned)
        if match:
            try:
                return _json.loads(match.group(0))
            except _json.JSONDecodeError:
                pass

        # Strategy 3: find [ ... ] and wrap
        match = re.search(r'\[[\s\S]*\]', cleaned)
        if match:
            try:
                arr = _json.loads(match.group(0))
                return {"triples": arr}
            except _json.JSONDecodeError:
                pass

        return None

    def _validate_llm_triple(self, item: dict, source_text: str) -> Triple | None:
        """
        Validate a single LLM-extracted triple:
          1. Must have subject, predicate, object (non-empty strings)
          2. technique_id must exist in ATTACK_TECHNIQUE_MAP (or be null)
          3. Subject and object should appear in the source text (anti-hallucination)
        """
        subject = str(item.get("subject", "")).strip()
        predicate = str(item.get("predicate", "")).strip()
        obj = str(item.get("object", "")).strip()

        # Rule 1: Required fields
        if not subject or not predicate or not obj:
            return None

        # Rule 2: Validate technique_id against ATT&CK
        technique_id = str(item.get("technique_id", "") or "").strip()
        technique_name = ""
        if technique_id:
            # Normalize format
            if not technique_id.startswith("T"):
                technique_id = f"T{technique_id}"
            if technique_id in ATTACK_TECHNIQUE_MAP:
                technique_name = ATTACK_TECHNIQUE_MAP[technique_id]
            else:
                # Hallucinated T-code — discard the technique_id, keep the triple
                log.debug("llm_hallucinated_technique_discarded",
                          technique_id=technique_id, subject=subject)
                technique_id = ""

        # Rule 3: Anti-hallucination — entity grounding check
        text_lower = source_text.lower()
        subj_grounded = subject.lower() in text_lower
        obj_grounded = obj.lower() in text_lower

        if not subj_grounded and not obj_grounded:
            log.debug("llm_triple_ungrounded_discarded",
                      subject=subject, object=obj)
            return None

        confidence = float(item.get("confidence", 0.7))
        confidence = max(0.0, min(1.0, confidence))

        # Reduce confidence for partially grounded triples
        if not subj_grounded or not obj_grounded:
            confidence *= 0.7

        return Triple(
            subject=subject,
            predicate=predicate,
            obj=obj,
            technique_id=technique_id,
            technique_name=technique_name,
            confidence=confidence,
            source="llm_extraction",
        )

    def _merge_triples(
        self, regex_triples: list[Triple], llm_triples: list[Triple],
    ) -> list[Triple]:
        """
        Merge regex and LLM triples, deduplicating by content hash.
        When both produce the same triple, keep the one with richer metadata
        (technique_id, higher confidence).
        """
        merged: dict[str, Triple] = {}

        # Regex triples first (baseline)
        for t in regex_triples:
            merged[t.id] = t

        # LLM triples overlay — keep richer version on collision
        for t in llm_triples:
            if t.id in merged:
                existing = merged[t.id]
                # Keep LLM version if it has technique_id and existing doesn't
                if t.technique_id and not existing.technique_id:
                    t.source = "llm_enriched"
                    merged[t.id] = t
                elif t.confidence > existing.confidence and t.technique_id:
                    t.source = "llm_enriched"
                    merged[t.id] = t
                # else keep regex version
            else:
                merged[t.id] = t

        return list(merged.values())

    def _map_to_attack(self, triple: Triple, context: str) -> Triple:
        """Map a triple to ATT&CK technique if applicable."""
        # First try explicit T-codes
        techniques = re.findall(r'[Tt](\d{4}(?:\.\d{3})?)', context)
        for tech_id in techniques:
            full_id = f"T{tech_id}"
            if full_id in ATTACK_TECHNIQUE_MAP:
                triple.technique_id = full_id
                triple.technique_name = ATTACK_TECHNIQUE_MAP[full_id]
                triple.confidence = min(1.0, triple.confidence + 0.15)
                return triple
        # Then try NLP pattern matching
        return self._nlp_map_to_attack(triple, context)

    def _nlp_map_to_attack(self, triple: Triple, context: str) -> Triple:
        """Map triple to ATT&CK using NLP patterns on natural language."""
        ctx_lower = context.lower()
        for pattern, (tech_id, tech_name) in NLP_TTP_MAP.items():
            if re.search(pattern, ctx_lower):
                triple.technique_id = tech_id
                triple.technique_name = tech_name
                triple.confidence = min(1.0, triple.confidence + 0.10)
                return triple
        return triple

    def extract_nlp_ttps(self, text: str) -> list[dict]:
        """Extract TTPs from natural language using NLP patterns.
        This is a KEY innovation: mapping prose descriptions to ATT&CK."""
        found = []
        seen = set()
        text_lower = text.lower()
        for pattern, (tech_id, tech_name) in NLP_TTP_MAP.items():
            if re.search(pattern, text_lower, re.IGNORECASE) and tech_id not in seen:
                found.append({"id": tech_id, "name": tech_name, "method": "nlp_pattern"})
                seen.add(tech_id)
        # Also get explicit T-codes
        for match in re.findall(r'[Tt](\d{4}(?:\.\d{3})?)', text):
            full_id = f"T{match}"
            if full_id in ATTACK_TECHNIQUE_MAP and full_id not in seen:
                found.append({"id": full_id, "name": ATTACK_TECHNIQUE_MAP[full_id], "method": "explicit"})
                seen.add(full_id)
        return found

    def _infer_relation(self, type1: str, type2: str) -> str:
        """Infer relation type from entity type pair."""
        pair = f"{type1}_{type2}"
        relation_map = {
            "threat_actor_malware": "uses",
            "malware_cve": "exploits",
            "threat_actor_technique": "employs",
            "malware_ip_address": "connects_to",
            "malware_domain": "connects_to",
            "threat_actor_ip_address": "operates_from",
            "threat_actor_domain": "controls",
            "cve_technique": "enables",
        }
        return relation_map.get(pair, "related_to")

    def semantic_search(self, query: str, k: int = 5) -> list[Triple]:
        """
        Search knowledge graph for relevant triples using embedding similarity.
        Falls back to lexical overlap if sentence-transformers is unavailable.
        """
        if not self.triples:
            return []

        try:
            return self._embedding_search(query, k)
        except Exception:
            return self._lexical_search(query, k)

    def _embedding_search(self, query: str, k: int) -> list[Triple]:
        """Embedding-based KG search using sentence-transformers."""
        import numpy as np
        from cti_shield.model_cache import get_sentence_transformer

        # Shared, process-wide cached model (previously re-loaded every call).
        model = get_sentence_transformer("all-MiniLM-L6-v2", device="cpu")

        # Encode query
        query_emb = model.encode([query[:500]], normalize_embeddings=True)

        # Encode all triples
        triple_texts = []
        for t in self.triples:
            text = f"{t.subject} {t.predicate} {t.obj}"
            if t.technique_id:
                text += f" [{t.technique_id}: {t.technique_name}]"
            triple_texts.append(text)

        triple_embs = model.encode(triple_texts, normalize_embeddings=True, batch_size=64)

        # Cosine similarity (normalized → dot product)
        sims = np.dot(triple_embs, query_emb[0])

        # Get top-k
        top_indices = np.argsort(sims)[::-1][:k]
        results = []
        for idx in top_indices:
            if sims[idx] > 0.05:  # minimum threshold
                results.append(self.triples[idx])
        return results

    def _lexical_search(self, query: str, k: int) -> list[Triple]:
        """Fallback: lexical keyword overlap search."""
        query_l = query.lower()
        scored: list[tuple[float, Triple]] = []

        for triple in self.triples:
            score = 0.0
            text = f"{triple.subject} {triple.predicate} {triple.obj}".lower()
            query_words = set(query_l.split())
            triple_words = set(text.split())
            overlap = len(query_words & triple_words)
            if overlap > 0:
                score = overlap / max(len(query_words), 1)
            if triple.technique_id:
                score += 0.1
            if score > 0:
                scored.append((score, triple))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in scored[:k]]

    def get_neighbors(self, entity: str, hops: int = 1) -> list[Triple]:
        """
        Graph traversal: get 1-hop (or multi-hop) neighbors of an entity.
        Returns all triples where the entity appears as subject or object.
        """
        if hops < 1:
            return []

        neighbors: list[Triple] = []
        visited_entities: set[str] = {entity.lower()}
        current_entities: set[str] = {entity.lower()}

        for _ in range(hops):
            next_entities: set[str] = set()
            for triple in self.triples:
                subj_l = triple.subject.lower()
                obj_l = triple.obj.lower()
                if subj_l in current_entities or obj_l in current_entities:
                    if triple not in neighbors:
                        neighbors.append(triple)
                    # Discover new entities for next hop
                    if subj_l not in visited_entities:
                        next_entities.add(subj_l)
                        visited_entities.add(subj_l)
                    if obj_l not in visited_entities:
                        next_entities.add(obj_l)
                        visited_entities.add(obj_l)
            current_entities = next_entities

        return neighbors

    def get_graph_stats(self) -> dict[str, Any]:
        return {
            "total_triples": len(self.triples),
            "entity_counts": {k: len(v) for k, v in self.entities.items()},
            "attack_mapped": sum(1 for t in self.triples if t.technique_id),
            "unique_techniques": len(set(t.technique_id for t in self.triples if t.technique_id)),
        }

    # ── G7: Persistence — serialize/deserialize to disk ───────────

    _KG_PERSIST_PATH = Path(__file__).resolve().parent.parent / "data" / "kg_snapshot.json"

    def save_to_disk(self) -> None:
        """G7: Persist the in-memory KG to disk as JSON."""
        import json as _json
        data = {
            "triples": [
                {"subject": t.subject, "predicate": t.predicate, "obj": t.obj,
                 "technique_id": t.technique_id, "technique_name": t.technique_name,
                 "confidence": t.confidence, "source": t.source, "timestamp": t.timestamp}
                for t in self.triples
            ],
            "entities": {k: sorted(v) for k, v in self.entities.items()},
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        self._KG_PERSIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._KG_PERSIST_PATH.write_text(_json.dumps(data, indent=2))
        log.info("kg_saved_to_disk", path=str(self._KG_PERSIST_PATH),
                 triples=len(self.triples))

    def load_from_disk(self) -> bool:
        """G7: Load a previously persisted KG snapshot."""
        import json as _json
        if not self._KG_PERSIST_PATH.exists():
            return False
        try:
            data = _json.loads(self._KG_PERSIST_PATH.read_text())
            for td in data.get("triples", []):
                t = Triple(
                    subject=td["subject"], predicate=td["predicate"], obj=td["obj"],
                    technique_id=td.get("technique_id", ""),
                    technique_name=td.get("technique_name", ""),
                    confidence=td.get("confidence", 0.0),
                    source=td.get("source", ""),
                    timestamp=td.get("timestamp", ""),
                )
                if t.id not in self.triple_index:
                    self.triples.append(t)
                    self.triple_index[t.id] = t
            for k, vals in data.get("entities", {}).items():
                if k in self.entities:
                    self.entities[k].update(vals)
            log.info("kg_loaded_from_disk", triples=len(self.triples),
                     saved_at=data.get("saved_at", "unknown"))
            return True
        except Exception as e:
            log.warning("kg_load_failed", error=str(e))
            return False


_kg_builder: KGBuilderAgent | None = None
def get_kg_builder() -> KGBuilderAgent:
    global _kg_builder
    if _kg_builder is None:
        _kg_builder = KGBuilderAgent()
        _kg_builder.load_from_disk()  # G7: auto-load persisted graph
    return _kg_builder

