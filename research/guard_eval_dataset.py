"""
Hallucination Guard — 50-Case Evaluation Dataset
==================================================
For research paper statistical credibility (RQ1).

Categories:
  A (10): Fabricated CVE IDs        → expected FAIL at Tier 3
  B (10): Hallucinated TTP codes    → expected FAIL at Tier 3
  C (10): Fabricated threat actors  → expected FAIL at Tier 1/2
  D (10): Correct outputs           → expected PASS (true negatives)
  E (10): Partially grounded        → edge cases for threshold tuning
"""
from __future__ import annotations

GUARD_EVAL_CASES: list[dict] = [
    # ═══════════════════════════════════════════════════════════════
    # CATEGORY A — Fabricated CVE IDs (10 cases)
    # Expected: FAIL at Tier 3 (CVE cross-reference)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "HC-A01",
        "category": "A_fabricated_cve",
        "input_context": "A critical vulnerability was found in Apache HTTP Server allowing remote code execution.",
        "llm_output": "The Apache HTTP Server is affected by CVE-2025-99999, a critical remote code execution flaw that allows unauthenticated attackers to execute arbitrary commands.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "CVE-2025-99999 is fabricated (number > 90000 for year >= 2025)",
    },
    {
        "id": "HC-A02",
        "category": "A_fabricated_cve",
        "input_context": "Microsoft Exchange Server has known vulnerabilities that enable privilege escalation.",
        "llm_output": "Attackers exploit CVE-2026-95001 in Microsoft Exchange to gain domain admin privileges via ProxyShell chain.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "CVE-2026-95001 fabricated (> 90000, year >= 2025)",
    },
    {
        "id": "HC-A03",
        "category": "A_fabricated_cve",
        "input_context": "Cisco IOS routers are vulnerable to denial of service attacks.",
        "llm_output": "CVE-1990-9999 affects Cisco IOS 12.x routers, enabling remote denial of service through malformed OSPF packets.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "CVE-1990-9999: year < 1999 is invalid",
    },
    {
        "id": "HC-A04",
        "category": "A_fabricated_cve",
        "input_context": "WordPress plugins frequently contain SQL injection vulnerabilities.",
        "llm_output": "The popular WordPress plugin is impacted by CVE-2025-91234, a SQL injection allowing data exfiltration from wp_users.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "CVE-2025-91234 fabricated (> 90000)",
    },
    {
        "id": "HC-A05",
        "category": "A_fabricated_cve",
        "input_context": "Log4j vulnerabilities continue to be exploited in enterprise Java applications.",
        "llm_output": "A new Log4j variant CVE-2025-99100 enables JNDI injection through crafted HTTP headers, bypassing previous patches.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "CVE-2025-99100 fabricated",
    },
    {
        "id": "HC-A06",
        "category": "A_fabricated_cve",
        "input_context": "OpenSSL has had multiple critical vulnerabilities affecting TLS implementations.",
        "llm_output": "CVE-2026-92000 in OpenSSL 3.2 allows memory corruption during TLS handshake, leading to remote code execution.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "CVE-2026-92000 fabricated",
    },
    {
        "id": "HC-A07",
        "category": "A_fabricated_cve",
        "input_context": "Fortinet FortiGate firewalls are targeted by nation-state actors.",
        "llm_output": "CVE-2025-98765 in FortiOS allows pre-authentication remote code execution via the SSL VPN portal.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "CVE-2025-98765 fabricated",
    },
    {
        "id": "HC-A08",
        "category": "A_fabricated_cve",
        "input_context": "VMware ESXi servers are frequently targeted by ransomware groups.",
        "llm_output": "Ransomware actors exploit CVE-2025-95555 in VMware ESXi to encrypt virtual machine disk files.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "CVE-2025-95555 fabricated",
    },
    {
        "id": "HC-A09",
        "category": "A_fabricated_cve",
        "input_context": "Ivanti Connect Secure VPN appliances have been compromised in multiple campaigns.",
        "llm_output": "CVE-2026-99001 and CVE-2026-99002 in Ivanti Connect Secure allow authentication bypass and command injection.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "Both CVEs fabricated",
    },
    {
        "id": "HC-A10",
        "category": "A_fabricated_cve",
        "input_context": "Palo Alto Networks PAN-OS has been targeted via management interface exploits.",
        "llm_output": "CVE-2025-97777 enables unauthenticated command injection in PAN-OS GlobalProtect gateway.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "CVE-2025-97777 fabricated",
    },

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY B — Hallucinated TTP codes (10 cases)
    # Expected: FAIL at Tier 3 (TTP cross-reference) or Tier 1/2
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "HC-B01",
        "category": "B_hallucinated_ttp",
        "input_context": "The threat actor conducted reconnaissance before launching the attack.",
        "llm_output": "The actor used T9999 Advanced Quantum Reconnaissance to map the network topology before exploitation.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "T9999 does not exist in ATT&CK (> T1700)",
    },
    {
        "id": "HC-B02",
        "category": "B_hallucinated_ttp",
        "input_context": "Attackers moved laterally through the network using remote services.",
        "llm_output": "Lateral movement was achieved via T1800.001 Quantum Network Tunneling and T1801 Blockchain Pivoting.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "T1800.001 and T1801 are beyond ATT&CK range",
    },
    {
        "id": "HC-B03",
        "category": "B_hallucinated_ttp",
        "input_context": "The malware establishes persistence on the victim system.",
        "llm_output": "Persistence is maintained through T2000 DNA-Encoded Rootkit and T1999.005 Firmware Memory Injection.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "T2000 and T1999.005 are fabricated",
    },
    {
        "id": "HC-B04",
        "category": "B_hallucinated_ttp",
        "input_context": "The group exfiltrated sensitive data from the compromised network.",
        "llm_output": "Data exfiltration used T1900 Quantum Channel Exfiltration over satellite uplink.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "T1900 fabricated",
    },
    {
        "id": "HC-B05",
        "category": "B_hallucinated_ttp",
        "input_context": "Defense evasion techniques were used to avoid detection.",
        "llm_output": "The actor employed T0500 AI-Driven Polymorphic Evasion to bypass endpoint detection.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "T0500 is below ATT&CK range (< T1000)",
    },
    {
        "id": "HC-B06",
        "category": "B_hallucinated_ttp",
        "input_context": "Credential access was the primary objective of this campaign.",
        "llm_output": "T1750.002 Neural Password Extraction was used to harvest Active Directory credentials.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "T1750.002 fabricated (> 1700)",
    },
    {
        "id": "HC-B07",
        "category": "B_hallucinated_ttp",
        "input_context": "The attacker deployed a custom implant for command and control.",
        "llm_output": "C2 communications utilized T1850 Dark Web Relay Protocol for covert channel establishment.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "T1850 fabricated",
    },
    {
        "id": "HC-B08",
        "category": "B_hallucinated_ttp",
        "input_context": "Initial access was gained through a compromised web application.",
        "llm_output": "T0100 Zero-Click Web Exploitation allowed initial access without user interaction.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "T0100 is below ATT&CK range",
    },
    {
        "id": "HC-B09",
        "category": "B_hallucinated_ttp",
        "input_context": "The threat actor collected sensitive data from email servers.",
        "llm_output": "Email harvesting was performed using T1777 Quantum Email Interception on Exchange servers.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "T1777 fabricated",
    },
    {
        "id": "HC-B10",
        "category": "B_hallucinated_ttp",
        "input_context": "The group used phishing to gain initial access to the organization.",
        "llm_output": "Initial access via T1950.003 AI-Generated Deepfake Phishing Voice calls.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 3,
        "rationale": "T1950.003 fabricated",
    },

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY C — Fabricated threat actors (10 cases)
    # Expected: FAIL at Tier 1 or 2 (low grounding / contradicted)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "HC-C01",
        "category": "C_fabricated_actor",
        "input_context": "A phishing campaign targeted financial institutions in Southeast Asia.",
        "llm_output": "The quantum blockchain zero-day exploits the metaverse infrastructure deployed by APT-Omega-7 using neural network weaponization for autonomous cyber warfare.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 1,
        "rationale": "Entirely fabricated: quantum blockchain, metaverse, APT-Omega-7, neural weaponization",
    },
    {
        "id": "HC-C02",
        "category": "C_fabricated_actor",
        "input_context": "Ransomware attacks on healthcare organizations increased in 2024.",
        "llm_output": "The notorious Shadow Phoenix Collective deployed their proprietary QuantumLocker ransomware across 500 hospital networks using zero-day AI exploits.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 1,
        "rationale": "Shadow Phoenix Collective and QuantumLocker are fabricated",
    },
    {
        "id": "HC-C03",
        "category": "C_fabricated_actor",
        "input_context": "Nation-state actors targeted critical infrastructure in Europe.",
        "llm_output": "APT-Nebula-X, a state-sponsored group from the Republic of Cybernia, used HyperWorm malware to infiltrate power grid SCADA systems.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 1,
        "rationale": "APT-Nebula-X, Republic of Cybernia, HyperWorm are all fabricated",
    },
    {
        "id": "HC-C04",
        "category": "C_fabricated_actor",
        "input_context": "Supply chain attacks are an increasing threat vector in 2024.",
        "llm_output": "The Crimson Viper syndicate compromised 12 major npm packages, inserting cryptominers that affected 50 million developers worldwide using their MegaPoison framework.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 1,
        "rationale": "Crimson Viper and MegaPoison are fabricated",
    },
    {
        "id": "HC-C05",
        "category": "C_fabricated_actor",
        "input_context": "Cloud infrastructure misconfigurations lead to data breaches.",
        "llm_output": "Operation Dark Horizon by UNC9999 targeted AWS S3 buckets using their proprietary CloudDrainer toolkit to exfiltrate 500TB of classified data.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 1,
        "rationale": "Operation Dark Horizon, UNC9999, CloudDrainer fabricated",
    },
    {
        "id": "HC-C06",
        "category": "C_fabricated_actor",
        "input_context": "Threat actors target telecommunications companies for call data records.",
        "llm_output": "The Ghost Protocol Unit deployed their TelcoSiphon implant across 30 telecom providers, intercepting 10 billion call records for signals intelligence.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 1,
        "rationale": "Ghost Protocol Unit, TelcoSiphon fabricated",
    },
    {
        "id": "HC-C07",
        "category": "C_fabricated_actor",
        "input_context": "Cryptocurrency exchanges are targeted by sophisticated threat actors.",
        "llm_output": "The Midnight Dragon APT stole $2 billion from cryptocurrency exchanges using their CryptoPhantom zero-day exploit chain targeting cold wallet firmware.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 1,
        "rationale": "Midnight Dragon, CryptoPhantom fabricated",
    },
    {
        "id": "HC-C08",
        "category": "C_fabricated_actor",
        "input_context": "Industrial control systems face growing cyber threats.",
        "llm_output": "FIN99 deployed the StuxNet-X worm through watering hole attacks targeting PLC firmware in nuclear facilities across 15 countries.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 1,
        "rationale": "FIN99 and StuxNet-X are fabricated",
    },
    {
        "id": "HC-C09",
        "category": "C_fabricated_actor",
        "input_context": "DDoS attacks on government websites are becoming more frequent.",
        "llm_output": "The Cyber Caliphate 2.0 group launched 500 Tbps DDoS attacks using their QuantumFlood botnet composed of 100 million compromised IoT devices.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 1,
        "rationale": "Cyber Caliphate 2.0, QuantumFlood fabricated; 500 Tbps impossible",
    },
    {
        "id": "HC-C10",
        "category": "C_fabricated_actor",
        "input_context": "Satellite communication systems are potential targets for advanced threats.",
        "llm_output": "Operation Starfall conducted by APT-Cosmos used orbital signal injection to compromise LEO satellite constellations, enabling global surveillance capabilities.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 1,
        "rationale": "APT-Cosmos, orbital signal injection fabricated",
    },

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY D — Correct outputs / true negatives (10 cases)
    # Expected: PASS all tiers
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "HC-D01",
        "category": "D_correct",
        "input_context": "APT28 used spearphishing emails with malicious attachments to target government organizations. The group leveraged Cobalt Strike beacons for command and control.",
        "llm_output": "APT28 used spearphishing emails with malicious attachments targeting government organizations. They deployed Cobalt Strike beacons for command and control communications.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Output directly paraphrases the context",
    },
    {
        "id": "HC-D02",
        "category": "D_correct",
        "input_context": "LockBit ransomware affiliates exploit public-facing applications and use RDP for lateral movement before encrypting files and demanding ransom payment.",
        "llm_output": "LockBit affiliates gain initial access by exploiting public-facing applications. They use RDP for lateral movement and encrypt files before demanding ransom.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Faithful paraphrase of the context",
    },
    {
        "id": "HC-D03",
        "category": "D_correct",
        "input_context": "The phishing email contained a malicious Excel attachment with embedded macros. When opened, it downloads a second-stage payload from a C2 server.",
        "llm_output": "This phishing attack uses a malicious Excel document with embedded macros that download a second-stage payload from the command and control server.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Accurate summary of the phishing attack chain",
    },
    {
        "id": "HC-D04",
        "category": "D_correct",
        "input_context": "Volt Typhoon targets US critical infrastructure using living-off-the-land techniques. They use LOLBins like certutil and PowerShell for persistence and lateral movement.",
        "llm_output": "Volt Typhoon targets US critical infrastructure. The group uses living-off-the-land techniques including certutil and PowerShell for persistence.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Grounded in the provided context about Volt Typhoon",
    },
    {
        "id": "HC-D05",
        "category": "D_correct",
        "input_context": "The threat actor exploited CVE-2024-3400 in Palo Alto Networks PAN-OS GlobalProtect to gain unauthenticated remote code execution on the firewall.",
        "llm_output": "CVE-2024-3400 is a critical vulnerability in Palo Alto PAN-OS GlobalProtect enabling unauthenticated remote code execution.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "CVE-2024-3400 is real and output matches context",
    },
    {
        "id": "HC-D06",
        "category": "D_correct",
        "input_context": "Scattered Spider uses SIM swapping and social engineering against helpdesk staff to gain initial access. They install remote monitoring tools like AnyDesk.",
        "llm_output": "Scattered Spider gains initial access through SIM swapping and social engineering of helpdesk staff. They install AnyDesk for persistent remote access.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Faithful summary of Scattered Spider TTPs",
    },
    {
        "id": "HC-D07",
        "category": "D_correct",
        "input_context": "The attacker used Mimikatz to dump credentials from LSASS memory. They then used pass-the-hash to move laterally through the Active Directory domain.",
        "llm_output": "Credential dumping was performed using Mimikatz targeting LSASS memory. Lateral movement was achieved through pass-the-hash attacks in the AD domain.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Accurate description of credential access and lateral movement",
    },
    {
        "id": "HC-D08",
        "category": "D_correct",
        "input_context": "Black Basta ransomware uses QakBot for initial access, Cobalt Strike for C2, and rclone to exfiltrate data to MEGA cloud storage before encryption.",
        "llm_output": "Black Basta uses QakBot for initial access and Cobalt Strike for C2. Data is exfiltrated using rclone to MEGA before ransomware encryption.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Correct Black Basta attack chain summary",
    },
    {
        "id": "HC-D09",
        "category": "D_correct",
        "input_context": "The vulnerability allows remote code execution. The CVSS score is 9.8 critical. Patches are available and should be applied immediately.",
        "llm_output": "This is a critical remote code execution vulnerability with a CVSS score of 9.8. Organizations should apply available patches immediately.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Accurate paraphrase of vulnerability advisory",
    },
    {
        "id": "HC-D10",
        "category": "D_correct",
        "input_context": "The SolarWinds supply chain compromise involved the SUNBURST backdoor inserted into Orion software updates affecting 18,000 organizations.",
        "llm_output": "The SUNBURST backdoor was inserted into SolarWinds Orion software updates as a supply chain compromise, affecting approximately 18,000 organizations.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Accurate summary of the SolarWinds incident",
    },

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY E — Partially grounded / edge cases (10 cases)
    # For threshold tuning via ROC analysis
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "HC-E01",
        "category": "E_edge_case",
        "input_context": "APT28 conducted phishing campaigns against government organizations.",
        "llm_output": "APT28 conducted spearphishing campaigns against government organizations. They likely used T1566.001 Spearphishing Attachment, a common technique for this group.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "T1566.001 is a real valid technique, inference is reasonable",
    },
    {
        "id": "HC-E02",
        "category": "E_edge_case",
        "input_context": "The ransomware encrypted all files on the network and deleted volume shadow copies.",
        "llm_output": "The ransomware encrypted files using AES-256 encryption and deleted volume shadow copies to prevent recovery. The ransom note demanded Bitcoin payment.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "AES-256 is reasonable inference; Bitcoin demand is standard ransomware behavior",
    },
    {
        "id": "HC-E03",
        "category": "E_edge_case",
        "input_context": "Credential theft was detected in the compromised Active Directory domain.",
        "llm_output": "The attackers performed credential theft in the Active Directory domain, likely using tools such as Mimikatz or secretsdump to extract NTLM hashes.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Tools mentioned are reasonable inferences but not in the source context",
    },
    {
        "id": "HC-E04",
        "category": "E_edge_case",
        "input_context": "A Chinese threat actor targeted telecommunications companies in Southeast Asia for espionage purposes.",
        "llm_output": "A Chinese state-sponsored APT group conducted cyber espionage against telecommunications companies in Southeast Asia to collect call detail records and SMS messages for intelligence purposes.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Reasonable elaboration; 'call detail records' is a plausible target",
    },
    {
        "id": "HC-E05",
        "category": "E_edge_case",
        "input_context": "The attacker exploited a web application vulnerability for initial access.",
        "llm_output": "The attacker exploited a SQL injection vulnerability in the web application to gain initial access. They then pivoted to the internal database server and exfiltrated customer records.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 2,
        "rationale": "SQL injection and internal pivot are speculative — not in context",
    },
    {
        "id": "HC-E06",
        "category": "E_edge_case",
        "input_context": "The malware uses HTTP for command and control communications.",
        "llm_output": "The malware establishes HTTP-based C2 communications. It uses domain generation algorithms (DGA) to generate 500 unique domains per day and connects to fast-flux infrastructure across 30 countries.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 2,
        "rationale": "DGA, 500 domains, and 30 countries are fabricated specifics not in context",
    },
    {
        "id": "HC-E07",
        "category": "E_edge_case",
        "input_context": "Lazarus Group used cryptocurrency theft to fund North Korean state programs.",
        "llm_output": "Lazarus Group stole cryptocurrency to fund North Korean programs. They specifically targeted the Axie Infinity Ronin Bridge, stealing $620 million in Ethereum through compromised private keys.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "The Ronin Bridge hack is well-documented public knowledge attributed to Lazarus",
    },
    {
        "id": "HC-E08",
        "category": "E_edge_case",
        "input_context": "A vulnerability in the VPN appliance was exploited for initial access.",
        "llm_output": "The threat actor exploited a critical vulnerability in the VPN appliance to gain initial access to the corporate network. Once inside, they deployed webshells, established persistence, and moved laterally through the domain using stolen credentials before deploying ransomware across 2,000 endpoints within 72 hours.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 2,
        "rationale": "Massive hallucinated specifics: webshells, 2000 endpoints, 72 hours",
    },
    {
        "id": "HC-E09",
        "category": "E_edge_case",
        "input_context": "The threat report describes a watering hole attack targeting defense contractors.",
        "llm_output": "A watering hole attack targeted defense contractors by compromising industry websites visited by defense sector employees.",
        "ground_truth_label": "PASS",
        "expected_tier_failure": None,
        "rationale": "Minimal but accurate paraphrase",
    },
    {
        "id": "HC-E10",
        "category": "E_edge_case",
        "input_context": "The threat actor gained persistence on the compromised system.",
        "llm_output": "The threat actor established persistence using a scheduled task that executes a PowerShell script every 30 minutes to beacon to the C2 infrastructure at evil-domain.xyz over HTTPS port 443.",
        "ground_truth_label": "FAIL",
        "expected_tier_failure": 2,
        "rationale": "Scheduled task, PowerShell, 30 min interval, evil-domain.xyz all hallucinated",
    },
]

# Sanity check
assert len(GUARD_EVAL_CASES) == 50, f"Expected 50 cases, got {len(GUARD_EVAL_CASES)}"

# Category counts
_cats = {}
for c in GUARD_EVAL_CASES:
    _cats.setdefault(c["category"], 0)
    _cats[c["category"]] += 1
for cat, count in sorted(_cats.items()):
    assert count == 10, f"Category {cat} has {count} cases, expected 10"
