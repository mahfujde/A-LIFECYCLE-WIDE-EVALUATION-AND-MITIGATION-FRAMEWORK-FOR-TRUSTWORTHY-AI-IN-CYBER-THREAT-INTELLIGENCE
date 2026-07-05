# CTI-Shield Expert Evaluation — Evaluator Handout

Date: 2026-04-29
Evaluator ID: __________ (e.g., E1, E2, E3)

## Instructions
1. Read each CTI analysis output carefully
2. Score each on the 5 questions using 1-5 scale:
   1=Strongly Disagree, 2=Disagree, 3=Neutral, 4=Agree, 5=Strongly Agree
3. Do NOT try to guess which system produced each output
4. Base your judgement on your professional CTI expertise

## Scoring Dimensions
- **Q1_usability**: "I would include this analysis in an incident report"
- **Q2_accuracy**: "The claims appear factually accurate"
- **Q3_verifiability**: "I can verify where this information comes from"
- **Q4_hallucination**: "This output contains no fabricated details"
- **Q5_operational**: "Overall quality is sufficient for operational use"

---

## Sample: REAL-001_A
**Advisory:** CISA Advisory AA22-110A (Russian State-Sponsored Cyber Threats)

**Input (excerpt):**
> Russian state-sponsored cyber actors have targeted U.S. cleared defense contractors since at least January 2020. The actors have targeted both large and small CDCs and subcontractors with varying levels of cybersecurity protocols and resources. These actors leverage spearphishing emails with malicio...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--ab2d0757-28d7-4680-a669-a235632c1908', 'created': '2026-04-28T20:55:02.733462+00:00', 'modified': '2026-04-28T20:55:02.733462+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 50.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → 
[2] The attack uses malicious Excel documents with embedded macros that download a s → https://attack.mitre.org/techniques/T1587/001
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-001_B
**Advisory:** CISA Advisory AA22-110A (Russian State-Sponsored Cyber Threats)

**Input (excerpt):**
> Russian state-sponsored cyber actors have targeted U.S. cleared defense contractors since at least January 2020. The actors have targeted both large and small CDCs and subcontractors with varying levels of cybersecurity protocols and resources. These actors leverage spearphishing emails with malicio...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--ebb9538c-6c26-42ae-af60-5734882c4eef', 'created': '2026-04-28T20:55:34.733278+00:00', 'modified': '2026-04-28T20:55:34.733278+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 100.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → https://attack.mitre.org/techniques/T1597/001
[2] The attack uses malicious Excel documents with embedded macros that download a s → https://attack.mitre.org/techniques/T1681
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-001_C
**Advisory:** CISA Advisory AA22-110A (Russian State-Sponsored Cyber Threats)

**Input (excerpt):**
> Russian state-sponsored cyber actors have targeted U.S. cleared defense contractors since at least January 2020. The actors have targeted both large and small CDCs and subcontractors with varying levels of cybersecurity protocols and resources. These actors leverage spearphishing emails with malicio...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--cf10dca2-17c5-48f2-9cb7-f97ebe42a182', 'created': '2026-04-28T20:55:49.480475+00:00', 'modified': '2026-04-28T20:55:49.480475+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 50.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → 
[2] The attack uses malicious Excel documents with embedded macros that download a s → https://attack.mitre.org/techniques/T1587/001
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-002_A
**Advisory:** CISA Advisory AA23-136A (LockBit 3.0 Ransomware)

**Input (excerpt):**
> LockBit 3.0 ransomware operations function as a Ransomware-as-a-Service model. LockBit affiliates have been observed exploiting CVE-2023-0669 and CVE-2023-27350 for initial access. After gaining access, affiliates use Remote Desktop Protocol for lateral movement and deploy Cobalt Strike beacons. The...

**Analysis Output:**
```
{'analysis': {'summary': '🔴 This appears to be related to a RANSOMWARE attack. Ransomware encrypts your files and demands payment (often in Bitcoin) for the decryption key. Do NOT pay the ransom — there is no guarantee your files will be recovered. Contact law enforcement immediately.', 'threat_type': 'Ransomware', 'ttps': [{'id': 'T1486', 'name': 'Data Encrypted for Impact', 'tactic': 'Impact'}, {'id': 'T1490', 'name': 'Inhibit System Recovery', 'tactic': 'Impact'}, {'id': 'T1059.001', 'name': 'PowerShell', 'tactic': 'Execution'}], 'severity': 'Emergency', 'red_flags': ['Files have been encrypted or renamed', 'Ransom note demanding cryptocurrency payment', 'Threat of data publication or deletion']}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--ca288261-05a4-4856-89b0-2ba57e8b8c5c', 'created': '2026-04-28T20:56:16.763867+00:00', 'modified': '2026-04-28T20:56:16.763867+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo threat actor', 'threat_actor_types': ['crime-syndicate']}, {'type': 'malware', 'spec_version': '2.1', 'id': 'malware--9350a321-c72e-4556-af69-cc3aba922f00', 'created': '2026-04-28T20:56:16.763867+00:00', 'modified': '2026-04-28T20:56:16.763867+00:00', 'name': 'DemoRAT', 'description': 'Demo remote access trojan', 'malware_types': ['remote-access-trojan'], 'is_family': True}, {'type': 'attack-pattern', 'spec_version': '2.1', 'id': 'attack-pattern--e2954f6e-82be-434c-8f4d-f7fe75583759', 'created': '2026-04-28T20:56:16.7638
```

**Source Citations:**
```
Attribution rate: 75.0%
[1] {'summary': '🔴 This appears to be related to a RANSOMWARE attack. → https://attack.mitre.org/techniques/T1608/001
[2] Ransomware encrypts your files and demands payment (often in Bitcoin) for the de → https://attack.mitre.org/techniques/T1588/001
[3] Do NOT pay the ransom — there is no guarantee your files will be recovered. → 
[4] Contact law enforcement immediately.', 'threat_type': 'Ransomware', 'ttps': [{'i → https://attack.mitre.org/techniques/T1681
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-002_B
**Advisory:** CISA Advisory AA23-136A (LockBit 3.0 Ransomware)

**Input (excerpt):**
> LockBit 3.0 ransomware operations function as a Ransomware-as-a-Service model. LockBit affiliates have been observed exploiting CVE-2023-0669 and CVE-2023-27350 for initial access. After gaining access, affiliates use Remote Desktop Protocol for lateral movement and deploy Cobalt Strike beacons. The...

**Analysis Output:**
```
{'analysis': {'summary': '🔴 This appears to be related to a RANSOMWARE attack. Ransomware encrypts your files and demands payment (often in Bitcoin) for the decryption key. Do NOT pay the ransom — there is no guarantee your files will be recovered. Contact law enforcement immediately.', 'threat_type': 'Ransomware', 'ttps': [{'id': 'T1486', 'name': 'Data Encrypted for Impact', 'tactic': 'Impact'}, {'id': 'T1490', 'name': 'Inhibit System Recovery', 'tactic': 'Impact'}, {'id': 'T1059.001', 'name': 'PowerShell', 'tactic': 'Execution'}], 'severity': 'Emergency', 'red_flags': ['Files have been encrypted or renamed', 'Ransom note demanding cryptocurrency payment', 'Threat of data publication or deletion']}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--ef5dfd4f-6e1a-4628-af24-c444105d189a', 'created': '2026-04-28T20:56:43.861924+00:00', 'modified': '2026-04-28T20:56:43.861924+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo threat actor', 'threat_actor_types': ['crime-syndicate']}, {'type': 'malware', 'spec_version': '2.1', 'id': 'malware--690ccb76-750a-428b-bce7-40377bf13498', 'created': '2026-04-28T20:56:43.861924+00:00', 'modified': '2026-04-28T20:56:43.861924+00:00', 'name': 'DemoRAT', 'description': 'Demo remote access trojan', 'malware_types': ['remote-access-trojan'], 'is_family': True}, {'type': 'attack-pattern', 'spec_version': '2.1', 'id': 'attack-pattern--9b269e97-ec97-493e-bf5f-64fb7e8adc90', 'created': '2026-04-28T20:56:43.8619
```

**Source Citations:**
```
Attribution rate: 0.0%
[1] {'summary': '🔴 This appears to be related to a RANSOMWARE attack. → 
[2] Ransomware encrypts your files and demands payment (often in Bitcoin) for the de → 
[3] Do NOT pay the ransom — there is no guarantee your files will be recovered. → 
[4] Contact law enforcement immediately.', 'threat_type': 'Ransomware', 'ttps': [{'i → 
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-002_C
**Advisory:** CISA Advisory AA23-136A (LockBit 3.0 Ransomware)

**Input (excerpt):**
> LockBit 3.0 ransomware operations function as a Ransomware-as-a-Service model. LockBit affiliates have been observed exploiting CVE-2023-0669 and CVE-2023-27350 for initial access. After gaining access, affiliates use Remote Desktop Protocol for lateral movement and deploy Cobalt Strike beacons. The...

**Analysis Output:**
```
{'analysis': {'summary': '🔴 This appears to be related to a RANSOMWARE attack. Ransomware encrypts your files and demands payment (often in Bitcoin) for the decryption key. Do NOT pay the ransom — there is no guarantee your files will be recovered. Contact law enforcement immediately.', 'threat_type': 'Ransomware', 'ttps': [{'id': 'T1486', 'name': 'Data Encrypted for Impact', 'tactic': 'Impact'}, {'id': 'T1490', 'name': 'Inhibit System Recovery', 'tactic': 'Impact'}, {'id': 'T1059.001', 'name': 'PowerShell', 'tactic': 'Execution'}], 'severity': 'Emergency', 'red_flags': ['Files have been encrypted or renamed', 'Ransom note demanding cryptocurrency payment', 'Threat of data publication or deletion']}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--d76d37f3-01b7-4cff-a36d-adc48f83662d', 'created': '2026-04-28T20:58:37.391156+00:00', 'modified': '2026-04-28T20:58:37.391156+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo threat actor', 'threat_actor_types': ['crime-syndicate']}, {'type': 'malware', 'spec_version': '2.1', 'id': 'malware--d5dba758-2ec1-4036-9aaf-fe8e59ff5423', 'created': '2026-04-28T20:58:37.391156+00:00', 'modified': '2026-04-28T20:58:37.391156+00:00', 'name': 'DemoRAT', 'description': 'Demo remote access trojan', 'malware_types': ['remote-access-trojan'], 'is_family': True}, {'type': 'attack-pattern', 'spec_version': '2.1', 'id': 'attack-pattern--fea3743a-35fb-4b25-ba15-5e873899c899', 'created': '2026-04-28T20:58:37.3911
```

**Source Citations:**
```
Attribution rate: 25.0%
[1] {'summary': '🔴 This appears to be related to a RANSOMWARE attack. → 
[2] Ransomware encrypts your files and demands payment (often in Bitcoin) for the de → ATT&CK:T1003
[3] Do NOT pay the ransom — there is no guarantee your files will be recovered. → 
[4] Contact law enforcement immediately.', 'threat_type': 'Ransomware', 'ttps': [{'i → 
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-003_A
**Advisory:** CISA Advisory AA24-060A (Volt Typhoon / PRC State-Sponsored)

**Input (excerpt):**
> People's Republic of China state-sponsored cyber actors known as Volt Typhoon are pre-positioning themselves on IT networks to enable lateral movement to OT assets. Volt Typhoon actors exploit vulnerabilities in public-facing appliances including Fortinet FortiGuard devices using CVE-2023-27997. The...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--26aa8927-44e1-4d3d-ac74-ebd91d418eed', 'created': '2026-04-28T20:58:50.040401+00:00', 'modified': '2026-04-28T20:58:50.040401+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 100.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → https://attack.mitre.org/techniques/T1597/001
[2] The attack uses malicious Excel documents with embedded macros that download a s → https://attack.mitre.org/techniques/T1681
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-003_B
**Advisory:** CISA Advisory AA24-060A (Volt Typhoon / PRC State-Sponsored)

**Input (excerpt):**
> People's Republic of China state-sponsored cyber actors known as Volt Typhoon are pre-positioning themselves on IT networks to enable lateral movement to OT assets. Volt Typhoon actors exploit vulnerabilities in public-facing appliances including Fortinet FortiGuard devices using CVE-2023-27997. The...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--e224b238-8601-4fb4-b38a-8287fab86837', 'created': '2026-04-28T20:59:04.283848+00:00', 'modified': '2026-04-28T20:59:04.283848+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 100.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → https://attack.mitre.org/techniques/T1587/004
[2] The attack uses malicious Excel documents with embedded macros that download a s → https://attack.mitre.org/techniques/T1587/004
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-003_C
**Advisory:** CISA Advisory AA24-060A (Volt Typhoon / PRC State-Sponsored)

**Input (excerpt):**
> People's Republic of China state-sponsored cyber actors known as Volt Typhoon are pre-positioning themselves on IT networks to enable lateral movement to OT assets. Volt Typhoon actors exploit vulnerabilities in public-facing appliances including Fortinet FortiGuard devices using CVE-2023-27997. The...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--590c516c-0b9d-4dc0-aa58-f56f54b7d87a', 'created': '2026-04-28T20:59:34.738558+00:00', 'modified': '2026-04-28T20:59:34.738558+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 50.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → 
[2] The attack uses malicious Excel documents with embedded macros that download a s → ATT&CK:T1190
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-005_A
**Advisory:** MITRE ATT&CK Group G0007 (APT28/Fancy Bear)

**Input (excerpt):**
> APT28 is a threat group attributed to Russia's General Staff Main Intelligence Directorate (GRU). APT28 has been observed using spearphishing with malicious Microsoft Office documents exploiting CVE-2017-0199 and CVE-2015-1641. The group uses X-Agent and Zebrocy malware for persistent access. They e...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--473fb858-2836-4fe7-ae09-47bc0799995c', 'created': '2026-04-28T20:59:50.897297+00:00', 'modified': '2026-04-28T20:59:50.897297+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 50.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → 
[2] The attack uses malicious Excel documents with embedded macros that download a s → https://attack.mitre.org/techniques/T1587/001
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-005_B
**Advisory:** MITRE ATT&CK Group G0007 (APT28/Fancy Bear)

**Input (excerpt):**
> APT28 is a threat group attributed to Russia's General Staff Main Intelligence Directorate (GRU). APT28 has been observed using spearphishing with malicious Microsoft Office documents exploiting CVE-2017-0199 and CVE-2015-1641. The group uses X-Agent and Zebrocy malware for persistent access. They e...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--2240954a-bb45-42b0-ba21-e270612a59d8', 'created': '2026-04-28T21:00:47.181483+00:00', 'modified': '2026-04-28T21:00:47.181483+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 100.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → ATT&CK:T1566.001
[2] The attack uses malicious Excel documents with embedded macros that download a s → ATT&CK:T1566.001
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-005_C
**Advisory:** MITRE ATT&CK Group G0007 (APT28/Fancy Bear)

**Input (excerpt):**
> APT28 is a threat group attributed to Russia's General Staff Main Intelligence Directorate (GRU). APT28 has been observed using spearphishing with malicious Microsoft Office documents exploiting CVE-2017-0199 and CVE-2015-1641. The group uses X-Agent and Zebrocy malware for persistent access. They e...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--b6801ba1-4833-43d2-92a6-8e7ed4247e55', 'created': '2026-04-28T21:01:00.716948+00:00', 'modified': '2026-04-28T21:01:00.716948+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 100.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → https://attack.mitre.org/techniques/T1597/001
[2] The attack uses malicious Excel documents with embedded macros that download a s → https://attack.mitre.org/techniques/T1681
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-009_A
**Advisory:** NCSC Advisory (SolarWinds/SUNBURST)

**Input (excerpt):**
> The SolarWinds supply chain compromise affected approximately 18,000 organizations worldwide including US government agencies. The threat actor UNC2452 (later attributed to Russia's SVR) inserted malicious code called SUNBURST into SolarWinds Orion software updates. The backdoor communicated via HTT...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--1edf5e32-ddd6-4664-93f0-99c0823be3e4', 'created': '2026-04-28T21:01:15.987897+00:00', 'modified': '2026-04-28T21:01:15.987897+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 50.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → 
[2] The attack uses malicious Excel documents with embedded macros that download a s → https://attack.mitre.org/techniques/T1211
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-009_B
**Advisory:** NCSC Advisory (SolarWinds/SUNBURST)

**Input (excerpt):**
> The SolarWinds supply chain compromise affected approximately 18,000 organizations worldwide including US government agencies. The threat actor UNC2452 (later attributed to Russia's SVR) inserted malicious code called SUNBURST into SolarWinds Orion software updates. The backdoor communicated via HTT...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--e9c98447-a37a-479b-b10f-cb61eba76d2f', 'created': '2026-04-28T21:01:41.084292+00:00', 'modified': '2026-04-28T21:01:41.084292+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 0.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → 
[2] The attack uses malicious Excel documents with embedded macros that download a s → 
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---

## Sample: REAL-009_C
**Advisory:** NCSC Advisory (SolarWinds/SUNBURST)

**Input (excerpt):**
> The SolarWinds supply chain compromise affected approximately 18,000 organizations worldwide including US government agencies. The threat actor UNC2452 (later attributed to Russia's SVR) inserted malicious code called SUNBURST into SolarWinds Orion software updates. The backdoor communicated via HTT...

**Analysis Output:**
```
{'analysis': {'summary': 'This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.', 'threat_actor': {'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--764fe76a-03b4-40a4-8a88-ccfeb073bb18', 'created': '2026-04-28T20:54:15.427038+00:00', 'modified': '2026-04-28T20:54:15.427412+00:00', 'name': 'APT-DEMO-01', 'description': 'A sophisticated threat actor targeting financial institutions via spear-phishing.', 'threat_actor_types': ['crime-syndicate'], 'sophistication': 'advanced', 'resource_level': 'organization', 'primary_motivation': 'financial-gain'}, 'ttps': [{'id': 'T1566.001', 'name': 'Spear-phishing Attachment', 'tactic': 'Initial Access'}, {'id': 'T1059.003', 'name': 'Windows Command Shell', 'tactic': 'Execution'}, {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'}, {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}], 'severity': 'Serious Threat', 'iocs': {'domains': ['evil-c2.example.com'], 'ips': ['198.51.100.42'], 'hashes': ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4']}}, 'stix_objects': [{'type': 'threat-actor', 'spec_version': '2.1', 'id': 'threat-actor--d8005a44-a9a8-41b6-a16c-49644eea0a69', 'created': '2026-04-28T21:01:50.768241+00:00', 'modified': '2026-04-28T21:01:50.768241+00:00', 'name': 'APT-DEMO-01', 'description': 'Demo th
```

**Source Citations:**
```
Attribution rate: 100.0%
[1] {'summary': 'This threat report describes a sophisticated spear-phishing campaig → https://attack.mitre.org/techniques/T1597/001
[2] The attack uses malicious Excel documents with embedded macros that download a s → https://attack.mitre.org/techniques/T1681
```

### Scores
| Question | Score (1-5) |
|----------|-------------|
| Q1_usability | _____ |
| Q2_accuracy | _____ |
| Q3_verifiability | _____ |
| Q4_hallucination | _____ |
| Q5_operational | _____ |

---
