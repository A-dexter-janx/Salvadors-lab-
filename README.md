# Cybersecurity Portfolio - Salvador Janthan
## Security+ Candidate | SOC Analyst | Threat Hunter

A hands-on cybersecurity portfolio demonstrating practical skills across SIEM deployment, network security, vulnerability management, threat hunting, incident response, and security automation.

---

### 📋 About Me

Cybersecurity student and practitioner focused on defensive security, SOC operations, and threat hunting. I build practical skills through hands-on labs — deploying SIEM tools, designing network security controls, running vulnerability scans, writing detection rules, and automating security tasks with Python. Currently working toward CompTIA Security+ certification.

### 🔧 Technical Skills

| Category | Tools & Technologies |
|----------|---------------------|
| **SIEM** | Splunk Free, Elastic Stack (ELK), Microsoft Sentinel |
| **Network Security** | pfSense firewall, Wireshark, VLAN segmentation, ACL design |
| **OS Hardening** | Windows & Linux, group policy, log analysis, Sysmon, audit policies |
| **Vulnerability Management** | Nessus Essentials, OpenVAS, Nmap, CVSS triage, remediation planning |
| **Threat Hunting** | Sigma rules, YARA signatures, MITRE ATT&CK mapping, IOC extraction |
| **Scripting** | Python, Bash, PowerShell |
| **Incident Response** | NIST SP 800-61 lifecycle, forensic timeline reconstruction, malware triage |

---

### 🚀 Featured Projects

#### 1. SIEM Home Lab
Built a home-lab SIEM stack using Splunk Free and the Elastic Stack (ELK). Ingesting Windows Event Logs via Winlogbeat, DNS query logs, and firewall logs. Developed custom detection alerts including brute-force SSH/RDP detection and malware C2 domain pattern matching. Created Kibana dashboards for real-time monitoring and visibility.

| Deliverable | File |
|-------------|------|
| Brute-force detection SPL | `02-SIEM-Projects/splunk-alert-config/brute-force-detection.spl` |
| Malware C2 alert SPL | `02-SIEM-Projects/splunk-alert-config/malware-c2-alert.spl` |
| Winlogbeat forwarder config | `02-SIEM-Projects/elastic-stack/winlogbeat-config.yml` |
| Kibana index dashboard export | `02-SIEM-Projects/elastic-stack/kibana-dashboard-export.json` |

#### 2. Network Security Lab
Configured a pfSense edge firewall with custom ACLs across WAN, LAN, and DMZ interfaces. Documented the full rule set with rationale for each entry. Captured and analyzed live traffic with Wireshark to validate rule behavior and identify protocol patterns. Mapped the lab network topology showing segmentation between zones.

| Deliverable | File |
|-------------|------|
| pfSense rule documentation | `01-Network-Security/firewall-rules-pfsense.md` |
| Wireshark capture analysis | `01-Network-Security/wireshark-capture-analysis.pcapng` |
| Network topology diagram | `01-Network-Security/network-diagram.png` |

#### 3. Vulnerability Management
Ran credentialed Nessus scans against lab targets and triaged findings by CVSS severity. Identified high-priority issues including SMBv1 enabled (EternalBlue exposure), weak TLS cipher suites, and missing Windows patches. Produced a prioritized remediation plan with specific actions for each finding. Built a comprehensive Nmap scanning script for repeatable network assessment.

| Deliverable | File |
|-------------|------|
| Nessus findings & analysis | `04-Vulnerability-Management/nessus-report-analysis.md` |
| Remediation action plan | `04-Vulnerability-Management/remediation-recommendations.docx` |
| Comprehensive Nmap scan script | `04-Vulnerability-Management/nmap-scan-scripts/comprehensive-scan.sh` |

#### 4. Python Security Tools
Three functional security automation scripts: a multi-threaded TCP port scanner with common-port service mapping, a log analyzer that detects failed logins, sudo usage, HTTP 5xx errors, and suspicious patterns, and a file hash checker supporting MD5/SHA1/SHA256/SHA512 with known-hash verification.

| Deliverable | File | Description |
|-------------|------|-------------|
| Port scanner | `06-Python-Tools/port-scanner.py` | Threaded TCP connect scan, range or comma-list ports |
| Log analyzer | `06-Python-Tools/log-analyzer.py` | Failed logins, sudo, HTTP errors, suspicious patterns |
| Hash checker | `06-Python-Tools/hash-checker.py` | Multi-algorithm hashing, known-hash verification |

#### 5. Threat Hunting
Authored Sigma detection rules for suspicious PowerShell encoded command execution and lateral movement via PsExec/WMI, mapped to MITRE ATT&CK techniques T1059.001 and T1021. Created a YARA rule for generic malware indicators targeting common malicious API calls, obfuscation strings, and destructive commands.

| Deliverable | File | ATT&CK Mapping |
|-------------|------|---------------|
| PowerShell encoded command rule | `03-Threat-Hunting/sigma-rules/suspicious-powershell.yml` | T1059.001 |
| Lateral movement detection rule | `03-Threat-Hunting/sigma-rules/lateral-movement-detection.yml` | T1021 / T1047 |
| Generic malware signature | `03-Threat-Hunting/yara-rules/malware-signature.yar` | — |

#### 6. Incident Response
Developed a ransomware incident response playbook aligned to NIST SP 800-61 covering all six phases from preparation through lessons learned. Reconstructed a forensic timeline from Windows artifacts (event logs, registry, prefetch) demonstrating a suspected data exfiltration scenario. Wrote a malware analysis report covering static analysis (strings, imports, PE sections) and dynamic sandbox behavior with full IOC extraction.

| Deliverable | File |
|-------------|------|
| Ransomware IR playbook (NIST-aligned) | `05-Incident-Response/sample-ir-playbook.md` |
| Forensic timeline reconstruction | `05-Incident-Response/forensic-timeline.csv` |
| Malware analysis report (static + dynamic) | `05-Incident-Response/malware-analysis-report.md` |

---

### 📜 Certifications

| Certification | Status |
|---------------|--------|
| CompTIA Security+ | Expected [Date] |
| TryHackMe — Pre-Security Path | Completed |
| TryHackMe — Complete Beginner Path | Completed |
| TryHackMe — SOC Level 1 | Completed |

Badge evidence: `Certs-Badges/TryHackMe-Badges.png`

---

### 📞 Contact

- **GitHub:** [@A-dexter-janx](https://github.com/A-dexter-janx)
- **Resume:** `resume-cybersecurity.pdf`

---

### Repository Structure

```
Security-Plus-Lab-Portfolio/
├── 01-Network-Security/
│   ├── firewall-rules-pfsense.md
│   ├── wireshark-capture-analysis.pcapng
│   └── network-diagram.png
├── 02-SIEM-Projects/
│   ├── README.md
│   ├── splunk-alert-config/
│   │   ├── brute-force-detection.spl
│   │   └── malware-c2-alert.spl
│   └── elastic-stack/
│       ├── winlogbeat-config.yml
│       └── kibana-dashboard-export.json
├── 03-Threat-Hunting/
│   ├── sigma-rules/
│   │   ├── suspicious-powershell.yml
│   │   └── lateral-movement-detection.yml
│   └── yara-rules/
│       └── malware-signature.yar
├── 04-Vulnerability-Management/
│   ├── nessus-report-analysis.md
│   ├── nmap-scan-scripts/
│   │   └── comprehensive-scan.sh
│   └── remediation-recommendations.docx
├── 05-Incident-Response/
│   ├── sample-ir-playbook.md
│   ├── forensic-timeline.csv
│   └── malware-analysis-report.md
├── 06-Python-Tools/
│   ├── port-scanner.py
│   ├── log-analyzer.py
│   └── hash-checker.py
├── Certs-Badges/
│   ├── Security-Plus-Certificate.pdf
│   └── TryHackMe-Badges.png
├── README.md
└── resume-cybersecurity.pdf
```

---

*Portfolio built incrementally. Replace placeholder files with your real lab results, screenshots, and certificates as you complete each project. Commit regularly to show activity and progression.*
