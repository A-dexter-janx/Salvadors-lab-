# Salvador Janthan — Cybersecurity Portfolio

> Defensive security practitioner. I build detection, hunt threats, harden systems, and automate response — then document the whole thing so it can be reviewed, reproduced, and improved.

![GitHub repositories](https://img.shields.io/badge/repos-29-blue)
![Portfolio scope](https://img.shields.io/badge/scope-SIEM--Network--VulnMgmt--IR--Detection-orange)
![MITRE ATT&CK](https://img.shields.io/badge/attack-mapped-green)

---

## What this portfolio demonstrates

This is not a collection of screenshot dumps. Each section below shows **how I think about a security problem**, the **detection or control I built**, the **evidence I collected**, and **what I would do next** if I had more time or a production environment.

| Domain | What you will see |
|--------|-------------------|
| SIEM & Detection Engineering | Brute-force and C2 alerts with tuning rationale, correlation logic, eviction tests, and ATT&CK mapping |
| Network Security | pfSense ACL design with threat-model rationale, Wireshark validation, and DMZ-to-LAN least-privilege justification |
| Vulnerability Management | Nessus findings analyzed to CVE level, prioritized by exploitability and asset criticality, with a working Nmap automation script |
| Threat Hunting | Sigma rules and YARA signatures with ATT&CK technique IDs, hunting hypotheses, false-positive analysis, and test procedures |
| Incident Response | A full NIST SP 800-61 playbook for ransomware, a forensic timeline reconstruction, and a malware analysis report with IOCs |
| Security Automation | Three working Python tools deployed against real log and network data |

---

## Who I am

I am a cybersecurity student and practitioner focused on the defensive side — SOC operations, detection engineering, network hardening, and incident response. I learn by building, breaking, and documenting. This portfolio is the record of that work.

**What I care about:**
- Detecting real attacks, not just writing alerts that fire on noise
- Building controls with a clear threat model, not copying defaults
- Documenting so a reviewer can follow the chain from problem → approach → evidence → decision

---

## At a glance

| metric | value |
|--------|-------|
|| MITRE ATT&CK techniques mapped | T1059.001, T1021, T1047, T1105, T1071.001, T1048, T1567, T1486, T1559.003, T1555.003, T1562.001, T1573, T1102.002, T1204.002, T1566.001, T1053.005, T1547.001, T1027, T1190, T1068, T1557, T1055, T1485, T1072 |
|| Sigma rules written | 7 (2 generic hunting + 5 Nancy/Amatera-specific for C2, MSBuild LOLBIN, scheduled task persistence, BAT stager, WPA.exe payload) |
|| YARA rules written | 1 (generic malware indicators with API-call and string coverage) |
|| Splunk detection alerts | 2 (brute force, C2 DNS) with tuning notes |
|| Live IOC scanner | 1 (Python — scheduled tasks, files, registry, event logs, hash scan, C2 indicators) |
|| Sigma rules tested against | Real Defender DetectionHistory records from 2026-08-25 incident |
| Python tools delivered | 3 (port scanner, log analyzer, hash checker — all functional) |
| NIST IR playbook phases covered | 6 of 6 (Preparation → Lessons Learned) |
| Firewall interfaces designed | 3 (WAN, LAN, DMZ) with default-deny posture |

---

## Featured work

### 1. SIEM Detection Engineering — Brute Force & C2 Detection

**Problem:** A home-lab SIEM ingesting Windows Event Logs and DNS needs to detect two common attacker behaviors: password guessing against remote access, and malware beaconing to suspicious domains.

**What I built:**
- A Splunk brute-force detection alert grouping failed auth attempts by source IP over a 5-minute window, with a documented threshold rationale and a tuned eviction test.
- A C2 DNS detection alert flagging high-risk TLDs and beaconing patterns, with enrichment guidance into threat-intel sources.
- ATT&CK mapping: T1110 (Brute Force), T1071.001 (Web Protocols — C2), T1567 (Exfiltration Over Web Service).

**Why it stands out:**
- Most portfolios show the SPL query. I also document **why the threshold is 10**, **how I would tune it**, **what a false positive looks like**, and **how to test the alert before trusting it**.
- The C2 alert includes a beaconing-detection angle (periodic queries from the same host) beyond simple TLD matching.

See: `02-SIEM-Projects/README.md`, `02-SIEM-Projects/splunk-alert-config/`

---

### 2. Network Security — pfSense ACL Design with Threat Modeling

**Problem:** Design firewall rules for a segmented lab with WAN, LAN, and DMZ, and justify every rule with a security rationale rather than copying a default config.

**What I built:**
- A default-deny posture on WAN and DMZ, with explicit allow rules only where justified.
- DMZ-to-LAN restricted to TCP/80 and TCP/443 only — a least-privilege constraint that would stop a compromised DMZ host from freely reaching internal systems.
- NAT documentation (port forward for inbound HTTPS, source NAT for outbound).
- Wireshark validation plan describing what each interface capture should show if the rules are correct.

ATT&CK mapping: T1190 (Exploit Public-Facing App), T1021 (Remote Services), T1048 (Exfiltration Over Alternative Protocol).

See: `01-Network-Security/firewall-rules-pfsense.md`, `01-Network-Security/network-diagram.png`

---

### 3. Vulnerability Management — Nessus Triage + Nmap Automation

**Problem:** Run a real vulnerability scan, analyze the findings beyond the scanner's severity label, and prioritize remediation by exploitability and asset risk — not just CVSS.

**What I built:**
- A Nessus analysis documenting high findings (SMBv1/EternalBlue, weak TLS, missing patches) with CVE references, exploitability assessment, and specific remediation commands with verification steps.
- A prioritization logic that distinguishes internet-facing risk from internal-only risk.
- A comprehensive Nmap automation script that runs host discovery, common-port scan, full TCP scan, service/version detection, vuln NSE scripts, OS detection, and web enumeration — in stages, with a summary report.

ATT&CK mapping: T1190 (Exploit Public-Facing App), T1068 (Exploitation for Privilege Escalation), T1557 (Adversary-in-the-Middle via weak TLS).

See: `04-Vulnerability-Management/nessus-report-analysis.md`, `04-Vulnerability-Management/nmap-scan-scripts/comprehensive-scan.sh`

---

### 4. Threat Hunting — Sigma Rules & YARA Signatures

**Problem:** Write portable detection rules that map to ATT&CK, and a YARA signature that catches generic malware traits without depending on a single IOC.

**What I built:**
- Two Sigma rules: suspicious PowerShell encoded command execution (T1059.001) and lateral movement via PsExec/WMI/RPC (T1021, T1047).
- A YARA rule targeting common malware API calls (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread) and suspicious command strings, designed to catch generic payload behavior rather than a single hash.
- For each rule: logsource, detection logic, false-positive analysis, and a test procedure.

What makes this stand out: I include the **hunting hypothesis** behind each rule — the behavior I expect to see if the technique is in use — and a note on what would reduce false positives in production.

See: `03-Threat-Hunting/sigma-rules/`, `03-Threat-Hunting/yara-rules/malware-signature.yar`

---

### 5. Incident Response — Ransomware Playbook, Forensic Timeline & Malware Analysis

**Problem:** Show the full IR lifecycle for a ransomware event and demonstrate how to reconstruct what happened from endpoint artifacts.

**What I built:**
- A six-phase ransomware IR playbook aligned to NIST SP 800-61, from preparation through lessons learned, with ownership, timing estimates, and evidence-preservation steps.
- A forensic timeline from Windows artifacts (Security log, USBSTOR, Shellbags, Sysmon, PowerShell script-block logging, firewall/NetFlow) reconstructing a suspected data exfiltration — with key investigative questions and artifact-to-source mapping.
- A malware analysis report combining static analysis (strings, imports, PE sections, hashes) and dynamic sandbox behavior (C2, process injection, persistence) with a full IOC list.

ATT&CK mapping: T1486 (Data Encrypted for Impact), T1071.001 (Web Protocols), T1059.001 (PowerShell), T1021 (Lateral Movement), T1547 (Boot or Logon Autostart Execution).

See: `05-Incident-Response/sample-ir-playbook.md`, `05-Incident-Response/forensic-timeline.csv`, `05-Incident-Response/malware-analysis-report.md`

---

### 6. Security Automation — Detection, Analysis & Integrity Tools

**Problem:** During labs, I needed repeatable tools for port scanning, log triage, and file integrity. Off-the-shelf GUIs are fine, but scripting them teaches how they work and lets me tailor them.

**What I built:**
- `port-scanner.py` — threaded TCP connect scanner with common-port service mapping, range and comma-list port specs, and tunable concurrency/timeout.
- `log-analyzer.py` — auth log triage detecting failed logins, successful logins, sudo usage, HTTP 5xx errors, and suspicious keyword patterns.
- `hash-checker.py` — multi-algorithm hashing (MD5, SHA1, SHA256, SHA512) with known-hash verification suitable for malware triage and integrity checks.

These are functional, tested tools — not stubs. Every one runs from the command line with documented arguments.

See: `06-Python-Tools/`

---

### 7. Incident Case Study — Nancy / Amatera Stealer (real compromise)

> **This is not a lab simulation. A real infostealer compromised this machine.**
>
> On 2026-08-23, a fake "SamFw FRP Tool v5.5.1 Setup" from `frptoolsdownload.com` delivered a multi-stage loader (RenPy/PavinLoader → Wacatac → MSBuild LOLBIN) that deployed the Amatera stealer in memory. The malware persisted via a hidden scheduled task (`\\UpdateService`, logon trigger), exfiltrated browser credentials, session tokens, and autofill data, and used **EtherHiding over Binance Smart Chain** for C2 — storing encrypted blobs on a BSC smart contract and retrieving them via JSON-RPC.

**What the investigation produced:**

- **Full delivery chain recovered** — down to the terminal payload URL (`d8baab0c37a0454d6f22ad4c.192169482.com/675ab055f00e5d1087ae481e21d24a`), decoded from the gate's base64 JSON. Unpublished infrastructure as of 2026-08-25.
- **Blockchain time-travel C2 proof** — BSC archive node reads at blocks 117684888, ~117784311, ~117976228 show **four distinct 54-byte encrypted blobs**, proving per-session C2 rotation. Block numbers preserved for future key recovery.
- **Real evidence with provenance** — Defender DetectionHistory records (5 files, raw binary), scheduled task XML export, SHA256 payload manifest (8 files), Firefox `places.sqlite` gate decode, chain-of-custody log.
- **Actual IR performed** — evidence collected, eradication executed (process kill, task deletion, payload shredded with 3-pass overwrite), credentials rotated.

**ATT&CK coverage:** T1566.001, T1204.002, T1562.001, T1027, T1059.003, T1559.003, T1053.005, T1547.001, T1555.003, T1567, T1071.001, T1102.002, T1573.002.

See: `07-Incident-Case-Study/README.md`, `07-Incident-Case-Study/nancy-amatera/`

---

## Approach and philosophy

A few things I try to do consistently across every project:

- **Threat-model first.** Before building a control or a detection, I ask what behavior I am trying to stop or catch, and from whom.
- **Default-deny where it matters.** Firewall posture, least privilege, and explicit allow rules are cheaper to justify than retroactively explaining why something was left open.
- **Tune before you trust.** An alert that fires on noise gets ignored. I document threshold rationale, false positives, and a test procedure so the detection can be improved.
- **Evidence over assertion.** Screenshots, log excerpts, hashes, CVEs, and ATT&CK IDs are there so a reviewer can check the work instead of taking my word for it.
- **Document for the next person.** Each project has a "Next Steps" section so someone else — or future me — knows what would come next.

---

## Repository map

```
Security-Plus-Lab-Portfolio/
├── 01-Network-Security/
│   ├── firewall-rules-pfsense.md         # pfSense ACL design + threat model
│   ├── wireshark-capture-analysis.pcapng # live capture: WAN/DMZ/LAN ACL validation, 23 packets, 12 scenarios
│   └── network-diagram.png               # segmented network topology
├── 02-SIEM-Projects/
│   ├── README.md                         # SIEM detection engineering overview
│   ├── splunk-alert-config/
│   │   ├── brute-force-detection.spl    # T1110 — SSH/RDP brute force
│   │   └── malware-c2-alert.spl         # T1071.001 / T1567 — C2 DNS
│   └── elastic-stack/
│       ├── winlogbeat-config.yml        # Windows log forwarder config
│       └── kibana-dashboard-export.json # DNS dashboard index template
├── 03-Threat-Hunting/
│   ├── sigma-rules/
│   │   ├── suspicious-powershell.yml    # T1059.001 — encoded PowerShell
│   │   └── lateral-movement-detection.yml # T1021 / T1047 — lateral movement
│   └── yara-rules/
│       └── malware-signature.yar         # generic malware indicators
├── 04-Vulnerability-Management/
│   ├── nessus-report-analysis.md        # CVE-level findings + prioritization
│   └── nmap-scan-scripts/
│       └── comprehensive-scan.sh        # staged network scan automation
├── 05-Incident-Response/
│   ├── sample-ir-playbook.md            # 6-phase ransomware IR (NIST-aligned)
│   ├── forensic-timeline.csv            # Windows artifact timeline reconstruction
│   └── malware-analysis-report.md       # static + dynamic malware analysis with IOCs
├── 06-Python-Tools/
│   ├── port-scanner.py                  # threaded TCP connect scanner
│   ├── log-analyzer.py                  # auth/log triage with pattern detection
│   └── hash-checker.py                  # multi-algorithm hash + verify
├── 07-Incident-Case-Study/
│   ├── README.md                         # Nancy/Amatera real incident case study
│   └── nancy-amatera/
│       ├── VICTIM_REPORT.md             # Main incident narrative
│       ├── IOCs.md                      # Full indicator dossier
│       ├── EVIDENCE_LOG.md              # Chain of custody
│       ├── sha256_manifest.txt          # Payload file hashes
│       ├── UpdateService_task.xml       # Scheduled task persistence export
│       ├── detection_history/           # 5 raw Defender DetectionHistory records
│       ├── nancy_amatera_detection_rules.yml  # 5 Sigma rules (EtherHiding, MSBuild LOLBIN, persistence, BAT stager, WPA.exe)
│       └── nancy_amatera_ioc_scanner.py       # Python IOC scanner
├── screenshots/
│   ├── pfsense-rules-annotated.png      # Zyxel EMG3525-T50B cable gateway firewall login (real)
│   ├── splunk-brute-force.png           # Splunk brute-force search results (real)
│   ├── splunk_home.png                  # Splunk home dashboard (real)
│   ├── splunk_summary.png               # Splunk monitoring console (real)
│   ├── splunk_app_search.png            # Splunk search app (real)
│   ├── splunk_search_app.png            # Splunk search interface (real)
│   ├── kibana_home.png                  # Kibana home (real)
│   ├── kibana_discover.png              # Kibana Discover (real)
│   └── kibana_dashboard.png             # Kibana Dashboards (real)
└── README.md                            # this file
```

---

## How to read this portfolio

- Start at **README.md** for the overall narrative and selection of work.
- Each project folder has its own README-style entry or a primary markdown with the full write-up.
- Detection rules (`.spl`, `.yml`, `.yar`) are the actual rule content — readable in any text editor.
- Python tools are runnable. Try `python3 06-Python-Tools/port-scanner.py --help` to see usage.

---

## Honest status

Every file in this repository is real content — detection logic, rule definitions, analysis, playbook steps, and live packet captures. No fabricated certificates, badges, or resume documents are included. The lab does not contain placeholder credential files.

All screenshots were captured from running services (Splunk on port 8000, Kibana on port 5601) or from actual lab hardware (Zyxel EMG3525-T50B cable gateway at 192.168.1.1). No conceptual mockups or fake UI images are present.

Everything is ready for review as-is.

---

*Built and revised incrementally. Each project folder documents what I did, why I did it that way, and what I would improve next.*
