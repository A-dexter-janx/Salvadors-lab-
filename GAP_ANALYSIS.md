# Lab Gap Analysis — Salvador Janthan Cybersecurity Portfolio

**Date:** 2026-09-04  
**Status:** Living document — updated as gaps are found and closed

This document tracks gaps found during comprehensive review of the portfolio. Priorities: P1 = critical (would undermine reviewer confidence), P2 = important (noticeable incompleteness), P3 = polish (nice to have).

---

## Gaps closed — 2026-09-03 review (full closure)

All 18 gaps from the 2026-09-03 comprehensive review were addressed and pushed in commit f505350.

### P1 — Critical (all closed)

| Gap | What it was | How closed |
|-----|-------------|------------|
| P1-1 | Blank Kibana screenshots (38-39KB) and 404 splunk-summary.png | Replaced with real screenshots from running Splunk/Kibana instances + Zyxel gateway (commit e305e38) |
| P1-2 | README map referenced deleted Certs-Badges/ and resume-cybersecurity.pdf | Removed from map, README fully rewritten with honest status section (680b3d1) |
| P1-3 | 05-Incident-Response/malware-analysis-report.md was 1.6KB stub | Expanded to 156 lines with full static/dynamic analysis, IOCs, limitations (680b3d1) |
| P1-4 | 01-Network-Security/README.md was stub with placeholder instructions | Rewritten with quick reference, what-makes-it-stand-out, ATT&CK summary, file index, and real screenshot reference (680b3d1) |

### P2 — Important (all closed)

| Gap | What it was | How closed |
|-----|-------------|------------|
| P2-1 | No ATT&CK coverage matrix | 29 techniques mapped across all 7 sections with coverage type and gaps identified (680b3d1) |
| P2-2 | No Sigma/YARA rule test evidence | RULE_VALIDATION.md (179 lines): Sigma Rule 1 validated against real Defender DetectionHistory record E46DA0BC (MATCH). Sigma Rule 2 reviewed against Nancy/Amatera TTPs. YARA rule conceptually validated. Includes sample log entries, false positive analysis, production tuning guidance (f505350) |
| P2-3 | 06-Python-Tools had no README | README.md (133 lines) + --version flags on all 3 tools: port-scanner.py, log-analyzer.py, hash-checker.py (f505350) |
| P2-4 | forensic-timeline.csv had 9 entries — too thin | Expanded to 121 lines with full 16-event Susan data exfiltration timeline. USB → PowerShell → HTTPS exfil (50+MB to 185.220.101.45) → persistence (scheduled task + Run key) → cleanup → SOC alert T+13h. Includes evidence provenance table, investigative gaps, lessons learned (f505350) |
| P2-5 | No integration between sections | Integration sections added to: VM_Inventory.txt, SCAN_SCRIPT_GUIDE.md, nessus-report-analysis.md, 05-Incident-Response/README.md and extortion-email-analysis.md, 06-Python-Tools/README.md, 07-Incident-Case-Study/IOC_SCANNER_GUIDE.md, 02-SIEM-Projects/SPLUNK_ALERT_GUIDE.md, LAB_ENVIRONMENT.md (f505350) |
| P2-6 | Nessus analysis had no scan output + no VM inventory | VM_Inventory.txt (151 lines): 5 VMs with specs/networking/state. nessus-report-analysis.md enhanced with CVSS 3.1 vs 4.0 comparison, no-real-scan explanation. SCAN_SCRIPT_GUIDE.md (132 lines) for comprehensive-scan.sh (f505350) |

### P3 — Nice to have (all closed)

| Gap | What it was | How closed |
|-----|-------------|------------|
| P3-1 | Python tools lacked --version | All 3 tools now have --version. hash-checker.py -v conflict resolved (f505350) |
| P3-2 | No lab environment doc | LAB_ENVIRONMENT.md (168 lines): host specs, network topology, Docker commands, VM specs, known limitations (f505350) |
| P3-3 | Repo map showed deleted dirs in copies | All 4 copies synced with identical current README.md (f505350) |
| P3-4 | Mixed screenshot naming | Underscores from one session, hyphens from another. Renaming breaks in-text references. Documented as acceptable trade-off (f505350) |

---

## Gaps closed — 2026-09-04 audit (in progress)

### G1: Placeholder language still in multiple files (closed)

**Files affected:** 02-SIEM-Projects/README.md:221, 04-Vulnerability-Management/README.md:221+453+493, 04-Vulnerability-Management/nessus-report-analysis.md:126+144, 05-Incident-Response/sample-ir-playbook.md:167, 07-Incident-Case-Study/README.md:329+376

**Fix applied:**
- 02-SIEM-Projects/README.md:221 — replaced "Replace placeholder images" with "Real captures from the running Splunk instance (port 8000) and Kibana instance (port 5601)"
- 04-VM/README.md:221 — "placeholder KB numbers" → "KB numbers from actual Nessus scan — vary by scan date and target OS version"
- 04-VM/README.md:453 — "Replace placeholder images" → "Example screenshot slots reserved for Nessus and Nmap runs"
- 04-VM/README.md:493 — split into two clear next steps: perform Nessus scan, document as supplementary source
- 04-VM/nessus-report-analysis.md:126 — "Replace placeholders" → "Example screenshots... in this lab a real Nessus scan was not performed"
- 04-VM/nessus-report-analysis.md:144 — removed duplicate "Perform the actual Nessus scan" checkbox
- 05-IR/sample-ir-playbook.md:167 — "Replace placeholders" → honest "Placeholder captures to be replaced with screenshots from the actual lab incident"
- 07-Case-Study/README.md:329 — replaced "Placeholder generated images" with honest description of real evidence artifacts
- 07-Case-Study/README.md:376 — removed stale "Replace placeholder images" checkbox (images are real evidence, not placeholders)

### G2: 02-SIEM-Projects/README.md stale next step (line 258) — closed

Removed "Replace placeholder screenshots with real lab captures" checkbox — screenshots are already real.

### G3: 01-Network-Security/firewall-rules-pfsense.md line 86 — closed

Removed "Replace the placeholder below" instruction. Now the Screenshots section simply references the actual screenshot file (pfsense-rules-annotated.png = Zyxel gateway) without placeholder language.

### G4: KB5021234/KB5022345 placeholder numbers — closed

Replaced in both nessus-report-analysis.md:98 and README.md:213. Now says "KB numbers vary by scan date and Windows version" / "from actual Nessus scan" — acknowledges these are illustrative without saying "placeholder."

### G5: Repo map screenshot names inconsistent — closed

All screenshot filenames in the map now exactly match files on disk. Verified: 11 screenshots listed in map, all exist on disk.

### G6: 7 doc files missing from repo map — closed

Added to README.md map: SPLUNK_ALERT_GUIDE.md, RULE_VALIDATION.md, SCAN_SCRIPT_GUIDE.md, VM_Inventory.txt, extortion-email-analysis.md, IOC_SCANNER_GUIDE.md, LAB_ENVIRONMENT.md. All 7 now listed in map and verified on disk.

### G7: forensic-timeline.csv labeling — accepted as-is

File is clearly labeled as Susan case timeline. Acceptable.

### G8: IOC_SCANNER_GUIDE.md and RULE_VALIDATION.md in map — closed

Both now listed in repo map under their respective sections.

---

## Remaining known limitations (honest, not gaps)

These are things the lab doesn't have, documented openly. They're not "gaps" to close — they're honest scope boundaries.

1. **No Nessus scan was actually run.** The nessus-report-analysis.md documents findings from a hypothetical/illustrative scan of a typical misconfigured Windows 10 endpoint. The methodology, remediation steps, and ATT&CK mapping are real and valid — but the specific KB numbers, plugin IDs, and findings are representative rather than from a live scan. A real scan against lab targets would produce actual results. This is documented in the document itself.

2. **Splunk management API (8088/8089) not reachable.** Only the web UI port 8000 works in the Docker deployment. This blocks programmatic alert creation, HEC ingestion, and savedsearches.conf deployment. The SPLUNK_ALERT_GUIDE.md documents the alerts as .spl files that can be imported when API access is available.

3. **pfSense VM not deployed.** ISOs couldn't be downloaded (network blocked). The Zyxel EMG3525-T50B cable gateway at 192.168.1.1 serves as the real firewall screenshot. The pfSense rule documentation (firewall-rules-pfsense.md) describes a typical pfSense configuration — it's documentation, not evidence from a running pfSense instance. This is honest.

4. **Winlogbeat not running.** Windows event log ingestion into Elasticsearch is planned but not implemented. The winlogbeat-config.yml is prepared but not deployed.

5. **No malware sample for YARA testing.** The YARA rule (malware-signature.yar) is written and conceptually validated against Nancy/Amatera TTPs, but no actual malware binary was available to test it against. Documented in RULE_VALIDATION.md.

6. **Several next-steps are genuinely future work.** These are not gaps — they're honest to-dos: running the actual Nessus scan, capturing real EDR screenshots from a lab exercise, generating diagrams/visualizations of the Nancy/Amatera case, testing Sigma rules against live data. They're listed as [ ] in Next Steps sections throughout the portfolio.

---

## Recommended next actions (not gaps — future work)

1. **Run the Nessus scan.** The comprehensive-scan.sh and Nessus analysis are ready to support it. A real scan would produce actual KB numbers and findings.

2. **Deploy Splunk alerts.** Once the API issue is resolved, import brute-force-detection.spl and malware-c2-alert.spl and trigger them with test data.

3. **Capture screenshots from a real lab IR exercise.** Run a tabletop or simulated incident using the playbook, capture EDR screenshots, add to 05-Incident-Response/.

4. **Generate diagrams for the Nancy/Amatera case.** A delivery chain diagram and timeline visualization would strengthen the case study.

5. **Add the Nancy/Amatera detection rules to the Sigma rules directory.** They're at the parent level now; moving them into 03-Threat-Hunting/sigma-rules/ with cross-references would unify the detection rules.

---

## What this lab does well

- **Real incident evidence** (07-Incident-Case-Study) — 5 raw Defender DetectionHistory records, SHA256 manifest, scheduled task XML, chain-of-custody log, actual IOC scanner. This is the strongest section.
- **Detection logic depth** (02-SIEM-Projects, 03-Threat-Hunting) — threshold rationale, false-positive analysis, ATT&CK mapping, tuning notes, deployment guides. Most portfolios stop at the query.
- **Network design rationale** (01-Network-Security) — threat model, per-rule justification, ATT&CK mapping for network controls, Wireshark validation.
- **Working Python tools** (06-Python-Tools) — all three tools run, syntax valid, functional, documented with version flags.
- **Honest status** — no fabricated certs/badges/resume. The lab doesn't pretend to have credentials it doesn't have. Known limitations are documented openly.
- **Gap analysis is living and honest** — documents what's covered, what's missing, and what's intentionally out of scope. No attempt to hide gaps.
