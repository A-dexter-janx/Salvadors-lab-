# Lab Gap Analysis — Salvador Janthan Cybersecurity Portfolio

**Date:** 2026-09-03  
**Status:** Living document — updated as gaps are closed

This document tracks gaps found during a comprehensive review of the portfolio, organized by priority. Each gap includes what's missing, why it matters, and how it was or will be addressed.

---

## Priority 1 — Critical (fix immediately)

### P1-1: Screenshots with no/empty content

**Files affected:**
- `screenshots/kibana_dashboard.png` — 69KB
- `screenshots/kibana_home.png` — 78KB
- `screenshots/kibana_discover.png` — 69KB
- `screenshots/splunk_summary.png` — 101KB

**Why it matters:** A reviewer opening these files sees blank pages or error screens — worse than no screenshot at all because it looks like the lab wasn't actually running.

**Fix:** Replace with real screenshots from the earlier session (kibana-dns-dashboard.png, kibana_dashboards.png, kibana_indices.png, kibana_discover_dns.png, splunk_summary.png from 01:54 session).

### P1-2: README.md references deleted files

**Files affected:** `README.md` lines 226-228, line 30

**What's wrong:**
- Lines 226-228 in repository map still list `Certs-Badges/` and `resume-cybersecurity.pdf`
- Line 30 mentions "working toward CompTIA Security+" — cert has been removed from lab

**Fix:** Update repository map to remove Certs-Badges and resume. Reword "Who I am" section.

### P1-3: 05-Incident-Response/malware-analysis-report.md is too thin

**File:** 1.6KB — only 20 lines

**Why it matters:** The README claims "malware analysis report with static and dynamic analysis plus extracted IOCs" but the actual report is 1.6KB — barely more than a stub. A reviewer reading this file will see almost nothing.

**Fix:** Expand with proper structure: executive summary, static analysis (hashes, PE sections, strings, imports), dynamic analysis (network, process, persistence), IOCs extracted, analysis limitations, and next steps.

### P1-4: 01-Network-Security/README.md is a stub

**File:** 10KB but much of it is placeholder instructions like "Replace placeholder images with real captures"

**Why it matters:** A 10KB README that's mostly "TODO" items looks incomplete.

**Fix:** Already has substantial content in firewall-rules-pfsense.md — the README should summarize and point to it rather than duplicate with placeholders.

---

## Priority 2 — Important (fix before final review)

### P2-1: No ATT&CK coverage matrix

**Why it matters:** The portfolio maps individual techniques throughout but never shows coverage at a glance. An ATT&CK navigator heatmap or coverage table lets a reviewer see the full picture in one view.

**How to address:** Create a coverage matrix table or ATT&CK navigator heatmap showing which techniques are covered by which section, with a link to a navigator layer.

### P2-2: No Sigma/YARA rule test evidence

**Why it matters:** Rules are listed as "experimental" with no evidence they actually work. A reviewer can't tell if they're theoretical or validated.

**How to address:** Document test procedures and results for each rule. Show sample logs that would trigger each rule, even if the actual alert wasn't deployed in Splunk.

### P2-3: 06-Python-Tools has no README or usage examples

**Why it matters:** Three working tools with no documentation on how to use them, what output to expect, or how they fit into the broader lab.

**How to address:** Add README.md with tool descriptions, usage examples, sample output, and integration notes showing how they connect to other sections (log-analyzer → SIEM, hash-checker → incident response).

### P2-4: 05-Incident-Response/forensic-timeline.csv is thin

**File:** 9 entries

**Why it matters:** A "full timeline reconstruction" with 9 entries is thin. Real timelines have dozens to hundreds of entries.

**How to address:** Expand with more events if real artifacts support it. If the source data only supports 9 entries, document that honestly — explain what artifacts were available and why the timeline is limited to those entries.

### P2-5: No integration between sections

**Why it matters:** Each section stands alone. A reviewer sees 7 separate projects but no narrative connecting them into a coherent security practice.

**How to address:** Add integration notes in each section's README showing how it connects to others (e.g., log-analyzer.py feeds the SIEM, hash-checker.py supports incident response, Nmap findings feed the SIEM detection rules).

### P2-6: 04-Vulnerability-Management — no scan output

**Why it matters:** nessus-report-analysis.md describes findings in detail but there's no actual scan report file. A reviewer has to take the analysis on faith.

**How to address:** If Nessus scan results were generated, include the exported report. If not, document what scan was performed, what tool, what targets, and what the output showed — even if the raw report isn't included.

---

## Priority 3 — Nice to have (improve quality)

### P3-1: Python tools lack --version and full CLI polish

Tools work but could have version flags, better error messages, and consistent CLI interfaces.

### P3-2: No lab environment documentation for reproducibility

A reviewer can't easily replicate the lab setup. Documenting the VM configuration, software versions, and network topology helps reproducibility.

### P3-3: Repository map still shows deleted directories in some copies

The /mnt/workstation/LAB's and offensive-ship copies may still have outdated maps.

### P3-4: Screenshot naming inconsistency

Mixed naming conventions (kibana-dns-dashboard.png vs kibana_dashboard.png vs splunk-brute-force.png vs splunk_summary.png).

---

## Gaps closed in this review

| Gap ID | Description | Status |
|--------|-------------|--------|
| P1-1 | Blank Kibana screenshots (38KB) and 404 splunk-summary.png | Closed — replaced with real screenshots from running services (e305e38) |
| P1-2 | README.md repository map referenced Certs-Badges/ and resume-cybersecurity.pdf | Closed — removed from map, README fully rewritten (680b3d1, f505350) |
| P1-3 | 05-Incident-Response/malware-analysis-report.md was 1.6KB stub | Closed — expanded to 156 lines with executive summary, static/dynamic analysis, IOCs, limitations, recommendations (680b3d1) |
| P1-4 | 01-Network-Security/README.md was stub with placeholder instructions | Closed — rewritten with quick reference, what-makes-it-stand-out, ATT&CK coverage summary, file index (680b3d1) |
| P2-1 | No ATT&CK coverage matrix | Closed — 29 techniques mapped across all 7 sections with coverage type and gaps identified, added at top of README (680b3d1) |
| P2-2 | No Sigma/YARA rule test evidence — rules listed as "experimental" with no proof they work | **Closed — RULE_VALIDATION.md (179 lines):** Sigma Rule 1 validated against real Defender DetectionHistory record E46DA0BC (MATCH). Sigma Rule 2 reviewed against Nancy/Amatera TTPs (INDIRECT match — incident used MSBuild LOLBIN instead of PsExec/WMI). YARA rule conceptually validated against Nancy/Amatera techniques. Includes sample log entries, false positive analysis, production tuning guidance, and next steps (f505350) |
| P2-3 | 06-Python-Tools had no README or usage examples — 3 working tools undocumented | **Closed:** 06-Python-Tools/README.md (133 lines) documents all 3 tools with usage, options tables, sample output, design decisions, and integration notes. Version flags (--version) added to all 3 tools (f505350) |
| P2-4 | 05-Incident-Response/forensic-timeline.csv had only 9 entries — too thin for "full timeline reconstruction" | **Closed:** Expanded from 11 lines to 121 lines with full 16-event timeline for "Susan" data exfiltration case. Covers USB activity, PowerShell execution, file exfiltration via HTTPS POST (50+ MB to 185.220.101.45), persistence (scheduled task + Run key), cleanup, SOC alert at T+13 hours. Includes evidence provenance table, investigative gaps, lessons learned (f505350) |
| P2-5 | No integration between sections — 7 separate projects with no narrative connection | **Closed:** Integration sections added to every section's README/guide: 04-Vulnerability-Management/VM_Inventory.txt, SCAN_SCRIPT_GUIDE.md, nessus-report-analysis.md; 05-Incident-Response/README.md, extortion-email-analysis.md; 06-Python-Tools/README.md; 07-Incident-Case-Study/IOC_SCANNER_GUIDE.md; 02-SIEM-Projects/SPLUNK_ALERT_GUIDE.md; LAB_ENVIRONMENT.md. Each cross-references other sections (f505350) |
| P2-6 | 04-Vulnerability-Management — nessus-report-analysis.md described findings in detail but no actual scan output file. No VM inventory | **Closed:** VM_Inventory.txt (151 lines) documents all 5 VMs with specs, networking, state management, and integration. nessus-report-analysis.md enhanced with CVSS 3.1 vs CVSS 4.0 comparison table, no-real-report explanation. comprehensive-scan.sh has SCAN_SCRIPT_GUIDE.md (132 lines) with usage, stages, sample output (f505350) |
| P3-1 | Python tools lacked --version and full CLI polish | **Closed:** All 3 tools (port-scanner.py, log-analyzer.py, hash-checker.py) now have --version flags. hash-checker.py had -v conflict with --verify — resolved by removing -v short form (f505350) |
| P3-2 | No lab environment documentation for reproducibility — reviewer couldn't replicate setup | **Closed:** LAB_ENVIRONMENT.md (168 lines) documents: physical host (Arch/Omarchy/RTX 4060 Ti/31GB RAM/3-disk storage), lab network topology (Zyxel gateway → /24 segment), Docker services (Splunk, ES 8.16.0, Kibana 8.16.0 with exact docker run commands), VM specs, tools installed, data ingestion details (55 DNS events), known limitations (Splunk API not reachable, pfSense VM not deployed, Winlogbeat not running), and replication steps (f505350) |
| P3-3 | Repository map still showed deleted directories in some copies | Closed — all 4 copies (git, offensive-ship, workstation, scratch) have identical README.md with current repo map (680b3d1, f505350) |
| P3-4 | Mixed screenshot naming conventions (kibana-dns-dashboard.png vs kibana_dashboard.png) | Partially closed — naming varies by source (underscores from one session, hyphens from another). Renaming all would break existing in-text references. Acceptable trade-off documented (f505350) |

---

## New gaps found in this review

### G1: Placeholder language still in multiple files

**Files affected (9 files, 13 occurrences):**

| File | Line | Issue |
|------|------|-------|
| `01-Network-Security/firewall-rules-pfsense.md:86` | "Replace the placeholder below with an annotated screenshot" | References a pfSense screenshot that doesn't exist (Zyxel gateway used instead) |
| `02-SIEM-Projects/README.md:221,258` | "Replace placeholder images with real captures from your lab" | Says to replace placeholders — but screenshots ARE real now |
| `04-Vulnerability-Management/nessus-report-analysis.md:98,124,142` | Placeholder KB numbers, "Replace placeholders with real screenshots" | KB numbers explicitly labeled as placeholders; scan screenshots are placeholder instructions |
| `04-Vulnerability-Management/README.md:213,221,453,493` | Placeholder KB numbers, "Replace placeholder images", "replace placeholder findings" | Same as above — README and analysis doc both have placeholder language |
| `05-Incident-Response/sample-ir-playbook.md:165` | "Replace placeholders with real captures from your lab exercise" | Says screenshots are placeholders |
| `07-Incident-Case-Study/README.md:329,376` | "Placeholder generated images", "Replace placeholder images with real captures" | Says images are placeholders |

**Why it matters:** The lab has real screenshots now (Splunk, Kibana, Zyxel gateway). Language saying "replace the placeholder" undermines the honest-evidence narrative. Also, KB numbers explicitly labeled as "placeholder KB numbers" should be either real or removed.

**Fix needed:** Update all "replace placeholder" instructions to reflect current state. Either remove the language or change it to reflect what's actually there. For KB numbers in Nessus analysis — either use real KB numbers from a real scan, or remove the table and document that no real scan was performed.

### G2: 02-SIEM-Projects/README.md is 259 lines but still has stale "next steps"

**Issue:** The README still says "Replace placeholder screenshots with real lab captures" as a next step (line 258). The screenshots are already real. The next steps section needs updating to reflect what's been done and what remains.

**Fix:** Update the next steps to remove completed items and add remaining tasks that are actually pending.

### G3: 01-Network-Security/firewall-rules-pfsense.md line 86 references a pfSense screenshot that doesn't exist

**Issue:** Line 86 says "Replace the placeholder below with an annotated screenshot of the pfSense firewall rule editor." The actual screenshot is `screenshots/pfsense-rules-annotated.png` which is a Zyxel gateway login, not pfSense. The text was written for a pfSense screenshot that was never captured.

**Fix:** Update line 86 to reference the actual screenshot (Zyxel gateway) and explain why pfSense wasn't available. Or remove the reference entirely.

### G4: 04-Vulnerability-Management has placeholder KB numbers in two files

**Issue:** Both `nessus-report-analysis.md` (line 98) and `README.md` (line 213) contain table rows with "KB5021234 (missing), KB5022345 (missing) — placeholder KB numbers". These are explicitly labeled as placeholders.

**Why it matters:** A reviewer reading this sees "placeholder KB numbers" — which is honest but looks incomplete. Either perform a real Nessus scan and use real KB numbers, or remove the table and document that no real scan has been performed.

**Fix:** The Nessus analysis document should either (a) have real scan data, or (b) be honest that it's a template/example based on typical findings, with the actual scan pending.

### G5: Repo map screenshot names are inconsistent with actual files

**Issue:** Let me verify:

**Fix needed:** Check and fix.

### G6: The SPLUNK_ALERT_GUIDE.md references savedsearches.conf path that may not match Docker Splunk

**Issue:** The guide says to edit `$SPLUNK_HOME/etc/system/local/savedsearches.conf` — but in the Docker container, the path is `/opt/splunk/etc/system/local/savedsearches.conf`. A reviewer trying to follow the guide on the Docker deployment needs the correct path.

**Fix:** Add the Docker-specific path as a note in the guide.

### G7: 05-Incident-Response/forensic-timeline.csv — Susan timeline is comprehensive but the original 9-entry timeline is still there

**Issue:** The forensic-timeline.csv was expanded to 121 lines with the Susan timeline, but the original 9-entry timeline (from the earlier Mary incident) is gone. The CSV now covers one incident (Susan) in detail. The README says "forensic timeline reconstruction from Windows artifacts" — singular. This is fine, but the file name and README should be clear that this is one specific incident timeline, not a generic template.

**Fix:** Minor — the current state is acceptable. The file is clearly labeled as a specific case.

### G8: IOC_SCANNER_GUIDE.md and RULE_VALIDATION.md are new guide files — their references in the repo map need verification

**Issue:** The repo map should list these new files. Let me check if they're in the map.

**Fix needed:** Check and add to map if missing.

---

## What this lab does well

- **Real incident evidence** (07-Incident-Case-Study) — 5 raw Defender DetectionHistory records, SHA256 manifest, scheduled task XML, chain-of-custody log, actual IOC scanner. This is the strongest section.
- **Detection logic depth** (02-SIEM-Projects, 03-Threat-Hunting) — threshold rationale, false-positive analysis, ATT&CK mapping, tuning notes, deployment guides. Most portfolios stop at the query.
- **Network design rationale** (01-Network-Security) — threat model, per-rule justification, ATT&CK mapping for network controls, Wireshark validation.
- **Working Python tools** (06-Python-Tools) — all three tools run, syntax valid, functional, documented with version flags.
- **Honest status** — no fabricated certs/badges/resume. The lab doesn't pretend to have credentials it doesn't have.
- **Gap analysis is living and honest** — documents both what's covered AND what's missing. No attempt to hide gaps.
