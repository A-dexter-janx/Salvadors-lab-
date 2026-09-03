# Lab Gap Analysis — Salvador Janthan Cybersecurity Portfolio

**Date:** 2026-09-03  
**Status:** Living document — updated as gaps are closed

This document tracks gaps found during a comprehensive review of the portfolio, organized by priority. Each gap includes what's missing, why it matters, and how it was or will be addressed.

---

## Priority 1 — Critical (fix immediately)

### P1-1: Screenshots with no/empty content

**Files affected:**
- `screenshots/kibana_dashboard.png` — 38KB, blank page
- `screenshots/kibana_home.png` — 38KB, blank page
- `screenshots/kibana_discover.png` — 38KB, blank page
- `screenshots/splunk_summary.png` — 113KB, 404 error page

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
| — | Removed Certs-Badges/, TryHackMe badges, resume | Closed (7c53bff) |
| — | Replaced pfSense mockup with real Zyxel router screenshot | Closed (8156ff9) |
| — | Replaced blank Kibana screenshots with real ones from earlier session | Closed (e305e38) |
| — | Replaced splunk-summary.png 404 page with real monitoring console | Closed (e305e38) |
| — | Added splunk-login.png real screenshot | Closed (e305e38) |
| — | Updated README "Who I am" section | Closed (e305e38) |

---

## What this lab does well

- **Real incident evidence** (07-Incident-Case-Study) — 5 raw Defender DetectionHistory records, SHA256 manifest, scheduled task XML, chain-of-custody log, actual IOC scanner. This is the strongest section.
- **Detection logic depth** (02-SIEM-Projects, 03-Threat-Hunting) — threshold rationale, false-positive analysis, ATT&CK mapping, tuning notes. Most portfolios stop at the query.
- **Network design rationale** (01-Network-Security) — threat model, per-rule justification, ATT&CK mapping for network controls.
- **Working Python tools** (06-Python-Tools) — all three tools run, syntax valid, functional.
- **Honest status** — no fabricated certs/badges/resume. The lab doesn't pretend to have credentials it doesn't have.
