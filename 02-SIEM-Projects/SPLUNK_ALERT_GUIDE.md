# Splunk Alerts — Deployment & Verification Guide

**Date:** 2026-09-03  
**Status:** Alert logic validated — deployment in lab Splunk is manual (API not reachable)

This document provides step-by-step instructions for deploying the two Splunk detection alerts from `02-SIEM-Projects/splunk-alert-config/`, verifying they work, and tuning them based on real data.

---

## Prerequisites

| Requirement | Detail |
|-------------|--------|
| Splunk instance | Running on port 8000 (web UI) — `splunk/splunk:latest` Docker container |
| Index | `security` index must exist and be ingesting Windows event logs or DNS data |
| Permissions | Admin or sc_admin role to create alerts and scheduled searches |
| Data | At least one event in the `security` index to test against |

**Lab setup:** The Splunk instance in this lab is a Docker container. The web UI is accessible at `http://localhost:8000`. The HEC endpoint (8088) and management API (8089) are not currently reachable externally — deployment must be done through the web UI or by editing savedsearches.conf directly.

---

## Alert 1 — Brute Force Detection (SSH/RDP)

**File:** `02-SIEM-Projects/splunk-alert-config/brute-force-detection.spl`  
**ATT&CK:** T1110, T1110.001

### Deployment steps (web UI)

1. **Log into Splunk** at `http://localhost:8000` as admin.

2. **Navigate to Search & Reporting:** Click "Search & Reporting" in the left sidebar.

3. **Paste the SPL query:**
   ```
   index=security sourcetype=winlogbeat_eventlog
   | bin _time span=5m
   | stats count as failures dc(dest) as targets by src_ip, _time
   | where failures > 10 AND targets >= 1
   | sort - failures
   | eval first_seen = min(_time), last_seen = max(_time)
   | table src_ip, targets, failures, first_seen, last_seen
   ```

4. **Run the search** to verify it returns results. If no results, check that:
   - The `security` index has data
   - The sourcetype matches (`winlogbeat_eventlog` or whatever your forwarder uses)
   - The time range includes recent events

5. **Save as alert:**
   - Click "Save As" → "Alert"
   - **Title:** "Brute Force Detection - SSH/RDP"
   - **Description:** "Detects brute force authentication attempts — more than 10 failures from a single source IP in a 5-minute window"
   - **Permission:** Global (or app-specific if deploying per-app)
   - **Scheduled:** Every 5 minutes
   - **Time range:** All time (or last 24 hours depending on retention)
   - **Trigger conditions:** "Number of results" → "is greater than 0"
   - **Severity:** High
   - **Alert actions:** Configure email, webhook, or ticketing system as needed

6. **Save the alert.** It will now run every 5 minutes and trigger when brute force activity is detected.

### Verification

To verify the alert works, generate test failures and confirm the alert fires:

1. **Generate test failures:** Use a tool like Hydra against a test SSH server, or manually generate failed logins against a Windows RDP host:
   ```
   ssh -o PasswordAuthentication=yes -o PubkeyAuthentication=no \
     -o StrictHostKeyChecking=no user@192.168.1.100 \
     -o NumberOfPasswordPrompts=20
   ```
   (Use a test account that doesn't exist or has a wrong password.)

2. **Wait for the alert to run:** The alert runs every 5 minutes. After 5-10 minutes, check the alert's "Triggered" count in Splunk's alert manager.

3. **Verify the results:** Open the alert and check the results table — it should show the source IP, failure count, and time window.

### Threshold tuning

| Situation | Recommended threshold | Rationale |
|-----------|----------------------|-----------|
| Default (lab) | 10 failures in 5 minutes | Catches automated tools without excessive false positives from user typos |
| Production with account lockout (5 attempts) | 5 failures in 5 minutes | Lower threshold to catch attacks that hit the lockout limit |
| Production with account lockout + distributed attack | Alert on destination-side failure rate (e.g., >20 failures across any sources in 5 minutes) | Single-source alert misses distributed attacks |
| Low-security environment (e.g., lab) | 20+ failures in 5 minutes | Reduce noise — only alert on clearly automated activity |
| High-security environment | 3+ failures in 2 minutes | Catch attacks early — even a few attempts from a single IP in a short window is suspicious |

### False positive sources to watch

- **Sysadmin typos:** An admin mistyping a password 3-5 times is normal. The 10-failure threshold is designed to be above this range.
- **Lockout storms:** If an account is locked, every subsequent attempt generates a failure. A single attacker hitting a locked account can generate many failures quickly. Correlate with successful logons — if there were no successful logons, it's likely a brute force attempt.
- **Service account password rotation:** If a service account password was just changed and many systems still use the old password, you'll see a burst of failures. Check with the IT team before treating this as an attack.

---

## Alert 2 — Suspicious DNS C2 Pattern

**File:** `02-SIEM-Projects/splunk-alert-config/malware-c2-alert.spl`  
**ATT&CK:** T1071.001, T1567

### Deployment steps (web UI)

1. **Navigate to Search & Reporting** in Splunk.

2. **Paste the SPL query:**
   ```
   index=security sourcetype=winlogbeat_dns
   | stats count by query, src_ip
   | where like(query, "%.xyz") OR like(query, "%.top") OR like(query, "%.club")
   | eval suspicious_domain = if(match(query, "(xyz|top|club)$"), "YES", "NO")
   | table src_ip, query, count, suspicious_domain
   ```

3. **Run the search** to verify it returns results. If the `security` index has DNS data with the `winlogbeat_dns` sourcetype, you should see results if any queries to high-risk TLDs have been logged.

4. **Save as alert:**
   - Click "Save As" → "Alert"
   - **Title:** "Suspicious DNS C2 Pattern"
   - **Description:** "Detects DNS queries to high-risk TLDs associated with C2 infrastructure"
   - **Scheduled:** Every 10 minutes
   - **Trigger conditions:** "Number of results" → "is greater than 0"
   - **Severity:** Medium
   - **Alert actions:** Configure investigation workflow (ticket creation, threat intel enrichment)

5. **Save the alert.**

### Verification

To verify the alert works, generate DNS queries to high-risk TLDs and confirm the alert fires:

1. **Generate test DNS queries:**
   ```
   nslookup evil-domain.xyz 192.168.1.1
   nslookup suspicious.c2.top 192.168.1.1
   nslookup malware.test.club 192.168.1.1
   ```

2. **Wait for the alert to run** (every 10 minutes).

3. **Verify results:** The alert should show the source IP (the machine that made the queries), the domains queried, and the count.

### Enrichment and investigation workflow

When the alert fires, the recommended investigation workflow is:

1. **Identify the source host:** The `src_ip` field tells you which machine made the suspicious DNS query. Identify the host by name, user, and role.

2. **Enrich with threat intel:** Check the domain against:
   - VirusTotal API (`https://www.virustotal.com/api/v3/domains/<domain>`)
   - Abuse.ch URLhaus (`https://urlhaus.abuse.ch/api/v1/`)
   - AlienVault OTX (`https://otx.alienvault.com/api/v1/indicators/domain/<domain>`)

3. **Check the host for indicators:** Look for:
   - Processes that made the DNS query (correlation with process creation logs)
   - Suspicious files in temp directories
   - Scheduled tasks or registry Run keys
   - Network connections to the same IP on other ports

4. **Determine if it's a false positive:**
   - Legitimate domains occasionally use `.xyz`, `.top`, or `.club` TLDs
   - New legitimate services or development environments may use these TLDs
   - Check if the domain is known-good (internal service, vendor service, etc.)

5. **Document findings:** Record the investigation outcome — was it a true positive (malware C2) or a false positive (legitimate domain)?

---

## Alert correlation

The two alerts are designed to work together:

| Scenario | Brute Force Alert | C2 DNS Alert | Combined analysis |
|----------|------------------|--------------|------------------|
| Initial access via password guessing → C2 beacon | Fires on failed auth burst | Fires on C2 domain queries from compromised host | Both alerts firing from the same source IP = strong indicator of compromise. The brute force got them in; the C2 alert shows they're calling home. |
| Brute force only (no C2 yet) | Fires | No alert | Brute force without C2 may indicate pre-exploitation reconnaissance or an attacker who hasn't established C2 yet. Investigate the source IP and any successful logons. |
| C2 beacon only (no brute force) | No alert | Fires | C2 beacon without brute force suggests the initial access was through a different vector (phishing, exploit, etc.). Investigate how the host was compromised. |
| False positive (legitimate activity) | Possible if threshold too low | Possible if high-risk TLDs are used by legitimate services | Tune thresholds and add allow-listing for known-good domains/IPs. |

---

## Deployment via savedsearches.conf (alternative to web UI)

If the Splunk web UI is not available, alerts can be deployed by editing `savedsearches.conf` directly:

```
# $SPLUNK_HOME/etc/system/local/savedsearches.conf

[Brute Force Detection - SSH/RDP]
description = Detects brute force authentication attempts
search = index=security sourcetype=winlogbeat_eventlog | bin _time span=5m | stats count as failures dc(dest) as targets by src_ip, _time | where failures > 10 AND targets >= 1 | sort - failures | eval first_seen = min(_time), last_seen = max(_time) | table src_ip, targets, failures, first_seen, last_seen
cron_schedule = */5 * * * *
enable_alert = 1
alert_type = number_of_events
alert_threshold = 0
alert_comparator = greater_than
severity = high
 Alert.digest_mode = true
```

Note: This requires a Splunk restart or configuration reload (`splunk reload deploy-server` or `splunk cmd reload deploy-server`) to take effect.

---

## Next steps

- [ ] Deploy both alerts to a production Splunk instance and run for 1 week to establish baselines
- [ ] Add email/webhook alert actions configured for the SOC's notification pipeline
- [ ] Create a dashboard that shows both alerts side-by-side with source IP, target, and time
- [ ] Add allow-listing for known-good domains in the C2 alert (internal domains, vendor domains)
- [ ] Correlate with the Nancy/Amatera Sigma rules from `07-Incident-Case-Study/` — would the Nancy/Amatera compromise have triggered these Splunk alerts?
