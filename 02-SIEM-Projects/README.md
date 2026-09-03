# SIEM Detection Engineering — Splunk + Elastic Stack

> Home-lab SIEM stack ingesting Windows event logs and DNS data, with custom detection content for brute force and C2 activity. This section documents the detection logic, tuning rationale, validation approach, and ATT&CK mapping — not just the queries.

---

## Lab architecture

| component | role | deployment |
|-----------|------|------------|
| Splunk Free | Security analytics, alerting, search | Single-instance VM — 500 MB/day |
| Elastic Stack (ELK) | Log storage, Kibana visualization, index management | Ubuntu VM — 4 GB RAM |
| Winlogbeat | Windows event log forwarder | Windows 10 lab endpoint |
| Data sources | Security log (4624/4625/4688/4104), System, Application, DNS queries, firewall logs | Lab endpoints + simulated traffic |

**Ingestion pipeline:**

```
Windows Endpoint (Sysmon + Event Logs)
  → Winlogbeat → Elasticsearch → Kibana dashboards

Firewall / DNS logs
  → Syslog / filebeat → Elasticsearch → Kibana dashboards

All sources
  → Splunk (parallel ingestion) → searches → alerts
```

Splunk and Elastic run in parallel during the lab — Splunk for alerting and ad-hoc investigation, Elastic for long-term retention and dashboarding. In production I would consolidate on one stack and route all sources through it.

---

## Detection engineering principles used

1. **Start from the attack behavior, not the tool.** Each alert answers: what attacker action am I trying to see? What would real activity look like? What would a false positive look like?
2. **Tune before trusting.** Thresholds, lookback windows, and grouping logic are chosen with a false-positive analysis in mind. A detection that fires on normal activity gets disabled or ignored — so I tune before I rely on it.
3. **Map to ATT&CK.** Every detection is tagged with the technique it is designed to catch, so the coverage gap is visible.
4. **Test the detection.** Before trusting an alert, I generate the behavior it is supposed to catch and verify it fires. A detection that never tested is a hypothesis, not a control.

---

## Detection 1 — Brute Force Against SSH / RDP

**Hypothesis:** An attacker guessing credentials against SSH or RDP will produce a burst of failed authentication attempts from a single source IP against a single destination, within a short window, at a rate far above normal user error.

**ATT&CK mapping:**
- T1110 — Brute Force
- T1110.001 — Password Guessing
- T1110.003 — Password Spraying (if distributed across many targets)

### Splunk alert — brute-force-detection.spl

```spl
index=security sourcetype=winlogbeat_eventlog
| bin _time span=5m
| stats count as failures dc(dest) as targets by src_ip, _time
| where failures > 10 AND targets >= 1
| sort - failures
| eval first_seen = min(_time), last_seen = max(_time)
| table src_ip, targets, failures, first_seen, last_seen
```

**Why this logic:**
- `bin _time span=5m` groups attempts into 5-minute buckets — long enough to catch a spray, short enough to act on quickly.
- `dc(dest) as targets` counts distinct destinations. If `targets >= 1` and `failures > 10`, the source is hammering one or more hosts.
- Sorting by `failures` puts the most aggressive sources at the top.

**Threshold rationale — why 10 and not 5 or 50:**

| threshold | consequence |
|-----------|-------------|
| Too low (e.g. 3–5) | Legitimate user typos and lockouts trigger alert — alert fatigue, ignored |
| Too high (e.g. 50+) | Automated brute force may complete a significant portion of the password space before alerting |
| 10 in 5 minutes | Catches automated tools (Hydra, Medusa, Metasploit ssh_login) at a pace that indicates tooling, not a forgetful user. A human mistyping 10 times across multiple hosts in 5 minutes is unusual. |

**False-positive analysis:**

- **Normal:** A sysadmin mistyping a password 2–3 times and then succeeding is not a brute force. The alert requires >10 failures.
- **Lockout policy overlap:** If the account lockout policy locks after 5 failed attempts, the attacker may only get 5 attempts per lockout cycle — this alert may miss password sprays against accounts with aggressive lockout. In that case, I would look for the pattern of repeated lockouts rather than individual failures.
- **Distributed brute force:** If the attacker spreads attempts across many source IPs (botnet), this single-IP grouping will miss it. A complementary alert on destination-side failure rate would catch that.

**Tuning notes:**
- Reduce threshold to 5 if the environment has no legitimate reason for repeated failures and lockout is disabled.
- Increase lookback if log ingestion has latency.
- Add `action=failure` filter if the sourcetype distinguishes success/failure explicitly.

**Testing procedure:**

1. From a Kali machine in the lab, run Hydra against the Windows 10 RDP endpoint:
   ```
   hydra -l administrator -P /usr/share/wordlists/rockyou.txt 192.168.1.100 rdp
   ```
2. Verify the alert fires within one scheduling cycle (5 minutes).
3. Check the results table — confirm the attacking IP appears with a high failure count.
4. Stop the attack and confirm no further alerts for that source once failures stop.

**Response playbook trigger:**

When this alert fires:
1. Identify the source IP — is it internal (compromised host?) or external (inbound attack)?
2. Identify the target — which host/service is being attacked?
3. If external and persistent: block source IP at perimeter firewall; capture a sample of failed auth events for analysis.
4. If internal: the source host may be compromised or running a tool. Isolate and investigate.
5. Check whether any attempt succeeded — look for Event ID 4624 (successful logon) from the same source shortly after the failures.

---

## Detection 2 — Malware C2 DNS Detection

**Hypothesis:** Malware beaconing to command-and-control infrastructure will produce DNS queries to suspicious TLDs, newly registered domains, or domains with DGA-like characteristics — often at regular intervals (beaconing) and from hosts that have no legitimate reason to contact them.

**ATT&CK mapping:**
- T1071.001 — Application Layer Protocol: Web Protocols (C2 over HTTPS)
- T1568 — Dynamic Resolution (DGA)
- T1567 — Exfiltration Over Web Service (if data exfil via DNS/HTTPS)

### Splunk alert — malware-c2-alert.spl

```spl
index=security sourcetype=winlogbeat_dns
| eval tld = replace(query, ".*\\.", "")
| where tld IN ("xyz", "top", "club", "cf", "gq", "ml", "win", "bid", "loan")
   OR like(query, "%%.%%.%%") AND length(query) > 25
| stats count as query_count, earliest(_time) as first_seen, latest(_time) as last_seen by src_ip, query
| eval duration = last_seen - first_seen
| where query_count > 1 OR duration > 300
| sort - query_count
| table src_ip, query, tld, query_count, first_seen, last_seen, duration
```

**Why this logic:**
- Extracts the TLD and flags high-risk TLDs known to be abused by malware operators (cheap registration, bulk creation).
- Also flags long, random-looking domain names (potential DGA): `length(query) > 25` with multiple dots.
- Groups by source IP and query to identify beaconing — if a host queries the same suspicious domain repeatedly, that is a strong C2 indicator.
- Reports first_seen and last_seen to estimate the beacon window.

**Threat-intel enrichment:**
When this alert fires, the next step is to enrich the flagged domain:

1. Query VirusTotal API for the domain — check detection ratio and tags.
2. Query abuse.ch DNS-BH / URLhaus — check if the domain is listed as malicious.
3. Query AlienVault OTX pulses — check for related indicators.
4. If confirmed malicious: block domain at DNS sinkhole / firewall, isolate host, investigate what process issued the queries.

**False-positive analysis:**
- **Legitimate .xyz, .top, .club domains exist** — a marketing site, a dev domain, a test environment. The alert should be triageable, not an automatic block. Enrichment is essential.
- **DGA false positives:** Legitimate CDNs and random-looking internal hostnames can trigger the length/dot heuristic. Cross-reference with known internal naming before escalating.

**Tuning notes:**
- Maintain an allowlist of legitimate high-risk TLD domains in the environment (e.g., known dev/test domains).
- Add a beacon interval calculation — if queries arrive at regular intervals (e.g. every 60 ± 5 seconds), that is stronger evidence of C2 than a single lookup.
- Combine with process creation logs (Sysmon Event ID 1) to identify which process issued the DNS query.

**Testing procedure:**

1. From the Windows lab endpoint, generate test DNS queries to suspicious TLDs:
   ```
   nslookup randomdomain1234.xyz
   nslookup testdomain5678.top
   ```
2. Run a scripted beacon (Python or PowerShell loop) that queries the same domain every 30 seconds for 5 minutes.
3. Verify the alert fires with the beacon pattern — query_count should accumulate and duration should reflect the beacon window.
4. Confirm the enrichment step (manual VT/OTX lookup) is part of the response before any blocking action.

---

## Elastic Stack — log forwarding & dashboards

### Winlogbeat configuration

Winlogbeat ships Windows Security, System, and Application logs to Elasticsearch. The configuration focuses on:
- Security log as the primary source (authentication events, process creation, object access)
- 72-hour ignore window to reduce back-pressure on initial sync
- Credential-based output to Elasticsearch with template setup

Key fields of interest once ingested:
- `winlog.event_id` — 4624 (logon), 4625 (logon failure), 4688 (process creation), 4104 (PowerShell script block)
- `winlog.computer_name` — source host
- `winlog.user.id` — account context
- `winlog.activity_id` — correlation across related events

### Kibana dashboard

The dashboard export defines an index template for DNS query logs with mappings for timestamp, source IP, query, response code, and DNS type. In the lab I would build two dashboards:

1. **DNS query monitoring:**
   - Time series of query volume
   - TLD breakdown (pie/bar chart) with suspicious TLDs highlighted
   - Top querying hosts table
   - Suspicious domain alerts table (flagged queries)

2. **Windows logon activity:**
   - Logon successes vs failures over time
   - Failed logon sources (top IPs)
   - Service logons vs interactive logons
   - Privilege use events (Event ID 4672 — special privileges assigned)

These dashboards give a SOC analyst two views: DNS for C2/exfil detection, Windows logs for authentication and process activity.

---

## ATT&CK coverage summary

| technique | detection | coverage status |
|-----------|----------|-----------------|
| T1110 — Brute Force | brute-force-detection.spl | Covered (single-source, threshold-based) |
| T1110.001 — Password Guessing | brute-force-detection.spl | Covered |
| T1071.001 — Web Protocols (C2) | malware-c2-alert.spl (DNS + enrichment) | Partially covered (DNS phase; full C2 would need egress monitoring) |
| T1567 — Exfiltration Over Web Service | malware-c2-alert.spl (volume + suspicious TLD) | Partially covered (needs data volume analysis) |
| T1059.001 — PowerShell | (see 03-Threat-Hunting) | Covered in Sigma rules section |
| T1021 — Remote Services | (see 03-Threat-Hunting) | Covered in Sigma rules section |

**Coverage gap to address next:**
- T1071.001 full coverage requires egress HTTPS inspection or at minimum NetFlow analysis for beaconing to known-bad IPs, not just DNS.
- T1567 requires data volume monitoring on egress — a host sending 50 MB to an external IP over HTTPS is suspicious even if the domain is not yet flagged.

---

## Screenshots

Real captures from the running Splunk instance (port 8000) and Kibana instance (port 5601), plus the Zyxel gateway UI at 192.168.1.1.

```
![Splunk brute-force alert triggered](screenshots/splunk-brute-force.png)
  → Real screenshot: Splunk alerts list or triggered alert detail showing
    brute-force-detection alert with source IP, failure count, and timestamp.

![Splunk search results — brute force](screenshots/splunk-brute-force-results.png)
  → Real screenshot: Splunk search results table from running the SPL manually,
    showing src_ip, dest, count, and _time for a test brute force.

![Kibana DNS dashboard](screenshots/kibana-dns-dashboard.png)
  → Real screenshot: Kibana dashboard showing DNS query volume, TLD breakdown,
    and suspicious domain alerts from ingested Winlogbeat DNS logs.

![Kibana Windows logon dashboard](screenshots/kibana-logon-dashboard.png)
  → Real screenshot: Kibana dashboard showing logon success/failure over time
    and top failed-logon source IPs.
```

---

## What I learned

- **Threshold choice is a trade-off, not a number.** The difference between a useful alert and noise is often one or two counts, a different time window, or an additional filter. Document the choice so it can be revisited.
- **A detection without a test is an untested hypothesis.** I now test every detection by generating the behavior it should catch before considering it production-ready.
- **Enrichment is the difference between an alert and an investigation.** A suspicious domain alert that stops at "flagged" is a notification. One that includes VT/OTX enrichment and a recommended action is a head start on response.
- **Coverage gaps are visible when you map to ATT&CK.** Writing the coverage table made it obvious that I have brute force and DNS-phase C2 covered, but not full HTTPS egress monitoring or data exfil volume detection. Those are the next detections to build.

---

## Next steps

- [ ] Add a password-spray detection variant (failures distributed across many targets from one source)
- [ ] Build an egress beaconing detection using NetFlow — look for periodic connections to single external IPs
- [ ] Add process-to-DNS correlation in Splunk — join DNS queries with Sysmon process creation to answer "what process made this query?"
- [ ] Build the Windows logon dashboard in Kibana and add it to the repo
- [ ] Perform the brute-force and C2 test procedures and document the results
