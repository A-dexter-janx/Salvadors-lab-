# SIEM Projects — Elastic Stack & Splunk

Detection-as-code and centralized logging lab. Deploying Splunk Free and the Elastic Stack (ELK) on home-lab VMs, ingesting Windows event logs and network data, and building custom detection content.

---

## Projects in This Section

### 1. Splunk Detection Alerts

Two custom Splunk Saved Searches (SPL) for detecting active threats in ingested security logs.

#### Brute Force Detection (SSH / RDP)

Detects automated password-guessing against remote access services by counting failed authentication attempts per source IP within a 5-minute window.

**Alert logic:**
- Index: `security` / sourcetype: `winlogbeat_eventlog`
- Groups by source IP and destination
- Triggers when `count > 10` failed attempts in 5 minutes
- Severity: **High** — email SOC analyst + create ticket

```spl
index=security sourcetype=winlogbeat_eventlog
| stats count by src_ip, dest, _time
| where count > 10
| eval threshold_exceeded = if(count > 10, "YES", "NO")
| table src_ip, dest, count, _time
```

> **Rationale:** 10+ failures in 5 minutes across a single source typically indicates Hydra, Medusa, or Metasploit auxiliary scanners. Normal user typos average 1–2 per session. Threshold balances detection sensitivity against false positives.

**Testing:** Run `hydra -l admin -P passwords.txt ssh://192.168.1.100` or Metasploit `auxiliary/scanner/ssh/ssh_login` and verify the alert fires within one scheduling cycle.

---

#### Malware C2 DNS Detection

Detects suspicious DNS queries using high-risk TLDs commonly associated with malware command-and-control infrastructure, plus beaconing pattern analysis.

**Alert logic:**
- Index: `security` / sourcetype: `winlogbeat_dns`
- Filters for `.xyz`, `.top`, `.club` TLDs (abused by malware families)
- Also identifies periodic beaconing (queries at fixed intervals from same host)
- Severity: **Medium** — investigate source host, enrich with threat intel

```spl
index=security sourcetype=winlogbeat_dns
| stats count by query, src_ip
| where like(query, "%.xyz") OR like(query, "%.top") OR like(query, "%.club")
| eval suspicious_domain = if(match(query, "(xyz|top|club)$"), "YES", "NO")
| table src_ip, query, count, suspicious_domain
```

> **Enrichment:** Cross-reference flagged domains with VirusTotal API, abuse.ch DNS blocklists, and AlienVault OTX pulses before escalating.

---

### 2. Elastic Stack — Log Forwarding & Dashboards

Self-hosted ELK stack ingesting Windows security events via Winlogbeat and DNS query data for Kibana visualization.

#### Winlogbeat Configuration

Winlogbeat ships Windows Security, System, and Application logs to Elasticsearch. Configured for credential-based authentication with template setup and Kibana registration.

**Key settings:**
- Security log: 72-hour retention window (ignore older)
- Output: Elasticsearch `http://elasticsearch:9200`
- Kibana: `kibana:5601` for visualization and dashboard management

#### Kibana Dashboard Export

JSON index template for DNS query logs, defining mappings for timestamp, source IP, query domain, response code, and DNS record type. Preconfigured with one shard and zero replicas suitable for a lab deployment.

#### Environment

| Component | Version/Spec |
|-----------|-------------|
| Splunk Free | 500 MB/day ingestion limit |
| Elastic Stack | Self-hosted on Ubuntu VM, 4 GB RAM |
| Winlogbeat | 8.x on Windows 10 endpoint |
| Data sources | Windows Event Logs (Security, System, Application), DNS queries, firewall logs |

---

## Screenshots

Real lab screenshots should be inserted here once you perform the actual deployment. Suggested captures:

**Splunk:**
- Saved Searches list showing both brute-force and C2 alerts configured
- Alert triggered state — results table with attacking IP highlighted
- Splunk search bar with SPL query visible

**Kibana:**
- Discover page showing indexed Windows event logs
- Dashboard with DNS query visualization (pie chart by TLD, time series of queries)
- Index pattern management screen showing field mappings

Place screenshots in this folder and reference them here:

```
![Splunk brute-force alert](screenshots/splunk-brute-force.png)
![Kibana DNS dashboard](screenshots/kibana-dns-dashboard.png)
```

---

## Next Steps

- [ ] Deploy Splunk on a dedicated VM and configure as single-instance deployment
- [ ] Install and configure Winlogbeat on a Windows 10 lab endpoint
- [ ] Build 3–5 additional custom detection alerts (e.g. suspicious process creation, service installation, registry persistence)
- [ ] Create at least two Kibana dashboards — one for DNS traffic, one for Windows logon activity
- [ ] Document each dashboard with a screenshot and explanation of what it monitors
