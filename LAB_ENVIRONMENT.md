# Lab Environment — Reproducibility Reference

**Date:** 2026-09-03  
**Status:** Living document — updated as the lab evolves

This document describes the lab environment so someone can understand or replicate what was built. It covers the physical setup, virtualized components, Docker services, and network topology.

---

## Physical host

| Attribute | Detail |
|-----------|--------|
| Host OS | Arch Linux (rolling) — current as of 2026-09-03 |
| Desktop | Omarchy (Hyprland-based) with Quickshell |
| CPU | Intel Core i7-xxxx (specific model varies by hardware) |
| RAM | 31 GB |
| GPU | NVIDIA RTX 4060 Ti 8 GB |
| Storage | 3-disk setup: NVMe 938 GB (workstation), NVMe 469 GB (storage), SATA 880 GB (bulk) |
| Ollama | Available for model inference (RTX 4060 Ti, 31 GB RAM) |

---

## Lab network

```
Internet
  │
  ▼
Zyxel EMG3525-T50B (cable gateway/router)
  IP: 192.168.1.1 (management/web UI)
  │
  ▼
192.168.1.0/24 lab network
  │
  ├── 192.168.1.10  — Windows 10 VM (endpoint, simulated user workstation)
  ├── 192.168.1.50   — DMZ web server (intentionally misconfigured for vuln management)
  ├── 192.168.1.100  — Kali Linux (attacker machine, attack simulation)
  ├── 192.168.1.200  — Ubuntu VM (Nessus scanner host)
  └── 192.168.1.250  — SIEM zone / management (Splunk, Elastic, Kibana via Docker)
```

**Note:** The Zyxel EMG3525-T50B is the actual cable gateway on the lab's physical network. Its web UI (at 192.168.1.1) is the "firewall screenshot" used in the network security section. The pfSense VM referenced in documentation was planned but not deployed — the Zyxel gateway served as the real firewall device instead.

---

## Docker services

| Service | Image | Version | Port | Purpose |
|---------|-------|---------|------|---------|
| Splunk | `splunk/splunk:latest` | Free edition | 8000 (web UI), 8088 (HEC), 8089 (mgmt API) | SIEM — search, alerting, dashboards. 55 DNS events indexed. |
| Elasticsearch | `docker.elastic.co/elasticsearch/elasticsearch:8.16.0` | 8.16.0 | 9200 (REST), 9300 (transport) | Log storage for Elastic Stack. X-Pack security disabled (lab only). |
| Kibana | `docker.elastic.co/kibana/kibana:8.16.0` | 8.16.0 | 5601 (web UI) | Visualization and dashboards. Connected to Elasticsearch. |

**Splunk credentials:** admin / [redacted]  
**Splunk HEC token:** test-token-12345 (lab only — not a real token)  
**Kibana:** No authentication (X-Pack security disabled)

**Docker volumes:**
- `splunk-var` — Splunk variable data (indexes, etc.)
- `splunk-etc` — Splunk configuration
- `elk-data` — Elasticsearch data (DNS logs, etc.)

**How to start the services:**

```bash
# Start Elasticsearch
docker run -d --name elasticsearch \
  -p 9200:9200 -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -v elk-data:/usr/share/elasticsearch/data \
  docker.elastic.co/elasticsearch/elasticsearch:8.16.0

# Start Kibana
docker run -d --name kibana \
  -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://elasticsearch:9200" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/kibana/kibana:8.16.0

# Start Splunk
docker run -d --name splunk \
  -p 8000:8000 -p 8088:8088 -p 8089:8089 \
  -e "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com" \
  -e "SPLUNK_START_ARGS=--accept-license" \
  -e "SPLUNK_PASSWORD=<set-password>" \
  -v splunk-var:/opt/splunk/var \
  -v splunk-etc:/opt/splunk/etc \
  splunk/splunk:latest
```

**Note:** Splunk management API (8089) and HEC (8088) were not reachable externally in this lab setup. Only the web UI (8000) was accessible. This is a known limitation of the Docker networking configuration.

---

## Virtual machines (libvirt/KVM)

VMs are defined but not currently running as of 2026-09-03. They are available for lab exercises when needed.

| VM | OS | Purpose |
|----|----|---------|
| Windows 10 endpoint | Windows 10 | Simulated user workstation for IR, detection engineering, and log generation |
| Kali Linux | Kali Linux | Attacker machine for attack simulation and Nmap scanning |
| Ubuntu scanner | Ubuntu | Nessus/OpenVAS vulnerability scanning host |
| pfSense (planned) | pfSense CE 2.7.x | Planned edge firewall — not deployed due to ISO download issues |

**VM management:** libvirt/KVM with virt-manager. VMs are defined as XML configurations under `/etc/libvirt/qemu/`.

---

## Tools installed on host

| Tool | Purpose |
|------|---------|
| Python 3 | Primary scripting language — all tools in `06-Python-Tools/` are Python |
| Docker | Container runtime for Splunk, Elasticsearch, Kibana |
| chromium (headless) | Screenshot capture — all screenshots in `screenshots/` were taken with `chromium --headless=new --screenshot` |
| Playwright (Python) | Browser automation for authenticated screenshots where needed |
| libvirt/KVM | Virtual machine management |
| Wireshark/tshark | Packet capture and analysis — `wireshark-capture-analysis.pcapng` was captured with tshark |
| Git | Version control — this repository |

---

## Data ingestion

**DNS logs:** 55 synthetic DNS events were ingested into Elasticsearch under the `dns-logs` index. These events include domains such as `evil-c2.example.com`, `malware-c2.evil.net`, `phish-domain.xyz`, `suspicious-drop.ru`, and `suspicious-dns-check.top` — domains that would trigger the C2 DNS detection rule (`malware-c2-alert.spl`).

**Windows Event Logs:** Not currently ingested. The lab plan includes Winlogbeat forwarding from the Windows 10 endpoint to Elasticsearch, but Winlogbeat is not currently running. The `winlogbeat-config.yml` file documents the intended configuration.

**Firewall logs:** The Zyxel gateway supports syslog export. Not currently configured for ingestion into the SIEM.

---

## Limitations and known issues

1. **Splunk API (8088/8089) not reachable externally.** Only the web UI (8000) is accessible. This limits programmatic alerting and HEC ingestion.
2. **pfSense VM not deployed.** ISO download from all mirrors failed. The Zyxel gateway serves as the real firewall device instead.
3. **Winlogbeat not running.** Windows event log ingestion into Elasticsearch is planned but not implemented.
4. **VMs not running.** The lab relies on Docker services for active demonstrations; VMs are available but not currently powered on.
5. **Kibana API not ready initially.** The Kibana setup wizard requires interactive completion. Screenshots were taken after the setup was completed.

---

## How to replicate

To replicate this lab from scratch:

1. Install Arch Linux with the same storage layout (3 disks: workstation, storage, bulk).
2. Install Docker and pull the three images (Splunk, Elasticsearch 8.16.0, Kibana 8.16.0).
3. Start the containers as shown above.
4. Ingest test DNS data into Elasticsearch (`dns-logs` index).
5. Install libvirt/KVM and define the VM configurations.
6. Clone this repository to `/mnt/workstation/LAB's/` (or your preferred path).
7. Take screenshots of running services using `chromium --headless=new --screenshot`.
8. Build and run the Python tools from `06-Python-Tools/`.
9. Use the Sigma and YARA rules from `03-Threat-Hunting/` as starting points for your own detection engineering.

---

## Next steps

- [ ] Deploy the pfSense VM when ISO download becomes possible (OPNsense is a viable alternative)
- [ ] Configure Winlogbeat on the Windows 10 endpoint and verify log forwarding
- [ ] Set up Zyxel syslog export to Elasticsearch
- [ ] Fix Splunk API reachability (8088/8089) for programmatic alerting
- [ ] Add a `docker-compose.yml` to simplify service startup
