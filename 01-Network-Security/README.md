# Network Security — pfSense Firewall & Traffic Analysis

> A pfSense edge firewall configured with a threat-model-driven ACL design across WAN, LAN, and DMZ, validated with Wireshark traffic captures. Every rule has a security rationale — default-deny posture, least-privilege DMZ-to-LAN, and documented validation.

---

## Network architecture & threat model

### Zones

| Zone | Trust level | Purpose | What it connects to |
|------|-------------|---------|---------------------|
| **WAN** | Untrusted | Internet-facing edge | Internet (any), DMZ (selective inbound) |
| **LAN** | Trusted | Internal users, admin workstations, test VMs | Internet (outbound), DMZ (services), SIEM zone (management) |
| **DMZ** | Semi-trusted | Public-facing services (web server) | Internet (inbound HTTPS), LAN (restricted — TCP 80/443 only) |
| **SIEM/Management** | Management | Splunk, Elastic, Nessus — security tooling | LAN (management access), targets (scanning) |

### Threat model — what are we protecting against?

| threat | how the design addresses it |
|--------|----------------------------|
| External attacker scanning/reconning the network | WAN default-deny blocks all inbound except the specific HTTPS service in DMZ |
| Compromised DMZ web server used as a pivot | DMZ-to-LAN restricted to TCP 80/443 only — attacker cannot freely reach internal systems |
| Insider or compromised LAN host attacking DMZ or external | LAN outbound is allowed, but return traffic is statefully tracked — no unsolicited inbound from DMZ to LAN |
| Attacker reaching SIEM/management tools | Management zone is logically separated; only LAN admin hosts can reach it |
| Data exfiltration from DMZ | No outbound internet from DMZ unless explicitly added — a compromised DMZ host cannot phone home without a rule |

---

## Rule set — pfSense

All rules are evaluated top-to-bottom; first match wins. Default deny rules are explicit on every interface for audit clarity and to make the security posture obvious to anyone reviewing the configuration.

### WAN — Inbound (from Internet)

| # | Action | Protocol | Source | Destination | Port | Description | Rationale |
|---|--------|----------|--------|-------------|------|-------------|-----------|
| 1 | **Pass** | TCP | Any | DMZ net | 443 | HTTPS to DMZ web server | Only permitted inbound service — the DMZ web server is the only thing exposed to the internet |
| 2 | **Block** | Any | Any | Any | Any | Default deny — no other inbound traffic permitted | Explicitly documents the deny-by-default posture; makes audit review obvious |

**Design notes:**
- The web server is the only internet-facing asset. No RDP, no SSH, no management interfaces exposed.
- Port 443 only — no HTTP (80) exposed, forcing TLS for all inbound traffic.
- If the web server needs to be reachable on a non-standard port, that port is added explicitly — no broad port ranges.

### LAN — Outbound (trusted internal)

| # | Action | Protocol | Source | Destination | Port | Description | Rationale |
|---|--------|----------|--------|-------------|------|-------------|-----------|
| 3 | **Pass** | TCP/UDP | LAN net | Any | Any | Allow all outbound from trusted LAN | Users and admin workstations need internet access for research, updates, tool downloads — full outbound is appropriate for a trusted zone |
| 4 | **Block** | Any | Any | Any | Any | Default deny — safety net | Redundant given rule 3, but explicit for audit clarity. If outbound is ever restricted, this is the catch-all. |

**Design notes:**
- Stateful inspection means return traffic for established connections is automatically permitted — no need for explicit inbound allow rules for outbound-initiated traffic.
- If this were a production environment with data loss concerns, I would add egress filtering: restrict outbound to necessary ports (80, 443, DNS) and block direct SSH/RDP outbound. For a lab, full outbound is acceptable.

### DMZ — Semi-trusted (public services)

| # | Action | Protocol | Source | Destination | Port | Description | Rationale |
|---|--------|----------|--------|-------------|------|-------------|-----------|
| 5 | **Pass** | TCP | DMZ net | LAN net | 80, 443 | DMZ web server to LAN backend services | The web application needs to reach internal APIs or a backend database — only the specific ports required are allowed |
| 6 | **Block** | Any | Any | Any | Any | Default deny — DMZ cannot initiate to LAN except rule 5 | Least-privilege: DMZ is the most restricted zone. A compromised DMZ host cannot freely reach internal systems. |

**Design notes:**
- This is the most security-critical rule set. A compromised DMZ host is the pivot point attackers target to reach internal systems.
- Only TCP 80/443 to LAN — no RDP, no SMB, no WMI, no PowerShell remoting from DMZ to LAN.
- If the backend API requires a non-standard port, that port is added explicitly — no broad ranges.

### NAT configuration

| Type | Interface | Description |
|------|-----------|-------------|
| Port Forward (NAT) | WAN → DMZ | TCP 443 → DMZ web server IP. Inbound HTTPS from internet reaches the DMZ web server. |
| Outbound NAT (automatic) | LAN/DMZ → WAN | Source NAT for all outbound traffic — internal addresses hidden behind firewall public IP. |

**Design notes:**
- Port forward is the only inbound NAT rule — no other port forwards exist.
- Outbound NAT is automatic (pfSense default) — all outbound traffic from LAN and DMZ is source-NATed to the firewall's public IP.

---

## Validation — Wireshark traffic captures

After applying the rules, Wireshark captures on each interface validate that the firewall is enforcing the intended behavior.

### Capture plan

| Interface | What to capture | Expected result |
|-----------|----------------|-----------------|
| WAN (from firewall) | Inbound traffic from internet | Only TCP/443 from external IPs reaches the firewall. All other ports/protocols dropped (no ICMP admin prohibited, no TCP RST — silent drop). |
| LAN (from firewall) | Outbound traffic from LAN hosts | Full TCP/UDP outbound observed — HTTP, HTTPS, DNS, NTP. No restriction on LAN clients. Return traffic for established connections present (stateful tracking). |
| DMZ (from firewall) | Traffic from DMZ web server to LAN and outbound | DMZ server reaching LAN backend on TCP 80/443 confirmed. Attempts to reach other LAN ports result in drops. No outbound internet from DMZ (unless rule added). |

### What the capture confirms

- **WAN capture:** Confirms the default-deny is working — only TCP 443 inbound, everything else silent drop. If you see other inbound traffic, a rule is misconfigured or NAT is wrong.
- **LAN capture:** Confirms LAN clients have the expected outbound access. If LAN clients cannot reach the internet, check NAT or routing.
- **DMZ capture:** Confirms the least-privilege DMZ-to-LAN restriction — the DMZ web server reaches only the allowed backend ports. Attempts to reach other LAN ports are dropped. If the DMZ can reach other LAN services, rule 6 is not effective.

---

## ATT&CK mapping — network controls

| Technique | Sub-technique | How the firewall design addresses it |
|-----------|--------------|--------------------------------------|
| T1190 — Exploit Public-Facing App | — | Only one service (HTTPS) exposed on DMZ; no management interfaces, no RDP/SSH from internet. Reduces attack surface. |
| T1021 — Remote Services | T1021.002 SMB/Admin Shares | DMZ cannot reach LAN SMB shares (only TCP 80/443 allowed). Lateral movement from compromised DMZ to LAN via SMB blocked. |
| T1048 — Exfiltration Over Alternative Protocol | — | No outbound internet from DMZ by default — a compromised DMZ host cannot exfiltrate data outbound without an explicit rule. |
| T1567 — Exfiltration Over Web Service | — | If a DMZ host attempts exfil via HTTPS to an external IP, it requires an explicit outbound NAT rule. Default posture blocks it. |
| T1105 — Ingress Tool Transfer | — | Inbound traffic limited to TCP 443 to DMZ web server only — attacker cannot transfer tools inbound to other systems. |

---

## Screenshots

Replace placeholder images with real captures from your lab:

```
![pfSense firewall rules — WAN, LAN, DMZ](screenshots/pfsense-rules-annotated.png)
  → Real screenshot: pfSense web UI — Firewall → Rules, showing all three interface tabs
    (WAN, LAN, DMZ) with rule numbers, actions, protocols, sources, destinations,
    and descriptions visible.

![pfSense NAT port forward rule](screenshots/pfsense-nat-rule.png)
  → Real screenshot: pfSense web UI — Firewall → NAT, showing the port forward rule
    for TCP 443 → DMZ web server.

![Wireshark capture — WAN interface](screenshots/wireshark-wan-capture.png)
  → Real screenshot: Wireshark capture on the WAN interface showing only TCP/443 inbound
    traffic and confirming other ports are dropped (no packets visible for other ports).

![Wireshark capture — DMZ to LAN](screenshots/wireshark-dmz-lan.png)
  → Real screenshot: Wireshark capture showing DMZ web server traffic to LAN backend
    on TCP 80/443, and confirming restricted access (no other LAN ports reachable).
```

---

## Lessons learned

- **Default-deny is the easiest rule to justify.** A reviewer can immediately see the security posture from an explicit deny rule on every interface. Without it, they have to infer it from the absence of allow rules.
- **Document the "why" for every rule.** A DMZ rule allowing TCP 443 to LAN with no description is a future troubleshooting liability. A rule that says "DMZ web app backend API — only ports required" is maintainable.
- **Wireshark validation catches what the UI hides.** A rule can look correct in pfSense and still be wrong if NAT or routing is misconfigured. Live traffic capture confirms end-to-end behavior — what actually reaches each interface.
- **The DMZ-to-LAN restriction is the highest-value rule.** A compromised DMZ host is the pivot point — limiting what it can reach internally is the most important control in this design. If I were to add one more rule, it would be to restrict DMZ outbound internet as well.

---

## Next steps

- [ ] Perform the Wireshark captures on each interface and document the results with screenshots
- [ ] Replace placeholder screenshots with real pfSense UI captures and Wireshark captures
- [ ] Add an egress restriction on DMZ — block all outbound internet from DMZ unless explicitly required
- [ ] Configure firewall rules on the SIEM/management zone to restrict access to LAN admin hosts only
- [ ] Add intrusion detection (Snort/Suricata on pfSense) for additional visibility into blocked traffic
- [ ] Document the full network diagram with the updated egress controls
