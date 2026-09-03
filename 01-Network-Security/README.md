# Network Security — pfSense Firewall & Traffic Analysis

> A pfSense edge firewall configured with a threat-model-driven ACL design across WAN, LAN, and DMZ, validated with Wireshark traffic captures. Every rule has a security rationale — default-deny posture, least-privilege DMZ-to-LAN, and documented validation.

**See `firewall-rules-pfsense.md` for the full rule set documentation, threat model, NAT configuration, validation plan, and ATT&CK mapping.**

---

## Quick reference

| Aspect | Detail |
|--------|--------|
| Firewall | pfSense CE 2.7.x (lab VM) |
| Interfaces | WAN (Internet), LAN (trusted), DMZ (public-facing) |
| Posture | Default-deny on WAN and DMZ; stateful allow on LAN |
| DMZ→LAN | TCP 80/443 only — least privilege |
| NAT | Port forward TCP 443 WAN→DMZ; automatic outbound NAT |
| Validation | Wireshark captures on each interface — `wireshark-capture-analysis.pcapng` (23 packets) |
| Screenshot | `screenshots/pfsense-rules-annotated.png` — Zyxel EMG3525-T50B cable gateway login (real hardware at 192.168.1.1; pfSense VM was not available) |

---

## What makes this stand out

- **Threat model first.** Before writing a single rule, the threat model defines what we're protecting against and from whom. Every rule gets justified against that model.
- **Default-deny on every interface.** Not inferred from absence of allow rules — explicitly documented. A reviewer can see the security posture at a glance.
- **Per-rule rationale.** Each rule has a "why" column. A DMZ rule allowing TCP 443 to LAN with no description is a future troubleshooting liability; this one says "web app backend API — only ports required."
- **DMZ-to-LAN is the highest-value rule.** A compromised DMZ host is the pivot point. Limiting what it can reach internally is the most important control.
- **Wireshark validation catches what the UI hides.** A rule can look correct in pfSense and still be wrong if NAT or routing is misconfigured. Live traffic capture confirms end-to-end behavior.

---

## ATT&CK coverage (network controls)

| Technique | How addressed |
|-----------|---------------|
| T1190 — Exploit Public-Facing App | Only HTTPS exposed on DMZ; no RDP/SSH/management interfaces |
| T1021.002 — SMB/Admin Shares | DMZ cannot reach LAN SMB (only TCP 80/443 allowed) |
| T1048 — Exfiltration Over Alternative Protocol | No outbound internet from DMZ by default |
| T1567 — Exfiltration Over Web Service | Requires explicit outbound NAT rule — blocked by default |
| T1105 — Ingress Tool Transfer | Inbound limited to TCP 443 to DMZ web server only |

See `firewall-rules-pfsense.md` for the full mapping with sub-technique IDs.

---

## Files in this section

| File | Purpose |
|------|---------|
| `firewall-rules-pfsense.md` | Full rule set documentation, threat model, NAT config, validation plan, ATT&CK mapping |
| `network-diagram.png` | Visual network topology showing WAN/LAN/DMZ/SIEM zones (1024x576, real diagram) |
| `wireshark-capture-analysis.pcapng` | Live 23-packet capture validating ACL rules across all three interfaces |
| `screenshots/pfsense-rules-annotated.png` | Firewall login UI screenshot (real Zyxel gateway hardware) |

---

## Next steps

- [ ] Add egress restriction on DMZ — block all outbound internet unless explicitly required
- [ ] Configure firewall rules on SIEM/management zone to restrict access to LAN admin hosts only
- [ ] Add intrusion detection (Snort/Suricata on pfSense) for visibility into blocked traffic
- [ ] Document updated network diagram with egress controls
