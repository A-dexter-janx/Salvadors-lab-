# Firewall Rules — pfSense

Lab: Network Security Fundamentals — documenting and analyzing firewall rule sets on a pfSense edge firewall to demonstrate understanding of network segmentation, ACL design principles, and traffic control policies.

---

## Objective

Capture the firewall rule set configured on a pfSense CE 2.7.x appliance managing three interfaces (WAN, LAN, DMZ). Document each rule with its purpose, traffic flow, and security rationale. Validate the configuration through live packet capture and demonstrate that the rules enforce the intended segmentation.

---

## Environment

| Component | Detail |
|-----------|--------|
| Firewall | pfSense CE 2.7.x |
| Interfaces | WAN (isp), LAN (trusted), DMZ (public-facing) |
| Rule set | Custom ingress and egress ACLs per interface |
| Validation tool | Wireshark / tshark for traffic capture |
| Network context | Home-lab with Kali Linux, Windows 10 VM, DMZ web server |

---

## Rule Set

### WAN — Inbound (Internet-facing)

| # | Action | Protocol | Source | Destination | Port | Description |
|---|--------|----------|--------|-------------|------|-------------|
| 1 | **Block** | Any | Any | Any | Any | Default deny all inbound from WAN — explicit last rule, no exceptions |
| 2 | **Pass** | TCP | Any | DMZ net | 443 | Allow HTTPS inbound to DMZ web server — only permitted inbound service |

> WAN policy: deny-by-default. Only the DMZ HTTPS service is reachable from the internet. All other inbound traffic is silently dropped.

### LAN — Outbound (Trusted internal)

| # | Action | Protocol | Source | Destination | Port | Description |
|---|--------|----------|--------|-------------|------|-------------|
| 3 | **Pass** | TCP/UDP | LAN net | Any | Any | Allow all outbound from trusted LAN — users and management stations need full internet access |
| 4 | **Block** | Any | Any | Any | Any | Default deny as safety net — redundant given rule 3's allow, but explicit for audit clarity |

> LAN policy: allow outbound with stateful inspection. Return traffic for established connections is automatically permitted by pfSense's state table. No LAN-to-DMZ restrictions — trusted zone can reach DMZ services.

### DMZ — Semi-trusted (Public services)

| # | Action | Protocol | Source | Destination | Port | Description |
|---|--------|----------|--------|-------------|------|-------------|
| 5 | **Pass** | TCP | DMZ net | LAN net | 80/443 | Allow DMZ web server to reach backend LAN services — web app needs to query internal APIs/database |
| 6 | **Block** | Any | Any | Any | Any | Default deny — DMZ cannot initiate connections to LAN except the explicit rule above |

> DMZ policy: most-restrictive. DMZ hosts can only reach specific LAN services needed for application function. No outbound internet from DMZ unless explicitly required (not configured in this lab).

---

## NAT Configuration

| Type | Interface | Description |
|------|-----------|-------------|
| Port Forward | WAN → DMZ | TCP 443 → DMZ web server IP — inbound HTTPS from internet reaches the DMZ web server |
| Outbound NAT | LAN/DMZ → WAN | Source NAT for all outbound traffic — hid internal addresses behind firewall public IP |

---

## Security Design Notes

- **Default deny** is enforced on WAN and DMZ. No implicit allow anywhere on untrusted interfaces.
- **Stateful inspection** enabled on LAN rules — connection tracking ensures only established/related return traffic is permitted.
- **Least privilege** on DMZ → LAN — only the specific TCP ports needed by the web application can traverse from DMZ to backend.
- **No DMZ→Internet** outbound in this lab — DMZ hosts cannot phone home to C2 or download additional payloads without an explicit rule.

---

## Traffic Validation (Wireshark)

After applying rules, captured traffic on each interface to validate expected behavior:

1. **WAN capture:** Confirmed only TCP 443 reaches the firewall from internet — all other ports/protocols dropped silently (no ICMP admin prohibited, no TCP RST).
2. **LAN capture:** Full outbound TCP/UDP observed — HTTP, HTTPS, DNS, NTP all passing. No restriction on LAN clients.
3. **DMZ capture:** DMZ web server reaching LAN backend on TCP 80/443 confirmed. Attempts to reach other LAN ports resulted in drops.

---

## Screenshots

```