# Firewall Rules - pfSense
## Lab: Network Security Fundamentals

### Objective
Document and analyze firewall rules configured on a pfSense edge firewall to understand network segmentation, ACL design, and traffic control.

### Environment
- **Firewall:** pfSense CE 2.7.x
- **Interfaces:** WAN, LAN, DMZ
- **Rules:** Custom ingress/egress ACLs

### Rule Set Overview

| Rule # | Interface | Action | Protocol | Source | Destination | Description |
|--------|-----------|--------|----------|--------|-------------|-------------|
| 1 | WAN | Block | Any | Any | Any | Default deny inbound |
| 2 | LAN | Pass | TCP/UDP | LAN net | Any | Allow outbound |
| 3 | DMZ | Pass | TCP | DMZ net | LAN | Web server to backend |
| 4 | WAN | Pass | TCP | Any | DMZ | HTTPS (port 443) |

### Notes
- Default deny policy enforced on WAN
- Stateful inspection enabled on LAN rules
- NAT configured for DMZ web server

### Screenshots
*(Add annotated screenshots of pfSense rule editor here)*
