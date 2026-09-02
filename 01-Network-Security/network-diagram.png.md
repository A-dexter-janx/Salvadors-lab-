# Network Diagram
## Lab: Network Segmentation & Architecture

### Description
Visual representation of the lab network topology showing segmentation between WAN, LAN, DMZ, and management interfaces.

### Components
- **Firewall:** pfSense (edge)
- **Router:** Internal routing between segments
- **Managed Switch:** VLAN segmentation
- **Endpoints:** Kali Linux, Windows 10 VM, Splunk server

### Zones
| Zone | Purpose | Access Level |
|------|---------|--------------|
| WAN | Internet-facing | External |
| DMZ | Public services | Restricted inbound |
| LAN | Internal users | Trusted |
| MGMT | Admin access | Isolated |

*(Insert network_diagram.png screenshot here)*
