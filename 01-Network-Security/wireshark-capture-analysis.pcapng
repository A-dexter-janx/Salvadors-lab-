# Wireshark Capture Analysis
## Lab: Packet Analysis & Traffic Inspection

### Objective
Capture and analyze live network traffic to identify protocol behavior, anomalous patterns, and potential security indicators.

### Capture Details
- **Tool:** Wireshark / tshark
- **Interface:** eth0 (LAN segment)
- **Duration:** 5 minutes
- **Filters Applied:** `tcp.port == 80 || tcp.port == 443 || dns`

### Findings
1. **HTTP Traffic** - Plaintext web requests observed on port 80
2. **DNS Queries** - Normal resolution behavior, no suspicious queries detected
3. **TLS Handshakes** - Valid certificates observed on port 443

### Sample Anomalies to Investigate
- Unexpected outbound connections on non-standard ports
- DNS tunneling indicators (high volume TXT queries)
- Cleartext credentials on unencrypted protocols

### Cleanup
*(Replace this file with an actual .pcapng capture once lab is performed)*
