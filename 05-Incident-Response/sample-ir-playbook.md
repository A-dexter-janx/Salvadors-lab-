# Incident Response Playbook
## IR Lab: Sample Incident Response Procedure

### Incident Type: Ransomware Infection

### Phase 1: Preparation
- **IR Team:** SOC analyst, incident commander, forensic examiner
- **Tools:** Forensic imaging software, memory analysis tools, network capture
- **Contacts:** CISO, legal, PR, insurance

### Phase 2: Identification
| Step | Action | Owner | Time |
|------|--------|-------|------|
| 1 | Alert triggered by EDR/AV detecting ransomware | SOC | T+0 |
| 2 | Confirm false positive or true infection | SOC | T+15m |
| 3 | Determine scope: how many systems affected | IR Lead | T+30m |
| 4 | Classify severity (Critical/High/Medium/Low) | IR Lead | T+45m |

### Phase 3: Containment
- **Short-term:** Isolate affected systems from network (pull cable, disable switch port)
- **Long-term:** Reset compromised credentials, block C2 IPs at firewall
- **Evidence preservation:** Capture memory dump, disk image before remediation

### Phase 4: Eradication
- Remove malware binaries and persistence mechanisms
- Rebuild affected systems from clean images
- Apply missing security patches

### Phase 5: Recovery
- Restore data from clean backups
- Bring systems back online with monitoring
- Verify normal operations

### Phase 6: Lessons Learned
- Document timeline of events
- Identify gaps in detection/response
- Update playbooks and controls
- Conduct tabletop exercise for similar scenarios

### Artifacts Collected
- Memory dump (RAM)
- Disk image (dd/FTK Imager)
- Network PCAP during incident window
- EDR/AV alert logs
- System event logs
