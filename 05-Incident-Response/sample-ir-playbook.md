# Incident Response Playbook — Ransomware Infection

Lab: Incident Response — a sample IR playbook aligned to NIST SP 800-61 Rev 2 (Computer Security Incident Handling Guide), covering the full incident response lifecycle for a ransomware event.

---

## Incident Overview

| Attribute | Detail |
|-----------|--------|
| Incident type | Ransomware infection |
| Severity | Critical |
| NIST alignment | SP 800-61 Rev 2 — Preparation, Detection & Analysis, Containment/Eradication/Recovery, Post-Incident Activity |
| Trigger | EDR/AV alert — ransomware behavior detected on endpoint |
| Scope | Single host initially, potential lateral spread under investigation |

---

## Phase 1: Preparation (Pre-incident)

Activities performed before any incident to ensure readiness.

- **IR team identified:**
  - SOC Analyst (first responder — alert triage)
  - Incident Commander (coordination, decision-making)
  - Forensic Examiner (evidence collection, timeline reconstruction)
  - IT/System Admin (system isolation, restoration)
- **Tools ready:**
  - Forensic imaging: FTK Imager, dd, Velociraptor
  - Memory analysis: Volatility 3, Rekall
  - Network capture: Wireshark, tcpdump, NetFlow logs
  - EDR console access for host isolation and log retrieval
- **Contact list established:**
  - CISO — executive escalation
  - Legal — regulatory notification assessment (data breach implications)
  - PR/Comms — external messaging if needed
  - Cyber insurance — notification and claim initiation
- **Playbooks reviewed:** ransomware, credential theft, data exfiltration

---

## Phase 2: Identification & Detection

Determine whether the alert is a true positive and characterize the incident.

| Step | Action | Owner | Target Time |
|------|--------|-------|-------------|
| 1 | EDR/AV alert received — ransomware behavior detected (file encryption, ransom note creation) | SOC Analyst | T+0 min |
| 2 | Triage: confirm true positive vs. false positive — review alert details, process tree, affected files | SOC Analyst | T+15 min |
| 3 | Scope assessment: how many hosts affected? Any lateral movement indicators? Check EDR for similar activity on peer hosts | IR Lead / SOC | T+30 min |
| 4 | Severity classification: Critical (active encryption, potential data loss, possible lateral spread) | IR Lead | T+45 min |
| 5 | Declare incident — notify Incident Commander, activate full IR team | IR Lead | T+45 min |

**Decision point:** If confirmed ransomware with active encryption — escalate immediately to Phase 3 Containment. Do not wait for full forensic analysis before isolating.

---

## Phase 3: Containment

Stop the incident from spreading and preserve evidence.

### Short-term Containment (immediate)

- **Isolate affected host(s):** Disable switch port or pull network cable. If EDR supports remote isolation, use it (quarantine host from network while maintaining EDR telemetry).
- **Block known indicators:** Add C2 IPs, domains, and file hashes to firewall/proxy blocklist immediately.
- **Stop spread:** Check for lateral movement indicators — PsExec, WMI, RDP sessions from affected host to others. If found, isolate those hosts too.

### Long-term Containment

- Reset all credentials that were on the affected host (local admin, domain accounts that logged in)
- Block C2 infrastructure at perimeter firewall and DNS sinkhole
- Disable compromised service accounts
- Review and rotate any API keys or tokens stored on the affected system

### Evidence Preservation

**Critical:** Capture evidence before remediation. Once the system is wiped, evidence is lost.

- Memory dump (RAM) using FTK Imager or Volatility-compatible tool — captures ransomware process, encryption keys in memory, network connections
- Disk image (forensic copy) via dd or FTK Imager — full disk for later timeline analysis
- Network PCAP of traffic during incident window (if capture was running)
- EDR/AV alert logs — export full alert with process tree, file activity, and network events
- System event logs (Security, System, Application) — export pre-incident and incident window
- Ransom note and any dropped files — photograph screen, copy files to evidence store

> **Chain of custody:** Log who collected each artifact, when, from where, and how. Label all evidence with incident ID, host name, collection timestamp.

---

## Phase 4: Eradication

Remove the threat from the environment.

- Remove malware binaries, scripts, and dropped files from affected systems
- Remove persistence mechanisms:
  - Registry Run keys (`HKLM\...\Run`, `HKCU\...\Run`)
  - Scheduled tasks
  - Startup folder entries
  - WMI event subscriptions
  - Services created by attacker
- Rebuild affected systems from known-clean images or fresh OS installation — do not trust a compromised OS to be "cleaned" in place for a Critical incident
- Apply all missing security patches (especially those that may have been the initial entry vector)
- Verify backups are clean (ransomware may have encrypted or infected backup targets)

---

## Phase 5: Recovery

Return systems to normal operations safely.

- Restore data from clean, verified backups — validate backup integrity before restore
- Bring systems back online one at a time with full monitoring enabled (EDR, logging, network detection)
- Verify normal operations — applications functioning, users able to work, no residual malicious activity
- Monitor closely for 48–72 hours post-recovery for any signs of re-infection or persistence
- Communicate recovery status to stakeholders (IR Commander → CISO → affected teams)

---

## Phase 6: Post-Incident Activity (Lessons Learned)

- **Document the full timeline** from initial alert to recovery completion
- **Root cause analysis:** How did the attacker get in? (Phishing? Unpatched vulnerability? Exposed RDP? Weak credentials?)
- **Identify gaps:**
  - Detection: How long was the attacker present before detection? Can we detect faster?
  - Response: Were containment actions timely? Did we have the right tools?
  - Prevention: What control would have prevented this? (MFA? Patching? Network segmentation? Email filtering?)
- **Update playbooks** with lessons learned — what worked, what didn't
- **Conduct tabletop exercise** for similar scenario to validate improvements
- **Reports:** Internal incident report (technical), executive summary (CISO/leadership), legal/regulatory notification if required

---

## Artifacts Collected (checklist)

During this incident, the following were collected:

| Artifact | Tool | Collected? |
|----------|------|-----------|
| Memory dump (RAM) | FTK Imager / Volatility | ☐ |
| Disk image (forensic) | FTK Imager / dd | ☐ |
| Network PCAP (incident window) | Wireshark / tcpdump | ☐ |
| EDR alert with full process tree | EDR console export | ☐ |
| System event logs (Security, System, Application) | Event Viewer export / wevtutil | ☐ |
| Ransom note (photo + file copy) | Camera + file copy | ☐ |
| Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT) | FTK Imager | ☐ |
| Prefetch files | Copy from C:\Windows\Prefetch | ☐ |
| Shimcache / Amcache | Volatility / Kape | ☐ |
| Browser history and downloads | Browser export / Kape | ☐ |

---

## NIST SP 800-61 Alignment

| NIST Phase | This Playbook Section |
|------------|----------------------|
| Preparation | Phase 1 (Preparation) |
| Detection & Analysis | Phase 2 (Identification) |
| Containment, Eradication & Recovery | Phase 3 (Containment), Phase 4 (Eradication), Phase 5 (Recovery) |
| Post-Incident Activity | Phase 6 (Lessons Learned) |

---

## Screenshots

Replace placeholders with real captures from your lab exercise:

```
![EDR alert — ransomware detected](screenshots/edr-ransomware-alert.png)
![Isolated host in EDR console](screenshots/edr-isolated-host.png)
![Ransom note on affected system](screenshots/ransom-note.png)
```

---

## Next Steps

- [ ] Run a tabletop ransomware exercise using this playbook
- [ ] Document a real or simulated incident timeline
- [ ] Capture EDR screenshots showing alert and containment actions
- [ ] Add additional playbooks: phishing response, DDoS mitigation, insider threat, business email compromise
