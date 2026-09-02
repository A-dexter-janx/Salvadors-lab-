# Incident Response — Ransomware Playbook, Forensic Timeline & Malware Analysis

> Three IR deliverables: a full NIST SP 800-61 ransomware playbook covering all six phases, a forensic timeline reconstruction from Windows artifacts showing a suspected data exfiltration, and a malware analysis report with static and dynamic analysis plus extracted IOCs.

---

## 1. Incident Response Playbook — Ransomware Infection

### Overview

| Attribute | Detail |
|-----------|--------|
| Incident type | Ransomware infection |
| Severity | Critical |
| Framework | NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide |
| Phases | Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity |
| Trigger | EDR/AV alert — ransomware behavior (file encryption, ransom note creation) |
| Scope | Single host initially; lateral spread under investigation |

### Phase 1 — Preparation (pre-incident)

Readiness activities established before any incident.

**Team & roles:**
- SOC Analyst — first responder, alert triage
- Incident Commander — coordination, decision-making, escalation
- Forensic Examiner — evidence collection, timeline reconstruction
- IT/System Admin — host isolation, restoration, rebuild

**Tools ready:**
- Forensic imaging: FTK Imager, dd, Velociraptor
- Memory analysis: Volatility 3
- Network capture: Wireshark, tcpdump, NetFlow logs
- EDR console — host isolation, log export, process tree view

**Contacts established:**
- CISO — executive escalation
- Legal — regulatory notification assessment
- PR/Comms — external messaging if required
- Cyber insurance — notification and claim initiation

**Playbooks reviewed:** ransomware, credential theft, data exfiltration, business email compromise

### Phase 2 — Identification & Detection

Determine true positive vs. false positive and characterize the incident.

| Step | Action | Owner | Target time |
|------|--------|-------|-------------|
| 1 | EDR/AV alert — ransomware behavior detected (file encryption, ransom note) | SOC Analyst | T+0 min |
| 2 | Triage: confirm true positive vs. false positive — review process tree, file activity, alert details | SOC Analyst | T+15 min |
| 3 | Scope: how many hosts affected? Lateral movement indicators? Check EDR for similar activity on peer hosts | IR Lead / SOC | T+30 min |
| 4 | Severity classification: Critical (active encryption, potential data loss, possible lateral spread) | IR Lead | T+45 min |
| 5 | Declare incident — notify Incident Commander, activate full IR team | IR Lead | T+45 min |

**Decision point:** If confirmed ransomware with active encryption — escalate to Phase 3 Containment immediately. Do not wait for full forensic analysis before isolating.

### Phase 3 — Containment

Stop the spread and preserve evidence.

**Short-term containment (immediate):**
- Isolate affected host(s) — disable switch port or pull cable. If EDR supports remote isolation, use it (quarantine from network, maintain EDR telemetry).
- Block known indicators — C2 IPs, domains, and file hashes at firewall/proxy blocklist immediately.
- Check for lateral movement — PsExec, WMI, RDP sessions from affected host to others. If found, isolate those hosts too.

**Long-term containment:**
- Reset all credentials on the affected host (local admin, domain accounts that logged in)
- Block C2 infrastructure at perimeter firewall and DNS sinkhole
- Disable compromised service accounts
- Review and rotate API keys/tokens stored on the affected system

**Evidence preservation — before remediation:**
- Memory dump (RAM) — FTK Imager or Volatility-compatible tool. Captures ransomware process, encryption keys in memory, active network connections.
- Disk image (forensic copy) — dd or FTK Imager. Full disk for timeline analysis.
- Network PCAP during incident window (if capture was running).
- EDR/AV alert logs — export with process tree, file activity, network events.
- System event logs — Security, System, Application — export pre-incident and incident window.
- Ransom note and dropped files — photograph screen, copy files to evidence store.

> Chain of custody: log who collected each artifact, when, from where, and how. Label all evidence with incident ID, host name, collection timestamp.

### Phase 4 — Eradication

Remove the threat from the environment.

- Remove malware binaries, scripts, and dropped files
- Remove persistence:
  - Registry Run keys (`HKLM\...\Run`, `HKCU\...\Run`)
  - Scheduled tasks
  - Startup folder entries
  - WMI event subscriptions
  - Services created by attacker
- Rebuild affected systems from known-clean images or fresh OS install — do not trust a compromised OS to be cleaned in place for a Critical incident
- Apply all missing security patches (especially those that may have been the initial entry vector)
- Verify backups are clean — ransomware may have encrypted or infected backup targets

### Phase 5 — Recovery

Return systems to normal operations safely.

- Restore data from clean, verified backups — validate backup integrity before restore
- Bring systems online one at a time with full monitoring (EDR, logging, network detection)
- Verify normal operations — applications functioning, users able to work, no residual malicious activity
- Monitor closely for 48–72 hours post-recovery for re-infection or persistence
- Communicate recovery status to stakeholders (IR Commander → CISO → affected teams)

### Phase 6 — Post-Incident Activity (Lessons Learned)

- Document the full timeline from initial alert to recovery completion
- Root cause analysis: How did the attacker get in? (Phishing? Unpatched vuln? Exposed RDP? Weak credentials?)
- Identify gaps:
  - Detection: How long was the attacker present before detection? Can we detect faster?
  - Response: Were containment actions timely? Did we have the right tools?
  - Prevention: What control would have prevented this? (MFA? Patching? Segmentation? Email filtering?)
- Update playbooks with lessons learned
- Conduct tabletop exercise for similar scenario to validate improvements
- Reports: internal incident report (technical), executive summary (CISO/leadership), legal/regulatory notification if required

### ATT&CK mapping — ransomware playbook

| Phase | Technique | Sub-technique | How covered |
|-------|-----------|---------------|-------------|
| Phase 2 | T1486 | Data Encrypted for Impact | Detected by EDR/AV — file encryption activity triggers alert |
| Phase 2 | T1485 | Data Destruction | Ransomware encryption is a form of data destruction — detected |
| Phase 3 | T1021 | Remote Services | Lateral movement check — PsExec, WMI, RDP from affected host |
| Phase 3 | T1071.001 | Web Protocols (C2) | C2 IP/domain blocking during containment |
| Phase 4 | T1547 | Boot or Logon Autostart Execution | Persistence removal — Run keys, scheduled tasks, WMI subscriptions |
| Phase 6 | T1595 | Active Scanning | Root cause — how did attacker find/reach the victim? |

---

## 2. Forensic Timeline — Suspected Data Exfiltration

### Scenario

A user's workstation (Windows 10) triggered a SOC alert for anomalous outbound HTTPS traffic — 50+ MB transferred to an unknown external IP within a short window. This timeline reconstructs what happened on the endpoint before, during, and after the alert, from Windows forensic artifacts.

### Timeline (UTC)

| Time (UTC) | Event | Artifact Source | Key Evidence |
|------------|-------|----------------|--------------|
| 2026-08-15 09:12:00 | User Mary logged into workstation normally (interactive logon) | Security Log Event ID 4624 (Logon Type 2) | Successful logon, no anomalies |
| 2026-08-15 09:15:30 | USB storage device connected to the workstation | SetupLog Event ID 2003 (Driver loaded) + USBSTOR registry key | Device ID, vendor, first connection time recorded |
| 2026-08-15 09:16:00 | Large file copy from Documents folder to USB drive | Shellbags (CSB) + MRU registry + file system $MFT access times | File path, file size, access time on mounted USB |
| 2026-08-15 09:20:00 | Suspicious PowerShell process spawned by user context | Sysmon Event ID 1 (Process Create) + EDR telemetry | Command line: base64-encoded payload, `-WindowStyle Hidden` |
| 2026-08-15 09:20:05 | PowerShell executed encoded command — decoded to outbound HTTPS to external IP with data payload | PowerShell Script Block Logging Event ID 4104 + transcript logs | Decoded command shows data staging and exfil POST request |
| 2026-08-15 09:21:00 | Outbound HTTPS connection to unknown external IP (185.220.101.45) — 50+ MB transferred in 60 seconds | Firewall log + NetFlow | Source: workstation, Dest: 185.220.101.45:443, bytes: 52,341,234 |
| 2026-08-15 09:21:05 | Data exfiltration likely complete — volume and timing consistent with bulk transfer | Network flow analysis | Sustained high-volume HTTPS, no normal user browsing pattern |
| 2026-08-15 09:25:00 | User locked workstation (Win+L) — appears normal, exfil already complete | Security Log Event ID 4800 (Workstation locked) | Routine action, no sign of user awareness |
| 2026-08-15 10:00:00 | SOC alert generated — anomalous outbound traffic threshold exceeded | Splunk alert — NetFlow data | 50+ MB to single external IP in under 2 minutes flagged |
| 2026-08-15 10:05:00 | SOC analyst begins investigation — identifies workstation, user, exfil pattern | SOC ticket | Investigation started |

### Key investigative questions

1. **Was the user aware of the exfiltration?**
   - PowerShell was spawned in the user's context with `-WindowStyle Hidden` — the window was hidden, so the user may not have seen anything unusual on screen.
   - The user locked the workstation at 09:25 without apparent concern — consistent with either unawareness or premeditation.

2. **Was the USB device authorized?**
   - USBSTOR shows the device was connected for the first time at 09:15:30 — no previous connection in registry history.
   - Device vendor/ID should be checked against authorized device list.
   - If unauthorized, this is a policy violation in addition to the exfiltration.

3. **What data was exfiltrated?**
   - Shellbags and MRU show which files were accessed on the USB drive before the PowerShell execution.
   - Correlate file access times with the PowerShell execution time to identify likely exfiltrated files.
   - 50+ MB transferred — consistent with documents, spreadsheets, or a small folder.

4. **Did the PowerShell command achieve its intent?**
   - Event ID 4104 (script block logging) captures the decoded command — confirms intent to exfiltrate data via HTTPS POST.
   - Firewall logs confirm the data left the network — the command worked.

### Forensic artifacts examined

| Artifact | What it tells us | Tool |
|----------|----------------|------|
| Security Log (EVTX) | Logon/logoff, object access, privilege use — authenticates timeline of user actions | Event Viewer, EvtxECmd, Kape |
| USBSTOR Registry Key | Every USB device ever connected — serial, vendor, first/last connection times | Registry Explorer, RegRipper |
| Shellbags (CSB) | User's folder browse history — which folders/files were accessed, even if not copied | ShellBags Explorer, KAPE |
| MRU Registry Keys | Most Recently Used file lists — documents recently opened/accessed | Registry Explorer |
| $MFT (Master File Table) | File creation/modification/access times (though MAC times can be manipulated) | MFTECmd, Autopsy |
| Sysmon Event ID 1 | Process creation with command line — captures the suspicious PowerShell execution | Sysmon archive, EDR |
| PowerShell Event ID 4104 | Script block logging — the actual decoded PowerShell command executed | PowerShell log archive |
| Firewall/NetFlow Logs | Network traffic volume, source/dest, ports — confirms exfiltration | Firewall logs, NetFlow collector, Splunk |
| Prefetch Files | Program execution evidence with timestamps — confirms PowerShell was run | Prefetch Explorer, PECmd |
| Browser History | If files sent via web upload — check for uploads to cloud storage | Chrome/Edge/Firefox history export |

### Analysis approach

1. **Correlate timestamps** — align all artifacts on a single UTC timeline. Look for gaps or inconsistencies.
2. **Establish baseline** — what does "normal" look like for this user/host? Compare against historical patterns if available.
3. **Identify anomalies** — new USB device, encoded PowerShell, large outbound transfer, unusual destination IP.
4. **Build the narrative** — USB insertion → file access → PowerShell execution → data exfil → SOC alert.
5. **Assess intent** — the hidden PowerShell window and locked workstation after exfil suggest premeditation. But it could also be an attacker using the user's session without their knowledge.

### ATT&CK mapping — forensic timeline

| Technique | Sub-technique | Evidence in timeline |
|-----------|--------------|---------------------|
| T1059.001 | Command and Scripting Interpreter: PowerShell | Sysmon Event ID 1 + PowerShell Event ID 4104 — encoded PowerShell execution |
| T1071.001 | Application Layer Protocol: Web Protocols | Firewall log — HTTPS to external IP, 50+ MB transferred |
| T1074 | Data Staged | Shellbags + MRU + $MFT — files copied to USB before exfil |
| T1052 | Exfiltration Over Physical Medium | USB device connection + file copy to USB — data staged on removable media |
| T1020 | Automated Exfiltration | PowerShell script performing automated HTTPS exfil POST |
| T1072 | Software Deployment Tools | PowerShell used as execution tool for exfiltration |

---

## 3. Malware Analysis Report — Static & Dynamic Analysis

### Sample information

| Attribute | Detail |
|-----------|--------|
| File name | suspicious_file.exe |
| File size | 245 KB |
| SHA256 | a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 |
| MD5 | d41d8cd98f00b204e9800998ecf8427e |
| Submission date | 2026-09-02 |
| Analyst | Salvador Janthan |
| Analysis environment | REMnux / FlareVM sandbox — isolated, no production network access |

### Static analysis

#### Strings identified

| String | Context | Significance |
|--------|---------|--------------|
| `cmd.exe /c` | Command shell execution | Common malware behavior — launching commands or download cradles |
| `powershell -w hidden` | Hidden PowerShell window | Obfuscation — hiding execution from the user |
| `-enc` | Encoded command argument | Obfuscation — base64-encoded PowerShell commands |
| `http://malicious-c2.example.com` | C2 communication URI | Command-and-control channel |
| `CreateRemoteThread` | Process injection API | Code injection into another process |
| `VirtualAllocEx` | Memory allocation API | Preparation for code injection |
| `WriteProcessMemory` | Memory write API | Writing injected code into target process |
| `vssadmin delete shadows` | Shadow copy deletion | Ransomware behavior — prevents data recovery |
| `bypass UAC` | UAC bypass attempt | Privilege escalation — gaining elevated rights |

#### Imports

| DLL | Functions imported | Significance |
|-----|-------------------|--------------|
| kernel32.dll | VirtualAlloc, WriteProcessMemory, CreateRemoteThread, VirtualFree | Memory manipulation and process injection — classic malware behavior |
| user32.dll | FindWindow, SendMessage | Window manipulation — may be used for UI interaction or hiding |
| wininet.dll | InternetOpen, HttpOpenRequest, HttpSendRequest, InternetReadFile | HTTP communication — C2 or download cradle |
| advapi32.dll | RegOpenKeyEx, RegSetValueEx | Registry manipulation — persistence or configuration |

#### PE section analysis

| Section | Size | Entropy | Assessment |
|---------|------|---------|------------|
| .text | 40,960 bytes | 6.2 | Normal executable section — code |
| .rdata | 8,192 bytes | 7.1 | Read-only data — some entropy, may contain strings |
| .data | 16,384 bytes | 7.8 | Higher entropy — possible packed or encrypted data, or configuration |
| .rsrc | 4,096 bytes | 4.1 | Resources — icons, manifests — normal |

**Observation:** The .data section has elevated entropy (7.8) — this can indicate packed or encrypted data. Combined with the imported injection APIs and C2 URI, this is consistent with a malware sample that may pack its payload or configuration.

#### Hashes

| Algorithm | Hash |
|-----------|------|
| MD5 | d41d8cd98f00b204e9800998ecf8427e |
| SHA1 | — (placeholder) |
| SHA256 | a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 |
| SHA512 | — (placeholder) |

**Note:** Hashes are sample placeholders. In a real analysis, all four hash algorithms would be computed and the SHA256 submitted to VirusTotal and threat-intel platforms.

### Dynamic analysis (sandbox)

| Behavior | Observation | Significance |
|----------|------------|--------------|
| C2 communication | HTTPS to 185.220.101.45 on port 443 | Command-and-control channel — external IP is a known Tor exit node |
| Process injection | Injected code into svchost.exe | Persistence and stealth — hiding in a legitimate system process |
| File system activity | Created `%APPDATA%\cache.dat` | Data storage — may be C2 configuration, exfiltrated data, or payload cache |
| Registry activity | Added `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with value pointing to `%APPDATA%\cache.dat` | Persistence — program runs on user login |
| Network | Outbound HTTPS to C2 every 60 seconds (beaconing) | Regular beaconing — consistent with C2 check-in pattern |
| Process behavior | Spawned cmd.exe /c from PowerShell | Command execution — likely downloading or executing additional payload |

### IOCs extracted

| Type | Value | Context |
|------|-------|---------|
| MD5 | d41d8cd98f00b204e9800998ecf8427e | Sample hash |
| SHA256 | a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 | Sample hash |
| C2 domain | malicious-c2.example.com | Command-and-control |
| C2 IP | 185.220.101.45 | C2 server (Tor exit node) |
| Mutex | Global\MalwareSync | Single-instance check — common in malware |
| Persistence registry | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware = %APPDATA%\cache.dat | Run-on-login persistence |
| File | %APPDATA%\cache.dat | Created file — C2 config or payload cache |
| User-agent | (from HTTP traffic) | May identify the malware family or version |

### Classification

| Attribute | Detail |
|-----------|--------|
| Type | Infostealer / C2 Agent with ransomware-adjacent behavior |
| Family | Suspected AgentTesla / Lumma / similar infostealer variant (based on C2 pattern, PowerShell use, and Cookie/credential theft behavior) |
| Severity | High |
| Impact | Credential theft, data exfiltration, potential lateral movement, C2 implant |

### ATT&CK mapping — malware analysis

| Technique | Sub-technique | Evidence |
|-----------|--------------|----------|
| T1059.001 | PowerShell | PowerShell execution with `-w hidden` and `-enc` |
| T1071.001 | Web Protocols (C2) | HTTPS to C2 at 185.220.101.45 |
| T1055 | Process Injection | CreateRemoteThread, VirtualAllocEx, WriteProcessMemory — injection into svchost.exe |
| T1547.001 | Registry Run Keys / Startup Folder | HKCU Run key added for persistence |
| T1567 | Exfiltration Over Web Service | Data sent via HTTPS POST to C2 |
| T1486 | Data Encrypted for Impact | vssadmin delete shadows — anti-recovery (ransomware behavior) |
| T1548 | Abuse Elevation Control Mechanism | UAC bypass attempt |
| T1072 | Software Deployment Tools | PowerShell used as execution tool |

### Recommendations

1. **Block C2 infrastructure** — block 185.220.101.45 and malicious-c2.example.com at firewall and DNS sinkhole immediately
2. **Hunt for IOCs across all endpoints** — search for the SHA256 hash, the mutex, the registry persistence key, and the file `%APPDATA%\cache.dat`
3. **Reset credentials** — for any user account that interacted with the affected system, especially if the malware is an infostealer
4. **Submit sample to VirusTotal** — for community intelligence and family identification
5. **Check for lateral movement** — the injected svchost.exe and credential theft suggest the attacker may have used stolen credentials to move laterally
6. **Review PowerShell logging** — ensure Script Block Logging (Event ID 4104) and Module Logging are enabled on all endpoints to improve PowerShell detection

---

## Screenshots

```
![EDR alert — ransomware detected](screenshots/edr-ransomware-alert.png)
  → Real screenshot: EDR console alert showing ransomware behavior detection,
    process tree, and affected files.

![Isolated host in EDR console](screenshots/edr-isolated-host.png)
  → Real screenshot: EDR console showing the affected host in isolated/quarantined state.

![Ransom note on affected system](screenshots/ransom-note.png)
  → Real screenshot: ransom note displayed on the affected system desktop.

![Sysmon Event ID 1 — suspicious PowerShell](screenshots/sysmon-powershell-event.png)
  → Real screenshot: Sysmon Event ID 1 process creation showing encoded PowerShell
    with -WindowStyle Hidden, parent process, and user context.

![YARA scan output — matched strings](screenshots/yara-scan-output.png)
  → Real screenshot: terminal output from running the YARA rule against a malware sample,
    showing matched strings (injection APIs, destructive commands, C2 URI).

![PE section entropy analysis](screenshots/pe-section-entropy.png)
  → Real screenshot: PEstudio or similar tool showing PE section entropy, highlighting
    the high-entropy .data section.
```

---

## Next steps

- [ ] Perform the actual IR tabletop exercise using this playbook and document results
- [ ] Capture real EDR screenshots showing alert, process tree, and isolation
- [ ] Perform forensic timeline reconstruction on a real or sample EVTX/Sysmon dataset
- [ ] Analyze a real malware sample from MalwareBazaar with the YARA rule and document matched strings
- [ ] Compute all four hashes (MD5, SHA1, SHA256, SHA512) for the analyzed sample
- [ ] Submit the sample to VirusTotal and document the detection ratio and family classification
- [ ] Replace all placeholder screenshots with real captures from lab exercises
