# Threat Hunting — Sigma Rules & YARA Signatures

> Detection-as-code and file-based malware signatures. Two Sigma rules with ATT&CK mapping, hunting hypotheses, false-positive analysis, and test procedures; one YARA rule targeting generic malware behavior rather than a single IOC.

---

## Hunting philosophy

A detection rule without a hunting hypothesis is just a query. Before writing each rule, I define:

1. **What attacker behavior am I hunting for?** The specific technique and sub-technique.
2. **What would real activity look like in the logs?** The event IDs, fields, and patterns I expect to see.
3. **What would a false positive look like?** Legitimate admin activity that might trigger the same pattern.
4. **How do I test it?** A concrete procedure to generate the behavior and verify the rule fires.

ATT&CK mapping is included for every rule so coverage is visible and gaps are obvious.

---

## Sigma Rule 1 — Suspicious PowerShell Execution (Encoded Commands)

**Hunting hypothesis:** An attacker using PowerShell for execution or exploitation will often encode the command line (base64) to evade casual inspection and logging. The encoded form appears as `-enc`, `-encodedcommand`, or `-e` followed by a base64 blob. Detecting the presence of these arguments in process creation logs is a strong indicator of suspicious PowerShell use.

**ATT&CK mapping:**
- T1059.001 — Command and Scripting Interpreter: PowerShell
- T1027 — Obfuscated Files or Information (encoding as a form of obfuscation)
- T1059 — Command and Scripting Interpreter (parent technique)

**Rationale:**
- Legitimate administrators rarely need to pass encoded commands to PowerShell. Most administrative scripts are visible in plain text or are scheduled tasks with clear commands.
- Encoding is not proof of malicious intent — it can be used to pass complex arguments — but combined with other context (hidden window, network activity, suspicious parent process) it is a strong signal.

**Logsource:**
- Category: `process_creation`
- Product: `windows`
- Expected data sources: Sysmon Event ID 1, Windows Security Event ID 4688, PowerShell transcript logs

**Detection:**
```yaml
title: Suspicious PowerShell Execution - Encoded Commands
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects PowerShell commands using encoded/base64 arguments, commonly used to obfuscate malicious intent.
author: Salvador Janthan
date: 2026/09/02
modified: 2026/09/02
references:
  - https://github.com/SigmaHQ/sigma
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
      - '-e '
  condition: selection
falsepositives:
  - Legitimate admin scripts using encoded commands (rare in most environments)
  - Software installers or management tools that pass encoded arguments
  - PowerShell remoting with encoded command blocks
level: high
```

**Detection logic explained:**
- `Image|endswith: '\powershell.exe'` — focuses on the PowerShell executable. Could be extended to `pwsh.exe` for PowerShell Core.
- `CommandLine|contains: '-enc', '-encodedcommand', '-e '` — catches the three common forms of encoded command invocation.
- `condition: selection` — both conditions must match: the process must be PowerShell, and the command line must contain an encoding argument.

**Hunt query — Splunk equivalent:**

```spl
index=security sourcetype=winlogbeat_eventlog
| search EventID=4688 OR (event_type=process_create)
| search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*" OR CommandLine="*-e *"
| stats count by src_ip, Image, CommandLine, _time
| sort - count
```

**Hunt query — Sysmon equivalent (raw log query):**

```
EventID=1 and (CommandLine contains "-enc" or CommandLine contains "-encodedcommand" or CommandLine contains "-e ")
```

**False-positive analysis and tuning:**
- **Software installers:** Some installers use encoded PowerShell for setup steps. If a specific installer is known and legitimate, add its parent process or command line signature to an allowlist.
- **Remote management:** PowerShell remoting may use encoded commands. Correlate with source IP and user to distinguish admin remote management from suspicious activity.
- **Tuning recommendation:** In a mature deployment, add context filters:
  - Exclude commands launched by known management tools (SCCM, Intune, PDQ) by parent process.
  - Require additional suspicious context (hidden window `-WindowStyle Hidden`, network activity, suspicious parent) before escalating to high severity.

**Test procedure:**
1. From a lab Windows endpoint, run a benign encoded PowerShell command:
   ```
   powershell.exe -enc SGV5Z2V0IG1hbmFnZXIgZm9yIGRldmVybmF0aW9u
   ```
   (Decodes to: "Detect malware for detection")
2. Verify Sysmon Event ID 1 or Security Event ID 4688 captures the command line with `-enc`.
3. Run the hunt query — confirm the event is returned.
4. Document the event fields (process name, command line, parent process, user, timestamp) for reference.

**Recommended additional context to collect:**
- Parent process (was PowerShell spawned by explorer.exe, cmd.exe, a suspicious binary, or a management tool?)
- User context (interactive user, system, or a service account?)
- Network activity from the same process (Sysmon Event ID 3) — did the PowerShell command make network connections?
- Window style (`-WindowStyle Hidden` is a stronger indicator than encoding alone)

---

## Sigma Rule 2 — Lateral Movement via PsExec, WMI, and RPC

**Hunting hypothesis:** After initial access, an attacker will move laterally using remote execution tools. PsExec, WMI process creation (`wmic process call create`), and SMB-based remote execution (`net use \\host` followed by remote execution) are common lateral movement techniques. Detecting these tools in process creation logs is a direct indicator of lateral movement.

**ATT&CK mapping:**
- T1021 — Remote Services
- T1021.002 — SMB/Windows Admin Shares (PsExec)
- T1047 — Windows Management Instrumentation (WMI)
- T1021.001 — Remote Desktop Protocol (if RDP is also used)

**Rationale:**
- PsExec, WMI process creation, and SMB resource access are legitimate administrative tools — but they are also the most common lateral movement mechanisms used by attackers post-compromise.
- Detection at the process-creation level gives visibility into who ran what, from where, and under which account — essential context for distinguishing admin activity from adversary lateral movement.

**Logsource:**
- Category: `process_creation`
- Product: `windows`

**Detection:**
```yaml
title: Lateral Movement via PsExec/WMI
id: b2c3d4e5-f6a7-8901-bcde-f23456789012
status: experimental
description: Detects remote execution tools commonly used for lateral movement post-compromise.
author: Salvador Janthan
date: 2026/09/02
modified: 2026/09/02
references:
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1047/
tags:
  - attack.lateral_movement
  - attack.t1021
  - attack.t1047
  - attack.t1021.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_psexec:
    Image|endswith: '\psexec.exe'
    CommandLine|contains: '-accepteula'
  selection_wmi:
    Image|endswith: '\wmic.exe'
    CommandLine|contains: 'process call create'
  selection_rpc:
    Image|endswith: '\net.exe'
    CommandLine|contains: 'use \\\\'
  condition: selection_psexec or selection_wmi or selection_rpc
falsepositives:
  - Legitimate administrative remote management using PsExec or WMI
  - Automated deployment tools that use PsExec for software distribution
  - Admin scripts that use net use to access shared resources
level: medium
```

**Detection logic explained:**
- **PsExec:** Catches `psexec.exe` with `-accepteula` — the silent EULA acceptance flag that indicates scripted use rather than interactive admin use. Interactive admin use would typically show the EULA prompt.
- **WMI:** Catches `wmic.exe` with `process call create` — the exact WMI syntax for remote process creation.
- **RPC/SMB:** Catches `net.exe` with `use \\` — mapping a remote share, often a precursor to remote execution via admin shares (C$, ADMIN$, IPC$).

**Hunt query — Splunk equivalent:**

```spl
index=security sourcetype=winlogbeat_eventlog
| search (EventID=4688 OR event_type=process_create)
| search (CommandLine="*psexec*" AND CommandLine="*-accepteula*")
   OR (CommandLine="*wmic*" AND CommandLine="*process call create*")
   OR (CommandLine="*net use *\\*")
| stats count by src_ip, Image, CommandLine, User, _time
| sort - count
```

**False-positive analysis and tuning:**
- **Legitimate admin use:** PsExec and WMI are used by sysadmins for remote management. The key differentiator is context:
  - Is this a known admin account?
  - Is this a known admin workstation?
  - Is this during a maintenance window?
- **Automated deployment tools:** SCCM, Intune, PDQ Deploy, and similar tools may use PsExec. Identify these tools and exclude their parent processes or service accounts.
- **Tuning recommendation:**
  - Escalate to high severity if the source is a non-admin host, the user is not a known admin, or the target is a sensitive system.
  - Correlate with network connections (Sysmon Event ID 3) from the same process to confirm the remote target.
  - Look for sequences: `net use \\host\IPC$` followed by `psexec \\host` — this sequence is a strong lateral movement indicator.

**Test procedure:**
1. From a Kali attacker machine in the lab, use PsExec to execute a command on the Windows 10 target:
   ```
   psexec \\192.168.1.100 -accepteula -u administrator -p password cmd
   ```
2. Verify Sysmon Event ID 1 or Security Event ID 4688 captures the PsExec process on the target (or source, depending on logging posture).
3. Run the hunt query — confirm the PsExec event is returned with the `-accepteula` flag visible.
4. Repeat with WMI:
   ```
   wmic /node:192.168.1.100 process call create "cmd.exe /c echo test"
   ```
5. Repeat with net use:
   ```
   net use \\192.168.1.100\IPC$ /user:administrator password
   ```
6. Document each event's fields.

**Recommended additional context:**
- Source and destination IP/hostname for each event.
- User context — was the command run as SYSTEM, an admin, or a service account?
- Parent process — was PsExec/WMI spawned by an interactive shell, a script, or a known management tool?
- Sequence analysis — did a `net use` precede a `psexec`? That sequence is more suspicious than either in isolation.

---

## ATT&CK coverage — this section

| Technique | Sub-technique | Sigma rule | Status |
|-----------|--------------|------------|--------|
| T1059 — Command and Scripting Interpreter | T1059.001 — PowerShell | suspicious-powershell.yml | Covered (encoded command detection) |
| T1027 — Obfuscated Files or Information | — | suspicious-powershell.yml | Partially covered (encoding detected; full deobfuscation not in scope) |
| T1021 — Remote Services | T1021.002 — SMB/Windows Admin Shares | lateral-movement-detection.yml | Covered (PsExec detection) |
| T1047 — Windows Management Instrumentation | — | lateral-movement-detection.yml | Covered (WMI process creation) |

**Gap to address next:**
- T1021.001 — Remote Desktop Protocol: add RDP logon detection (Event ID 4624 Logon Type 10) from non-admin sources.
- T1021.004 — SSH: add SSH logon detection if Linux targets are in scope.
- Credential dumping (T1003) and token manipulation (T1134) are common follow-on techniques after lateral movement — would complement this rule set.

---

## YARA Rule — Generic Malware Indicators

**Hunting hypothesis:** Malware commonly uses a set of Windows API calls for injection and memory manipulation (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread), executes destructive commands (vssadmin delete shadows, cmd.exe /c), hides its window (powershell -w hidden), and attempts UAC bypass. A YARA rule targeting these patterns can catch generic malware behavior even when the specific sample is unknown.

**ATT&CK mapping:**
- T1055 — Process Injection (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
- T1059.001 — PowerShell (hidden window execution)
- T1486 — Data Encrypted for Impact (vssadmin delete shadows — ransomware behavior)
- T1548 — Abuse Elevation Control Mechanism (UAC bypass)

**Rationale:**
- Single-IOC rules (one hash, one domain) expire quickly — malware changes hashes and domains constantly.
- Behavioral indicators — API calls, command strings, destructive actions — persist across variants and families.
- This rule is designed as a **generic triage rule**: it will flag files that exhibit common malware traits, but it will also have false positives. It is a starting point for deeper analysis, not a final verdict.

**YARA rule — malware-signature.yar:**

```yara
rule Suspicious_Malware_Generic
{
    meta:
        description = "Generic detection rule for common malware indicators: injection APIs, destructive commands, obfuscation, and UAC bypass attempts"
        author = "Salvador Janthan"
        date = "2026-09-02"
        license = "CC BY-SA 4.0"
        attck = "T1055, T1059.001, T1486, T1548"

    strings:
        $injection_api_1 = "VirtualAllocEx" nocase wide ascii
        $injection_api_2 = "WriteProcessMemory" nocase wide ascii
        $injection_api_3 = "CreateRemoteThread" nocase wide ascii
        $injection_api_4 = "NtMapViewOfSection" nocase wide ascii
        $cmd_destructive_1 = "cmd.exe /c" nocase wide ascii
        $cmd_destructive_2 = "vssadmin delete shadows" nocase wide ascii
        $cmd_destructive_3 = "bcdedit /set {default} recoveryenabled No" nocase wide ascii
        $powershell_hidden = "powershell -w hidden" nocase wide ascii
        $powershell_encoded = "-enc" nocase wide ascii
        $uac_bypass = "bypass UAC" nocase wide ascii
        $suspicious_url = "http://" nocase wide ascii
        $dll_load = "LoadLibrary" nocase wide ascii
        $shell_execute = "ShellExecute" nocase wide ascii

    condition:
        any of them
}
```

**Strings explained:**

| string | what it catches | ATT&CK relevance |
|--------|----------------|------------------|
| VirtualAllocEx, WriteProcessMemory, CreateRemoteThread | Process injection API calls — a remote thread or code injection is being prepared | T1055 Process Injection |
| cmd.exe /c | Command shell execution — often used to run destructive commands or download cradles | T1059 Command and Scripting Interpreter |
| vssadmin delete shadows | Volume shadow copy deletion — classic ransomware behavior to prevent recovery | T1486 Data Encrypted for Impact |
| bcdedit /set {default} recoveryenabled No | Disables Windows recovery — another ransomware anti-recovery technique | T1486 |
| powershell -w hidden | Hidden PowerShell window — obfuscation of execution | T1059.001 / T1027 |
| -enc | Encoded PowerShell command — obfuscation | T1059.001 / T1027 |
| bypass UAC | UAC bypass attempt | T1548 Abuse Elevation Control |
| http:// | Network communication — may indicate C2 or download cradle | T1071 Application Layer Protocol |
| LoadLibrary, ShellExecute | DLL loading and process execution APIs — used by loaders and droppers | T1055 / T1059 |

**Usage:**

```bash
# Scan a single file
yara -r Suspicious_Malware_Generic.yar /path/to/sample.exe

# Scan a directory recursively
yara -r Suspicious_Malware_Generic.yar /path/to/suspicious/directory/

# Scan with verbose output showing matched strings
yara -r -s Suspicious_Malware_Generic.yar /path/to/sample.exe
```

**False-positive analysis:**
- **Legitimate admin scripts** may contain `cmd.exe /c` or `powershell -w hidden` for legitimate automation.
- **System DLLs and tools** may reference `LoadLibrary`, `ShellExecute`, or even `VirtualAllocEx` in their import tables — this rule scans strings, not imports, so DLL import tables will not trigger unless the string appears in the file content.
- **Security tools** (EDR, AV, remote administration tools) may contain these strings — test the rule against known benign binaries in the environment to establish a baseline.

**Tuning recommendation:**
- Use as a **first-pass triage rule** — files flagged should be investigated, not automatically deleted.
- For production, add a **threshold condition** requiring 2+ strings to match before flagging, to reduce single-string false positives.
- For more precision, write additional rules targeting specific families or behaviors with more specific string combinations.

**Test procedure:**
1. Test against a known benign binary (e.g., a Windows system DLL or a trusted utility) — confirm whether it triggers and which string matches.
2. Test against a malware sample from a malware zoo (MalwareBazaar, VirusShare, or any lab malware repository) — confirm it triggers.
3. Document which strings matched for both benign and malicious samples — this informs tuning.
4. Scan a directory of mixed files to see the false-positive rate in practice.

---

## ATT&CK coverage — full portfolio

| Technique | Sub-technique | Where covered | Status |
|-----------|--------------|--------------|--------|
| T1110 — Brute Force | T1110.001 Password Guessing | 02-SIEM-Projects (Splunk) | Covered |
| T1071.001 — Web Protocols (C2) | — | 02-SIEM-Projects (Splunk C2 DNS) | Partially covered |
| T1567 — Exfiltration Over Web Service | — | 02-SIEM-Projects (volume detection) | Partially covered |
| T1059.001 — PowerShell | — | 03-Threat-Hunting (Sigma) | Covered |
| T1027 — Obfuscated Files or Information | — | 03-Threat-Hunting (Sigma) | Partially covered |
| T1021 — Remote Services | T1021.002 SMB/Admin Shares | 03-Threat-Hunting (Sigma) | Covered |
| T1047 — WMI | — | 03-Threat-Hunting (Sigma) | Covered |
| T1055 — Process Injection | — | 03-Threat-Hunting (YARA) | Partially covered (API detection, not runtime) |
| T1486 — Data Encrypted for Impact | — | 03-Threat-Hunting (YARA) | Partially covered (vssadmin string) |
| T1548 — Abuse Elevation Control | — | 03-Threat-Hunting (YARA) | Partially covered (UAC string) |
| T1190 — Exploit Public-Facing App | — | 01-Network-Security (firewall rules) | Controlled (DMZ exposure minimized) |
| T1048 — Exfiltration Over Alternative Protocol | — | 01-Network-Security (DMZ egress controlled) | Controlled |
| T1486 — Data Encrypted for Impact | — | 05-Incident-Response (playbook) | Responded (playbook covers ransomware) |

**Overall coverage assessment:**
- Strong detection coverage for brute force, PowerShell execution, and lateral movement.
- Partial coverage for C2 (DNS phase only — need egress monitoring for full C2 picture) and injection (static string detection — need runtime detection for full coverage).
- Network controls (firewall segmentation) provide preventative coverage for public-facing exploit and exfiltration paths.
- IR playbook covers ransomware response end-to-end.

**Next detections to build:**
- T1021.001 — RDP logon detection from non-admin sources
- T1003 — Credential Dumping (LSASS access, mimikatz indicators)
- T1071.001 full coverage — egress HTTPS monitoring or NetFlow beaconing detection
- T1055 runtime coverage — Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) for actual injection detection

---

## Screenshots

```
![Sigma rule in VS Code with ATT&CK tags](screenshots/sigma-vscode.png)
  → Real screenshot: Sigma rule YAML open in an editor with ATT&CK tags visible.

![YARA rule scan output](screenshots/yara-scan-output.png)
  → Real screenshot: terminal output from running the YARA rule against a test file,
    showing matched strings and the rule name.

![Sysmon Event ID 1 — suspicious PowerShell](screenshots/sysmon-powershell-event.png)
  → Real screenshot: Sysmon Event ID 1 process creation event showing encoded PowerShell,
    with command line and parent process visible.
```

---

## Next steps

- [ ] Add RDP logon detection rule (Event ID 4624 Logon Type 10) to Sigma
- [ ] Add credential dumping detection (LSASS access — Sysmon Event ID 10, or Event ID 4656/4663)
- [ ] Test both Sigma rules against real log data and document results
- [ ] Tune the YARA rule with a threshold (2+ strings) to reduce false positives
- [ ] Scan a sample malware from MalwareBazaar with the YARA rule and document which strings matched
- [ ] Add screenshots of the rules in an editor and the scan/test output
