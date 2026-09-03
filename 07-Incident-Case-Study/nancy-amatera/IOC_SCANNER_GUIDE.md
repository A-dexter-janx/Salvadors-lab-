# Nancy/Amatera IOC Scanner — Usage & Integration Guide

**Date:** 2026-09-03  
**Status:** Functional — tested against real incident artifacts

This document explains how to use the IOC scanner, what it checks, and how it integrates with the rest of the security lab.

---

## What the scanner does

The IOC scanner (`nancy_amatera_ioc_scanner.py`) checks a Windows endpoint for indicators of the Nancy/Amatera stealer compromise. It combines five scan types into a single tool:

| Scan type | What it checks | Why it matters |
|-----------|----------------|----------------|
| Scheduled tasks | Enumerate all tasks and compare names/paths against known IOCs | The persistence mechanism was a scheduled task (`UpdateService`) |
| File paths | Check common staging paths (`%APPDATA%\Microsoft\Windows\Caches\Nancy\`, `%TEMP%\`, etc.) for files matching known hashes | The payload was staged in these locations |
| SHA256 hash scan | Hash files in scanned directories and compare against the SHA256 manifest | Identifies known payload files even if renamed |
| Registry | Check Run keys, persistence-related registry values, and known malicious keys | The malware added a Run key for persistence |
| Event logs | Search for relevant Event IDs (process creation with encoded PowerShell, Defender detections, etc.) | Provides behavioral evidence of the attack chain |

---

## Usage

```bash
# Check current user's endpoint
python3 nancy_amatera_ioc_scanner.py

# Check a specific directory
python3 nancy_amatera_ioc_scanner.py --path "C:\Users\Mary\AppData\Local\Temp"

# Check with verbose output (shows each check as it runs)
python3 nancy_amatera_ioc_scanner.py --verbose

# Check with SHA256 hash verification only
python3 nancy_amatera_ioc_scanner.py --hashes-only

# Output results as JSON for programmatic consumption
python3 nancy_amatera_ioc_scanner.py --json
```

---

## Sample output

```
============================================================
IOC SCANNER — Nancy/Amatera Stealer Indicators
============================================================
Scan target: local endpoint (current user)
Scan date: 2026-09-03 10:30:00 SAST

[1/5] Scheduled Tasks
  Enumerating 124 scheduled tasks...
  ✓ No known malicious task names detected
  (Checked: UpdateService, Update Svc, Microsoft Update Task, and 121 others)

[2/5] File Path Checks
  Checking 8 staging paths...
  ✓ Path %APPDATA%\Microsoft\Windows\Caches\Nancy\ — not found
  ✓ Path %TEMP%\abners.exe — not found
  ✓ Path %TEMP%\Wacatac\ — not found
  ... (6 more paths checked)

[3/5] SHA256 Hash Scan
  Scanning 3 files in staging directories...
  ✓ No files matched known malicious SHA256 hashes
  (Manifest contains 8 known payload hashes)

[4/5] Registry Checks
  Checking 5 registry keys/values...
  ✓ HKCU\...\Run — no suspicious entries
  ✓ HKLM\...\Run — no suspicious entries
  ✓ Defender exclusions — no suspicious exclusions found

[5/5] Event Log Checks
  Checking Windows Event Logs for 6 relevant Event IDs...
  ✓ No suspicious process creation events found (last 30 days)
  ✓ No Defender detection events found matching known patterns

============================================================
RESULT: NO IOC INDICATORS FOUND
Endpoint appears clean of known Nancy/Amatera indicators.
============================================================
```

---

## Integration with other lab sections

| Section | Integration |
|---------|-------------|
| 02-SIEM-Projects | The event log check uses the same Event IDs that the Splunk detection rules monitor (4688 for process creation, 4104 for PowerShell script block logging). The scanner is the local triage version of the SIEM alerts. |
| 03-Threat-Hunting | The Sigma rules in `suspicious-powershell.yml` and `lateral-movement-detection.yml` target the same behaviors the scanner's event log check looks for. The scanner is the endpoint-level implementation; Sigma rules are the SIEM-level implementation. |
| 05-Incident-Response | During IR, this scanner provides rapid IOC checking at the endpoint level. The forensic timeline and malware analysis report document what was found; the scanner is the tool that finds it. |
| 06-Python-Tools | The hash-checker.py tool is used internally by the scanner for SHA256 computation. The scanner depends on the same hashing logic. |
| 07-Incident-Case-Study | The scanner is the primary investigative tool for checking other endpoints for the same compromise. It uses the SHA256 manifest and IOCs from this section as its reference data. |

---

## Design decisions

- **Standalone execution:** The scanner runs on a single endpoint without network access to a SIEM. It pulls data from the local Windows API (scheduled tasks, registry, event logs, file system) and produces a human-readable report.
- **No external dependencies:** Only Python standard library is used. The scanner runs on any Windows machine with Python 3.8+ installed.
- **Verbose mode by default in development:** When debugging, the `--verbose` flag shows each check as it runs, making it easy to see which check found (or didn't find) an indicator.
- **JSON output for automation:** The `--json` flag produces machine-readable output suitable for feeding into a SIEM or ticketing system.

---

## Extending the scanner

To add new IOCs:

1. **Scheduled task IOC:** Add the task name to the `KNOWN_TASKS` list in the script.
2. **File path IOC:** Add the path to the `STAGING_PATHS` list.
3. **SHA256 hash IOC:** Add the hash to the `KNOWN_HASHES` list (or update the manifest file).
4. **Registry IOC:** Add the registry key/value to the `REGISTRY_CHECKS` list.
5. **Event log IOC:** Add the Event ID and filter criteria to the `EVENT_LOG_CHECKS` list.

The scanner is designed to be extended as new IOCs are discovered from incident investigations.

---

## Next steps

- [ ] Add a `--remediation` flag that suggests remediation steps based on which IOCs were found
- [ ] Add support for scanning remote endpoints via WMI (for fleet-wide IOC hunts)
- [ ] Integrate with the SIEM: push scanner results to Splunk/Elastic as an endpoint telemetry source
- [ ] Add digital signature checking — flag unsigned executables in staging paths even if hash doesn't match
