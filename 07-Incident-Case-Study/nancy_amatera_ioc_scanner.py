#!/usr/bin/env python3
"""
Nancy/Amatera Stealer — Live IOC Scanner
Scans a Windows system for indicators of the Nancy/Amatera infostealer incident (2026-08-25).

Indicators checked:
- Scheduled task UpdateService (hidden, logon trigger)
- Nancy cache directory and payload files
- sync_afc1.cmd stager
- WPA.exe from Nancy cache
- MSBuild with Nancy .csproj execution (recent event log)
- EtherHiding C2 indicators (BSC JSON-RPC to contract 0x328a1fad...)
- Known payload file hashes

Usage:
    python3 nancy_amatera_ioc_scanner.py
    python3 nancy_amatera_ioc_scanner.py --registry
    python3 nancy_amatera_ioc_scanner.py --events
    python3 nancy_amatera_ioc_scanner.py --all

Author: Salvador Janthan
Based on: Incident 2026-08-25 — RenPy Loader / Nancy / Amatera Stealer
           https://github.com/A-dexter-janx/Salvadors-lab-/blob/Lab-Portfolio/07-Incident-Case-Study/nancy-amatera/IOCs.md
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ==============================================================================
# KNOWN IOCs FROM THE 2026-08-25 INCIDENT
# ==============================================================================

KNOWN_PAYLOAD_HASHES = {
    "905ECF0E9F625502F65FBF667DC07E3A7B9E2606732764968AFABE6CE8F337CF": "cache_21ebfd.dat (66 bytes)",
    "6E955E70F72D268B7C7B60BD099090CA74751F8391EB7E31A37BE86EF690707D": "Nancy.Compile.targets (1,058,695 bytes)",
    "2213EA83927F928E14B70FC1A0BA157E9C206724494DCE1EE2132CAD9F68701B": "Nancy.csproj (9,762,294 bytes)",
    "8195BE8C730E5BF88BD9C8174446A9D30380576A1C02A1E918D0DBF874D7CEE3": "Nancy.csproj.user (407,398 bytes)",
    "BA5D127EDEAC89278940F0531BC2C766705D1C68928869D34066ACF0190C6E83": "Nancy.Internal.props (383,944 bytes)",
    "5DAB7083234D2F21F6C1CC2DDEEEA30140B6F19E468AE4BD7068F2F09972B1CF": "runtime_4133.dat (188 bytes)",
    "F025A3E26C5E710D40CDBDC2B2B783E2205F312A447C121DA9E61686E1346023": "runtime_bda1.tmp (247 bytes)",
    "F6C25973719AB4EFD48AFECEFDABD5D62D7464BCC9E1B94CC73AF66A3D5224DC": "sync_afc1.cmd (1,520 bytes)",
}

KNOWN_DETECTION_HASHES = {
    "810F257542018BE0FC62AF542D13D012": "Amatera sample (VT MD5 — GollopDevest stage)",
    "29203ca123d51b1b33505a0813d360df": "Amatera sample (VT MD5 — GollopDevest stage)",
}

SCHEDULED_TASK_NAME = "UpdateService"
NANCY_CACHE_DIRS = [
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Caches\Nancy"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Caches"),
]
KNOWN_DROP_PATHS = [
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Caches\Nancy"),
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%USERPROFILE%\AppData\Local\Temp"),
]

C2_CONTRACT = "0x328a1fadff154290f0ce1389a4e633698cdfdaa7"
C2_SELECTOR = "0x06fdde03"
C2_BSC_NODES = [
    "bsc-dataseed.binance.org",
    "bsc-mainnet.public.blastapi.io",
]

SUSPICIOUS_C2_HEADER_PATTERN = re.compile(r"X-Timestamp|X-Nonce|X-Signature")
SUSPICIOUS_DOH_PATTERN = re.compile(r"8.8.8.8|8.8.4.4|dns.google", re.IGNORECASE)

KNOWN_FILENAMES = [
    "sync_afc1.cmd",
    "Nancy.csproj",
    "Nancy.csproj.user",
    "Nancy.Compile.targets",
    "Nancy.Internal.props",
    "runtime_4133.dat",
    "runtime_bda1.tmp",
    "cache_21ebfd.dat",
    "WPA.exe",
    "Setup.exe",
]

SUSPICIOUS_TASKS = ["UpdateService"]

# ==============================================================================
# SCAN FUNCTIONS
# ==============================================================================

def scan_scheduled_tasks():
    """Check for known suspicious scheduled tasks."""
    findings = []
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/FO", "LIST", "/V"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return [{"type": "scheduled_task", "status": "unavailable", "detail": "schtasks query failed"}]
        
        lines = result.stdout.split("\n")
        current_task = {}
        for line in lines:
            line = line.strip()
            if not line:
                if current_task and "TaskName" in current_task:
                    check_task(current_task, findings)
                current_task = {}
                continue
            
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                if key in ("TaskName", "Next Run Time", "Status", "Last Run Time"):
                    current_task[key] = value
        
        if current_task and "TaskName" in current_task:
            check_task(current_task, findings)
            
    except FileNotFoundError:
        findings.append({"type": "scheduled_task", "status": "unavailable", "detail": "schtasks not found — not Windows?"})
    except Exception as e:
        findings.append({"type": "scheduled_task", "status": "error", "detail": str(e)})
    
    return findings


def check_task(task, findings):
    """Check a single scheduled task for suspicious indicators."""
    task_name = task.get("TaskName", "")
    
    for suspicious in SUSPICIOUS_TASKS:
        if suspicious.lower() in task_name.lower():
            findings.append({
                "type": "scheduled_task",
                "status": "FOUND — SUSPICIOUS",
                "detail": f"Task '{task_name}' matches suspicious task '{suspicious}'",
                "task_info": task
            })
    
    if "UpdateService" in task_name:
        findings.append({
            "type": "scheduled_task",
            "status": "FOUND — NANCY/AMATERA PERSISTENCE",
            "detail": f"Task '{task_name}' is the known Nancy/Amatera persistence mechanism",
            "task_info": task,
            "ioc": "UpdateService scheduled task — Nancy/Amatera (2026-08-25)"
        })


def scan_files():
    """Check for known malicious files and payloads."""
    findings = []
    
    # Check Nancy cache directory
    for cache_dir in NANCY_CACHE_DIRS:
        if not cache_dir or not os.path.exists(cache_dir):
            continue
        
        try:
            for root, dirs, files in os.walk(cache_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    fname_lower = fname.lower()
                    
                    # Check known filenames
                    for known in KNOWN_FILENAMES:
                        if known.lower() in fname_lower:
                            findings.append({
                                "type": "file",
                                "status": "FOUND — SUSPICIOUS FILENAME",
                                "detail": f"File '{fpath}' matches known Nancy/Amatera filename '{known}'",
                                "file": fpath,
                                "filename": fname
                            })
                    
                    # Check file hash
                    try:
                        file_hash = compute_sha256(fpath)
                        if file_hash in KNOWN_PAYLOAD_HASHES:
                            matched_name = KNOWN_PAYLOAD_HASHES[file_hash]
                            findings.append({
                                "type": "file",
                                "status": "FOUND — KNOWN MALWARE HASH",
                                "detail": f"File '{fpath}' has known malicious SHA256 hash — {matched_name}",
                                "file": fpath,
                                "hash": file_hash,
                                "ioc": f"Known Nancy/Amatera payload hash {file_hash}"
                            })
                    except (PermissionError, OSError):
                        pass
                    
        except PermissionError:
            findings.append({"type": "file", "status": "partial", "detail": f"Permission denied scanning {cache_dir}"})
    
    return findings


def compute_sha256(filepath):
    """Compute SHA256 of a file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest().upper()


def scan_registry():
    """Check registry for persistence indicators."""
    findings = []
    
    # Check for Nancy cache directory references in common persistence locations
    registry_paths = [
        (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    ]
    
    for reg_path, label in registry_paths:
        try:
            result = subprocess.run(
                ["reg", "query", reg_path, "/s"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    line_upper = line.upper()
                    if "NANCY" in line_upper or "CACHE" in line_upper:
                        findings.append({
                            "type": "registry",
                            "status": "FOUND — SUSPICIOUS REGISTRY VALUE",
                            "detail": f"Registry value containing 'Nancy' or 'Cache' in {label}: {line.strip()}",
                            "registry": label,
                            "value": line.strip()
                        })
        except Exception:
            pass
    
    return findings


def scan_event_logs():
    """Check Windows event logs for Nancy/Amatera indicators."""
    findings = []
    
    # Check for MSBuild execution of Nancy .csproj files
    try:
        # Security log — process creation events
        result = subprocess.run(
            ["wevtutil", "qe", "Security", "/q:", 
             'EventID=4688', "/f:", "text", "/c:", "100"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                line_upper = line.upper()
                if "NANCY" in line_upper and ("MSBUILD" in line_upper or ".CSPROJ" in line_upper):
                    findings.append({
                        "type": "event_log",
                        "status": "FOUND — MSBUILD NANCY EXECUTION",
                        "detail": f"Security EventID 4688 shows MSBuild executing Nancy project: {line.strip()[:200]}",
                        "event": "Security/4688"
                    })
    except Exception:
        pass
    
    # Check for Defender detections
    try:
        result = subprocess.run(
            ["wevtutil", "qe", "Microsoft-Windows-Windows Defender/Operational", "/q:",
             'EventID=1116', "/f:", "text", "/c:", "50"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                line_upper = line.upper()
                for detection in ["SUSPRENP IEXECPROC", "WACATAC", "SUSPETHERPCRPCONN", "NANCY"]:
                    if detection in line_upper:
                        findings.append({
                            "type": "event_log",
                            "status": "FOUND — DEFENDER DETECTION",
                            "detail": f"Windows Defender detected: {line.strip()[:200]}",
                            "event": "Defender/1116"
                        })
    except Exception:
        pass
    
    return findings


def scan_network_indicators():
    """Check for network indicators of EtherHiding C2."""
    findings = []
    
    # These would require live network capture or firewall log analysis
    # For a scanner, we flag the known C2 indicators as informational
    
    findings.append({
        "type": "network",
        "status": "INFO — KNOWN C2 INDICATORS",
        "detail": f"Known C2 contract: {C2_CONTRACT} — selector: {C2_SELECTOR}",
        "detail2": f"BSC nodes: {', '.join(C2_BSC_NODES)}",
        "note": "Live network scanning requires packet capture or firewall log analysis. Check for outbound connections to these BSC nodes or JSON-RPC eth_call traffic."
    })
    
    # Check for DNS-over-HTTPS indicators in network config
    try:
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "dns.google" in line.lower() or "8.8.8.8" in line:
                    findings.append({
                        "type": "network",
                        "status": "INFO — DNS CONFIG",
                        "detail": f"System DNS includes DoH-compatible DNS: {line.strip()}"
                    })
    except Exception:
        pass
    
    return findings


def scan_known_hashes_deep():
    """Scan common directories for files matching known malicious hashes."""
    findings = []
    search_dirs = []
    
    for env_var in ["TEMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE"]:
        val = os.path.expandvars(f"%{env_var}%")
        if val and os.path.exists(val):
            search_dirs.append(val)
    
    for search_dir in search_dirs:
        try:
            for root, dirs, files in os.walk(search_dir):
                # Skip deep system directories for performance
                if root.count(os.sep) - search_dir.count(os.sep) > 5:
                    continue
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        if os.path.getsize(fpath) > 50 * 1024 * 1024:
                            continue
                        file_hash = compute_sha256(fpath)
                        if file_hash in KNOWN_PAYLOAD_HASHES:
                            matched_name = KNOWN_PAYLOAD_HASHES[file_hash]
                            findings.append({
                                "type": "hash_scan",
                                "status": "FOUND — KNOWN MALWARE HASH",
                                "detail": f"File '{fpath}' matches known Nancy/Amatera hash — {matched_name}",
                                "file": fpath,
                                "hash": file_hash,
                                "ioc": f"Known payload hash {file_hash}"
                            })
                    except (PermissionError, OSError):
                        pass
        except PermissionError:
            pass
    
    return findings


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Nancy/Amatera Stealer — Live IOC Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scans a Windows system for indicators of the Nancy/Amatera infostealer incident (2026-08-25).

Indicators checked:
  --tasks        Scheduled task UpdateService (hidden persistence)
  --files        Nancy cache directory and known payload files
  --registry     Registry persistence (Run/RunOnce keys)
  --events       Windows event logs (MSBuild Nancy execution, Defender detections)
  --network      Known C2 indicators (BSC contract, EtherHiding)
  --hashscan     Deep scan of temp/appdata dirs for known payload hashes
  --all          Run all scans (default)

Author: Salvador Janthan
Based on: Incident 2026-08-25 — RenPy Loader / Nancy / Amatera Stealer
           (https://github.com/A-dexter-janx/Salvadors-lab-/blob/Lab-Portfolio/07-Incident-Case-Study/nancy-amatera/IOCs.md)
        """
    )
    parser.add_argument("--tasks", action="store_true", help="Scan scheduled tasks")
    parser.add_argument("--files", action="store_true", help="Scan for Nancy cache files")
    parser.add_argument("--registry", action="store_true", help="Scan registry persistence")
    parser.add_argument("--events", action="store_true", help="Scan event logs")
    parser.add_argument("--network", action="store_true", help="Check network IOC info")
    parser.add_argument("--hashscan", action="store_true", help="Deep hash scan of temp/appdata")
    parser.add_argument("--all", action="store_true", help="Run all scans (default)")
    
    args = parser.parse_args()
    
    if not any([args.tasks, args.files, args.registry, args.events, args.network, args.hashscan, args.all]):
        parser.print_help()
        sys.exit(0)
    
    scan_all = not any([args.tasks, args.files, args.registry, args.events, args.network, args.hashscan])
    if args.all:
        scan_all = True
    
    print("=" * 70)
    print("NANCY/AMATERA STEALER — LIVE IOC SCAN")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print(f"Known payload hashes: {len(KNOWN_PAYLOAD_HASHES)}")
    print(f"Known detection hashes: {len(KNOWN_DETECTION_HASHES)}")
    print(f"C2 contract: {C2_CONTRACT}")
    print(f"C2 selector: {C2_SELECTOR}")
    print()
    
    all_findings = []
    
    if scan_all or args.tasks:
        print("[*] Scanning scheduled tasks...")
        findings = scan_scheduled_tasks()
        all_findings.extend(findings)
        for f in findings:
            print(f"  [{f['status']}] {f['detail']}")
        print()
    
    if scan_all or args.files:
        print("[*] Scanning for Nancy cache files...")
        findings = scan_files()
        all_findings.extend(findings)
        for f in findings:
            print(f"  [{f['status']}] {f['detail']}")
        print()
    
    if scan_all or args.registry:
        print("[*] Scanning registry persistence...")
        findings = scan_registry()
        all_findings.extend(findings)
        for f in findings:
            print(f"  [{f['status']}] {f['detail']}")
        print()
    
    if scan_all or args.events:
        print("[*] Scanning event logs...")
        findings = scan_event_logs()
        all_findings.extend(findings)
        for f in findings:
            print(f"  [{f['status']}] {f['detail']}")
        print()
    
    if scan_all or args.network:
        print("[*] Checking network IOC info...")
        findings = scan_network_indicators()
        all_findings.extend(findings)
        for f in findings:
            print(f"  [{f['status']}] {f['detail']}")
            if 'detail2' in f:
                print(f"    {f['detail2']}")
            if 'note' in f:
                print(f"    NOTE: {f['note']}")
        print()
    
    if scan_all or args.hashscan:
        print("[*] Deep hash scan of temp/appdata directories...")
        findings = scan_known_hashes_deep()
        all_findings.extend(findings)
        for f in findings:
            print(f"  [{f['status']}] {f['detail']}")
        if not findings:
            print("  No known malicious hashes found in scanned directories.")
        print()
    
    # Summary
    print("=" * 70)
    print("SCAN SUMMARY")
    print("=" * 70)
    critical = sum(1 for f in all_findings if "FOUND" in f.get("status", ""))
    info = sum(1 for f in all_findings if "INFO" in f.get("status", ""))
    print(f"Total findings: {len(all_findings)}")
    print(f"Critical (FOUND): {critical}")
    print(f"Info: {info}")
    print()
    
    if critical > 0:
        print("!" * 70)
        print("! NANCY/AMATERA INDICATORS DETECTED — IMMEDIATE ACTION REQUIRED")
        print("!" * 70)
        print()
        print("Recommended actions:")
        print("  1. Isolate the system from the network immediately")
        print("  2. Do NOT reboot — capture memory dump if possible")
        print("  3. Export scheduled task (schtasks /Query /XML /TN UpdateService)")
        print("  4. Collect Security event log (EventID 4688 for process creation)")
        print("  5. Collect Windows Defender Operational log (EventID 1116)")
        print("  6. Capture firewall logs if available")
        print("  7. Check browser saved passwords — rotate all credentials")
        print("  8. Submit findings to: IC3 (ic3.gov), Microsoft DCU, Malwarebytes")
        print()
        sys.exit(2)
    else:
        print("No Nancy/Amatera indicators detected.")
        print()
        print("Note: This scan checks for known indicators from the 2026-08-25 incident.")
        print("A clean result does not guarantee the system is clean — new variants may")
        print("use different filenames, tasks, or C2 infrastructure.")
        sys.exit(0)


if __name__ == "__main__":
    main()
