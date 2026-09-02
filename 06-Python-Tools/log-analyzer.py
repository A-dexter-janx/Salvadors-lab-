#!/usr/bin/env python3
"""
Log Analyzer - Security Event Analysis Tool
Parses server/application logs to detect suspicious patterns.

Usage:
    python3 log-analyzer.py <logfile>
    python3 log-analyzer.py /var/log/auth.log --failed-logins
    python3 log-analyzer.py access.log --top-ips 10

Author: Salvador Janthan
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

# Common patterns for security log analysis
PATTERNS = {
    "failed_login": re.compile(
        r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(?:Failed|failure|invalid|denied).*?(?:password|login|authentication)",
        re.IGNORECASE
    ),
    "successful_login": re.compile(
        r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(?:Accepted|success|logged in)",
        re.IGNORECASE
    ),
    "sudo_usage": re.compile(
        r"(?P<user>\w+)\s+(?:sudo|COMMAND)",
        re.IGNORECASE
    ),
    "ssh_connection": re.compile(
        r"SSH\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE
    ),
    "error_5xx": re.compile(
        r'"\s+(?P<status>5\d{2})\s+',
    ),
    "ip_address": re.compile(r"\b(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
}

def analyze_log(filepath, options):
    """Analyze log file and return findings"""
    findings = {
        "total_lines": 0,
        "failed_logins": Counter(),
        "successful_logins": Counter(),
        "sudo_commands": defaultdict(list),
        "top_ips": Counter(),
        "errors_5xx": Counter(),
        "blocked_patterns": [],
    }
    
    try:
        with open(filepath, "r", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                findings["total_lines"] += 1
                
                # Extract all IPs
                for match in PATTERNS["ip_address"].finditer(line):
                    findings["top_ips"][match.group("ip")] += 1
                
                # Failed logins
                if options.failed_logins:
                    match = PATTERNS["failed_login"].search(line)
                    if match:
                        ip = match.group("ip")
                        findings["failed_logins"][ip] += 1
                
                # Successful logins
                if options.successful_logins:
                    match = PATTERNS["successful_login"].search(line)
                    if match:
                        ip = match.group("ip")
                        findings["successful_logins"][ip] += 1
                
                # Sudo usage
                if options.sudo:
                    match = PATTERNS["sudo_usage"].search(line)
                    if match:
                        user = match.group("user")
                        findings["sudo_commands"][user].append(line.strip())
                
                # HTTP 5xx errors
                if options.http_errors:
                    match = PATTERNS["error_5xx"].search(line)
                    if match:
                        findings["errors_5xx"][match.group("status")] += 1
                
                # Check for suspicious patterns
                suspicious_keywords = [
                    "root", "administrator", "admin",
                    "SELECT * FROM", "UNION SELECT", "DROP TABLE",
                    "eval(", "exec(", "system(",
                    "passwd", "shadow", "/etc/passwd",
                    "curl ", "wget ", "nc -e",
                    "cat /etc/shadow", "chmod 777",
                ]
                line_lower = line.lower()
                for keyword in suspicious_keywords:
                    if keyword.lower() in line_lower and keyword not in [p.lower() for p in findings["blocked_patterns"]]:
                        findings["blocked_patterns"].append(line.strip())
                        break
    
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied for '{filepath}'", file=sys.stderr)
        sys.exit(1)
    
    return findings

def print_report(findings, options):
    """Print analysis report"""
    print("=" * 60)
    print("LOG ANALYSIS REPORT")
    print("=" * 60)
    
    if options.summary:
        print(f"\n[Summary]")
        print(f"  Total lines analyzed: {findings['total_lines']}")
        print(f"  Unique IPs found: {len(findings['top_ips'])}")
        
        if findings["failed_logins"]:
            print(f"\n[Failed Logins by IP]")
            for ip, count in findings["failed_logins"].most_common(10):
                print(f"  {ip}: {count} attempts")
        
        if findings["successful_logins"]:
            print(f"\n[Successful Logins by IP]")
            for ip, count in findings["successful_logins"].most_common(10):
                print(f"  {ip}: {count} logins")
        
        if findings["sudo_commands"]:
            print(f"\n[Sudo Usage]")
            for user, commands in findings["sudo_commands"].items():
                print(f"  User '{user}': {len(commands)} sudo commands")
                if options.show_commands:
                    for cmd in commands[:5]:
                        print(f"    - {cmd}")
        
        if findings["errors_5xx"]:
            print(f"\n[HTTP 5xx Errors]")
            for status, count in findings["errors_5xx"].most_common():
                print(f"  {status}: {count} occurrences")
        
        if findings["blocked_patterns"]:
            print(f"\n[Suspicious Patterns Detected]")
            for pattern in findings["blocked_patterns"][:20]:
                print(f"  - {pattern}")
    
    if options.top_ips:
        print(f"\n[Top {options.top_ips} IPs by Activity]")
        for ip, count in findings["top_ips"].most_common(options.top_ips):
            print(f"  {ip}: {count} occurrences")

def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 log-analyzer.py /var/log/auth.log --summary
  python3 log-analyzer.py access.log --top-ips 20 --http-errors
  python3 log-analyzer.py syslog.log --failed-logins --sudo --show-commands
        """
    )
    parser.add_argument("logfile", help="Path to log file to analyze")
    parser.add_argument("--summary", action="store_true",
                        help="Show summary analysis")
    parser.add_argument("--failed-logins", action="store_true",
                        help="Detect failed login attempts")
    parser.add_argument("--successful-logins", action="store_true",
                        help="Detect successful logins")
    parser.add_argument("--sudo", action="store_true",
                        help="Detect sudo usage")
    parser.add_argument("--show-commands", action="store_true",
                        help="Show actual sudo commands (use with --sudo)")
    parser.add_argument("--http-errors", action="store_true",
                        help="Detect HTTP 5xx errors")
    parser.add_argument("--top-ips", type=int, metavar="N",
                        help="Show top N IPs by activity")
    
    args = parser.parse_args()
    
    if not any([args.summary, args.failed_logins, args.successful_logins,
                args.sudo, args.http_errors, args.top_ips]):
        parser.print_help()
        sys.exit(1)
    
    findings = analyze_log(args.logfile, args)
    print_report(findings, args)

if __name__ == "__main__":
    main()
