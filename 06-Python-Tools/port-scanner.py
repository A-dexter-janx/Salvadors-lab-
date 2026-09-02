#!/usr/bin/env python3
"""
Port Scanner - TCP Connect Scan
A simple multi-threaded port scanner for network reconnaissance.

Usage:
    python3 port-scanner.py <target> [ports]
    python3 port-scanner.py 192.168.1.1 1-1024
    python3 port-scanner.py 192.168.1.1 80,443,8080

Author: Salvador Janthan
"""

import socket
import argparse
import concurrent.futures
import sys
from datetime import datetime

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

def parse_port_range(port_str):
    """Parse port specification: '80,443,8080' or '1-1024'"""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def scan_port(target, port, timeout=3):
    """Scan a single TCP port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            return (port, "open", service)
        return (port, "closed", "")
    except Exception:
        return (port, "error", "")

def scan_target(target, ports, max_workers=100, timeout=3):
    """Scan all ports on target"""
    print(f"[*] Scanning {target} - {len(ports)} ports")
    print(f"[*] Started at: {datetime.now().strftime('%H:%M:%S')}")
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port, status, service = future.result()
            if status == "open":
                results.append((port, status, service))
                print(f"[+] Port {port:5d}/tcp  OPEN     {service}")
            elif status == "error":
                print(f"[!] Port {port:5d}/tcp  ERROR")
    
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Simple TCP Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 port-scanner.py 192.168.1.1
  python3 port-scanner.py 192.168.1.1 1-1024
  python3 port-scanner.py 192.168.1.1 80,443,8080
        """
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("ports", nargs="?", default="1-1024",
                        help="Port range (e.g. 1-1024) or comma list (80,443)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="Number of concurrent threads (default: 100)")
    parser.add_argument("-t", "--timeout", type=float, default=3.0,
                        help="Socket timeout in seconds (default: 3.0)")
    
    args = parser.parse_args()
    
    ports = parse_port_range(args.ports)
    results = scan_target(args.target, ports, args.workers, args.timeout)
    
    print(f"\n[*] Scan complete: {len(results)} open ports found")
    print(f"[*] Finished at: {datetime.now().strftime('%H:%M:%S')}")
    
    if results:
        print("\nOpen Ports:")
        for port, status, service in sorted(results):
            print(f"  {port:5d}/tcp  {status:5}  {service}")

if __name__ == "__main__":
    main()
