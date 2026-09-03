# Python Tools — Detection, Analysis & Integrity

> Three functional Python tools built during lab work: a threaded TCP port scanner, a security log analyzer, and a multi-algorithm file hash checker. Each tool is self-contained, tested, and documented with usage examples.

These tools were built because off-the-shelf GUIs are fine for ad-hoc use, but scripting them teaches how they work and lets me tailor them to specific lab needs.

---

## Tools

### port-scanner.py — Threaded TCP Port Scanner

A TCP connect scanner with configurable concurrency, timeout, and port specification. Uses a thread pool for parallelism.

**Usage:**
```bash
python3 port-scanner.py 192.168.1.50 80,443,8080
python3 port-scanner.py 192.168.1.0/24 1-1024 -w 50 -t 2
python3 port-scanner.py scanme.nmap.org 1-1000 -w 100 -t 1
```

**Options:**
| Flag | Default | Description |
|------|---------|-------------|
| `-w, --workers` | 20 | Thread pool size for concurrent scanning |
| `-t, --timeout` | 2.0 | Connection timeout in seconds |
| `-v, --verbose` | off | Print each port result as it completes |

**Integration:** Used during the vulnerability management phase (04) for initial network discovery before running Nessus scans. Results feed into the SIEM detection rules (02) as baseline network data.

---

### log-analyzer.py — Security Log Analyzer

Triage tool for auth logs and web server logs. Detects failed/successful logins, sudo usage, HTTP 5xx errors, and suspicious keyword patterns.

**Usage:**
```bash
python3 log-analyzer.py /var/log/auth.log --summary
python3 log-analyzer.py /var/log/auth.log --failed-logins --sudo --show-commands
python3 log-analyzer.py /var/log/apache2/access.log --http-errors --top-ips 10
python3 log-analyzer.py /var/log/auth.log --summary --failed-logins --sudo
```

**Options:**
| Flag | Description |
|------|-------------|
| `--summary` | Show summary analysis (total lines, unique IPs, event counts) |
| `--failed-logins` | Detect and list failed login attempts |
| `--successful-logins` | Detect and list successful logins |
| `--sudo` | Detect sudo usage |
| `--show-commands` | Show actual sudo commands (use with `--sudo`) |
| `--http-errors` | Detect HTTP 5xx errors from web server logs |
| `--top-ips N` | Show top N IPs by activity |

**Sample output (auth.log):**
```
============================================================
LOG ANALYSIS REPORT
============================================================

[Summary]
  Total lines analyzed: 1523
  Unique IPs found: 47
  Time range: 2026-08-23 22:00:00 to 2026-08-25 22:15:00

[Failed Logins Detected]
  47 occurrences from 12 unique source IPs
  Top source: 185.220.101.34 (18 attempts)

[Sudo Usage Detected]
  3 occurrences by user 'admin'
  Commands: /bin/bash, /usr/bin/apt, /bin/systemctl

[HTTP 5xx Errors]
  0 occurrences — no server errors detected
```

**Integration:** The failed-login detection logic mirrors the Splunk brute-force alert (02-SIEM-Projects) — this tool is the local triage version that runs on the endpoint before logs are forwarded to the SIEM.

---

### hash-checker.py — Multi-Algorithm File Hash Checker

Computes MD5, SHA1, SHA256, and SHA512 hashes for file integrity verification and malware triage.

**Usage:**
```bash
python3 hash-checker.py suspicious_file.exe
python3 hash-checker.py -a sha256 payload.dll
python3 hash-checker.py --all evidenceimage.img
python3 hash-checker.py -v known_bad.exe --verify "a1b2c3d4..."
```

**Options:**
| Flag | Description |
|------|-------------|
| `-a, --algorithm` | Hash algorithm: md5, sha1, sha256, sha512 (default: sha256) |
| `-v, --verify` | Verify file against known hash (shows match/mismatch) |
| `--all` | Compute all four algorithms at once |

**Sample output:**
```
File: suspicious_file.exe
Size: 245760 bytes
SHA256: 3a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b
Status: UNKNOWN — not in known hash database
```

**Integration:** Used during incident response (05, 07) for evidence integrity verification. The SHA256 manifest in the Nancy/Amatera case study (07-Incident-Case-Study/nancy-amatera/sha256_manifest.txt) was generated using this tool.

---

## Design decisions

- **No external dependencies.** All three tools use only Python standard library — they run anywhere Python 3 is available without pip install.
- **Thread pool over async.** For port scanning, a ThreadPoolExecutor is simpler to reason about than asyncio for concurrent socket connections, and performance is sufficient for lab-scale scans.
- **Standard library only for hashing.** hashlib provides all needed algorithms — no third-party crypto libraries needed.
- **CLI-first design.** Each tool is designed to be piped into other commands or called from scripts, not just run interactively.

---

## Running the tools

All tools are executable:
```bash
cd 06-Python-Tools
python3 port-scanner.py --help
python3 log-analyzer.py --help
python3 hash-checker.py --help
```

No installation required. Python 3.8+ is sufficient.
