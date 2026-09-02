# Python Tools
## Security Automation Scripts

### Tools in This Section
1. **port-scanner.py** - Multi-threaded TCP connect port scanner
2. **log-analyzer.py** - Security log analysis for suspicious patterns
3. **hash-checker.py** - File integrity verification (MD5/SHA1/SHA256/SHA512)

### port-scanner.py
- Threaded scanning for fast enumeration
- Common port database for service identification
- Supports range (1-1024) and comma-list (80,443,8080) formats

### log-analyzer.py
- Detects failed/successful logins from auth logs
- Tracks sudo usage per user
- Identifies HTTP 5xx errors from web logs
- Flags suspicious patterns (SQL injection, privilege escalation)

### hash-checker.py
- Computes MD5, SHA1, SHA256, SHA512 hashes
- Verifies files against known hash lists
- Useful for malware triage and integrity checking

### Usage
```bash
# Port scan
python3 port-scanner.py 192.168.1.1 1-1024

# Analyze auth log
python3 log-analyzer.py /var/log/auth.log --summary --failed-logins

# Verify file integrity
python3 hash-checker.py file.exe --verify hashes.txt
```

### Next Steps
- [ ] Add additional scan types (SYN scan via scapy)
- [ ] Add more log parsers (Windows Event Logs, Apache, Syslog)
- [ ] Add batch mode for scanning multiple files
