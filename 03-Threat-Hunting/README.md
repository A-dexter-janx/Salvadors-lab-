# Threat Hunting Projects
## Sigma Rules & YARA Signatures

### Projects in This Section
1. **Sigma Rules** - Detection-as-code rules for SIEM/SOAR ingestion
2. **YARA Rules** - File-based malware signature detection

### Methodology
- Write rules based on MITRE ATT&CK techniques
- Test against benign and malicious samples
- Tune to minimize false positives
- Document detection logic for SOC analysts

### Sigma Rules Created
- Suspicious PowerShell execution (encoded commands)
- Lateral movement via PsExec/WMI

### YARA Rules Created
- Generic malware indicator rule (IOCs, API calls, suspicious commands)

### Next Steps
- [ ] Add rules for specific malware families
- [ ] Integrate Sigma rules into Splunk/Sentinel pipeline
- [ ] Build YARA scanning into file upload pipeline
