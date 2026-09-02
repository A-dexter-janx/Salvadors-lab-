# Incident Response Projects
## IR Playbooks, Forensics & Malware Analysis

### Projects in This Section
1. **IR Playbook** - Sample incident response procedure for ransomware
2. **Forensic Timeline** - Timeline reconstruction from Windows artifacts
3. **Malware Analysis Report** - Static and dynamic analysis report

### Lab Environment
- **Sandbox:** REMnux, FlareVM, or Cuckoo Sandbox
- **Forensic Tools:** Autopsy, Volatility, FTK Imager, RegRipper
- **Malware Analysis:** PEstudio, Process Monitor, Wireshark

### Methodology
- Triage: Quick static analysis to determine if sample is malicious
- Static analysis: Strings, imports, PE sections, hashes
- Dynamic analysis: Monitor behavior in isolated sandbox
- IOC extraction: Hashes, domains, IPs, mutexes, file paths

### Key Skills Demonstrated
- Incident response lifecycle (NIST SP 800-61)
- Windows forensic artifact analysis
- Malware triage and IOC extraction
- Report writing for technical and executive audiences

### Next Steps
- [ ] Analyze real malware sample in sandbox
- [ ] Build forensic timeline from provided evidence
- [ ] Document full IR procedure for ransomware scenario
- [ ] Add additional playbooks for phishing, DDoS, insider threat
