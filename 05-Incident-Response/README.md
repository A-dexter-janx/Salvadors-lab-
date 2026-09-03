# Incident Response — Ransomware Playbook, Forensic Timeline & Malware Analysis

> Three IR deliverables: a full NIST SP 800-61 ransomware playbook covering all six phases, a forensic timeline reconstruction from Windows artifacts, and a malware analysis report with IOCs extracted.

This section demonstrates the full incident response lifecycle: preparing for incidents, detecting and analyzing them, containing and recovering, and conducting post-incident review.

---

## Contents

| File | Purpose |
|------|---------|
| `sample-ir-playbook.md` | Six-phase ransomware IR playbook aligned to NIST SP 800-61 |
| `forensic-timeline.csv` | Timeline reconstruction from Windows artifacts (Security log, USBSTOR, Shellbags, Sysmon, PowerShell logging) |
| `malware-analysis-report.md` | Malware analysis report with static and dynamic analysis findings and extracted IOCs |

---

## Integration with other sections

- **Python tools (06):** `hash-checker.py` validates file integrity during evidence collection; `log-analyzer.py` triage auth logs for initial detection
- **SIEM (02):** Detection rules from this section inform Splunk/Elastic alerting — the playbook defines what alerts the SOC should have
- **Threat hunting (03):** Sigma rules derived from this incident's TTPs feed ongoing hunting operations
- **Case study (07):** The Nancy/Amatera incident is a real-world application of these IR procedures

---

## Key takeaways

1. **Preparation matters most.** A ransomware response that starts at detection is already behind. The playbook documents readiness activities (tools, contacts, playbooks reviewed) that must be in place before any incident.

2. **Timeline reconstruction is iterative.** The forensic timeline starts with available artifacts and expands as more sources are examined. Each artifact type (Security log, USBSTOR, Shellbags) adds a different lens on the same event.

3. **Malware analysis without a sample has limits.** When the actual payload is not available (deleted, never captured), analysis relies on indirect evidence: process creation logs, network connections, file system artifacts, and memory-resident indicators. The report documents what could and could not be determined.

---

## Next steps

- [ ] Run the IOC scanner (`nancy-amatera-ioc_scanner.py`) against a test system and document output
- [ ] Validate Sigma rules from 03-Threat-Hunting against the Nancy/Amatera TTPs
- [ ] Add a lessons-learned post-incident report template
- [ ] Document the forensic timeline methodology — what artifacts were examined, in what order, and why
