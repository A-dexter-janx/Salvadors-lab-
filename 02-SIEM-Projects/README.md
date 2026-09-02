# SIEM Projects Overview
## Elastic Stack & Splunk Implementation

### Projects in This Section
1. **Splunk Alerts** - Custom detection rules for brute force and C2 traffic
2. **Elastic Stack** - Winlogbeat configuration and Kibana dashboard exports

### Lab Environment
- **Splunk Free:** 500MB/day ingestion limit
- **Elastic Stack:** Self-hosted on Ubuntu VM (4GB RAM)
- **Data Sources:** Windows Event Logs, DNS queries, firewall logs

### Approach
- Start with free/opensource tools before scaling to enterprise
- Build detection content incrementally
- Document everything for portfolio showcase

### Next Steps
- [ ] Deploy Splunk on a dedicated VM
- [ ] Configure Winlogbeat on a Windows endpoint
- [ ] Build 3-5 custom detection alerts
- [ ] Create dashboards for real-time monitoring
