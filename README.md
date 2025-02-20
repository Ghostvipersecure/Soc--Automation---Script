# Automated Threat Detection Script

This script monitors network traffic using `tshark`, detects suspicious activity, and automatically blocks malicious IPs.

## Features:
- 📌 Real-time attack detection
- 🛑 Automatic IP blocking via `iptables`
- 📧 Email alerts for security incidents
- 📊 CSV reports for analysis

Requirements:
tshark
jq
iptables

## Usage:
```bash
chmod +x automation_script.sh
./automation_script.sh input.pcap


added "README file"
