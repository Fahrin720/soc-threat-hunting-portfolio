# 🛡️ Network Forensics & Automated SOC Threat Hunting Engine

## 📌 Executive Summary
This project demonstrates end-to-end **Security Operations Center (SOC)** capabilities combining **Network Packet Forensics (Wireshark)** and **Security Automation (Python)**. 

Built as a foundational cybersecurity engineering portfolio project, it covers:
1. **Packet-Level Network Forensics:** Capturing and dissecting TCP 3-Way Handshakes and extracting cleartext credentials from unencrypted HTTP `POST` traffic.
2. **Automated SIEM Log Parsing & Threat Hunting:** A custom Python detection engine that parses web server logs using Regular Expressions (`re`) to detect **Brute-Force**, **SQL Injection (SQLi)**, **Directory Traversal**, and **Vulnerability Scanners**.
3. **Threat Intelligence Enrichment & MITRE ATT&CK Mapping:** Automatically enriches attacker IP addresses with live Geolocation/ISP telemetry via API and maps every alert to the **MITRE ATT&CK® Framework**.

---

## 🏗️ Project Architecture & Repository Structure
```text
soc-threat-hunting-portfolio/
├── logs/
│   └── server_access.log         # Simulated Apache/Nginx server logs with embedded attacks
├── reports/
│   ├── alerts.json               # Structured SIEM-ready JSON alerts
│   └── incident_report.md        # Auto-generated Executive Incident Response Report
├── screenshots/
│   ├── wireshark_http_creds.png  # Proof of cleartext HTTP credential interception
│   ├── wireshark_tcp_handshake.png # Packet capture of TCP SYN / SYN-ACK / ACK
│   └── soc_analyzer_report.png   # Output of the Python SOC Threat Hunter
├── log_generator.py              # Script that simulates normal traffic + 4 cyber attack vectors
├── soc_analyzer.py               # Core Regex detection & Threat Intel enrichment engine
└── README.md                     # Project documentation