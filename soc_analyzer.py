# soc_analyzer.py
import re
import json
import urllib.request
from collections import defaultdict
from datetime import datetime

LOG_FILE = "logs/server_access.log"
REPORT_MD = "reports/incident_report.md"
ALERT_JSON = "reports/alerts.json"

# Regex to parse standard Apache/Nginx Combined Log Format
LOG_PATTERN = re.compile(
    r'^(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?) (.*?) HTTP/.*" (\d+) (\d+) "(.*?)"'
)

# Attack Detection Signatures (Case-Insensitive Regex)
SIGNATURES = {
    "SQL Injection (SQLi)": re.compile(r"(UNION\s+SELECT|OR\s+'1'='1'|DROP\s+TABLE|--|%27)", re.IGNORECASE),
    "Directory Traversal": re.compile(r"(\.\./|\.\.%2F|/etc/passwd|/etc/shadow)", re.IGNORECASE),
    "Automated Security Scanner": re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster)", re.IGNORECASE)
}

BRUTE_FORCE_THRESHOLD = 10  # Flag IPs with >= 10 failed logins (HTTP 401)

def get_ip_threat_intel(ip):
    """Queries ip-api.com to enrich public attacker IPs with GeoIP and ISP metadata."""
    if ip.startswith(("192.168.", "10.", "172.16.")):
        return {"country": "Internal Network", "isp": "Local LAN", "org": "Internal"}
    
    url = f"http://ip-api.com/json/{ip}?fields=status,country,isp,org"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SOC-Threat-Hunter/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown")
                }
    except Exception:
        pass
    return {"country": "Lookup Failed (Offline)", "isp": "Unknown", "org": "Unknown"}

def analyze_logs():
    print("[*] Initializing SOC Log Analyzer & Threat Hunting Engine...")
    
    failed_logins = defaultdict(int)
    detected_incidents = []
    suspicious_ips = set()
    total_lines = 0

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            total_lines += 1
            match = LOG_PATTERN.match(line.strip())
            if not match:
                continue

            ip, timestamp, method, endpoint, status, size, user_agent = match.groups()
            status = int(status)

            # Rule 1: Track Failed Login Attempts (HTTP 401) for Brute Force Detection
            if endpoint.startswith("/login") and status == 401:
                failed_logins[ip] += 1

            # Rule 2: Check Endpoint & User-Agent against Attack Signatures
            combined_payload = f"{endpoint} {user_agent}"
            for attack_type, regex in SIGNATURES.items():
                if regex.search(combined_payload):
                    suspicious_ips.add(ip)
                    detected_incidents.append({
                        "timestamp": timestamp,
                        "source_ip": ip,
                        "attack_type": attack_type,
                        "mitre_tactic": get_mitre_mapping(attack_type),
                        "http_method": method,
                        "http_status": status,
                        "evidence": endpoint if attack_type != "Automated Security Scanner" else user_agent,
                        "line_number": line_num
                    })

    # Process Brute Force Thresholds
    for ip, count in failed_logins.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            suspicious_ips.add(ip)
            detected_incidents.append({
                "timestamp": "Multiple (Burst)",
                "source_ip": ip,
                "attack_type": "Credential Brute-Force Attack",
                "mitre_tactic": get_mitre_mapping("Credential Brute-Force Attack"),
                "http_method": "POST",
                "http_status": 401,
                "evidence": f"{count} failed login attempts on /login.php",
                "line_number": "Multiple"
            })

    # Enrich Suspicious IPs with Threat Intelligence
    print(f"[*] Enriching {len(suspicious_ips)} unique attacker IP(s) via Threat Intel API...")
    ip_intel = {}
    for ip in suspicious_ips:
        ip_intel[ip] = get_ip_threat_intel(ip)

    return total_lines, detected_incidents, ip_intel

def get_mitre_mapping(attack_type):
    mapping = {
        "Credential Brute-Force Attack": "T1110 - Brute Force (Credential Access)",
        "SQL Injection (SQLi)": "T1190 - Exploit Public-Facing Application (Initial Access)",
        "Directory Traversal": "T1083 - File and Directory Discovery (Discovery)",
        "Automated Security Scanner": "T1595 - Active Scanning (Reconnaissance)"
    }
    return mapping.get(attack_type, "Unclassified")

def generate_reports(total_lines, incidents, ip_intel):
    # 1. Save structured JSON alerts (SIEM ingestion format)
    alert_data = {
        "scan_time": datetime.now().isoformat(),
        "total_logs_processed": total_lines,
        "total_incidents": len(incidents),
        "attacker_intelligence": ip_intel,
        "incidents": incidents
    }
    with open(ALERT_JSON, "w", encoding="utf-8") as jf:
        json.dump(alert_data, jf, indent=4)

    # 2. Generate Executive Markdown Incident Report
    with open(REPORT_MD, "w", encoding="utf-8") as mf:
        mf.write("# 🚨 SOC Automated Incident Response Report\n\n")
        mf.write(f"**Analysis Timestamp:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`  \n")
        mf.write(f"**Total Log Entries Analyzed:** `{total_lines}`  \n")
        mf.write(f"**Total Security Incidents Detected:** `{len(incidents)}`  \n")
        mf.write(f"**Unique Threat Actor IPs Identified:** `{len(ip_intel)}`  \n\n")

        mf.write("## 🌍 Threat Actor Intelligence Summary\n")
        mf.write("| Attacker IP | Country | ISP | Organization |\n")
        mf.write("| :--- | :--- | :--- | :--- |\n")
        for ip, info in ip_intel.items():
            mf.write(f"| `{ip}` | {info['country']} | {info['isp']} | {info['org']} |\n")

        mf.write("\n## 🛡️ Detailed Security Incidents & MITRE ATT&CK Mapping\n")
        mf.write("| Attack Type | MITRE ATT&CK ID | Source IP | Status | Payload / Evidence |\n")
        mf.write("| :--- | :--- | :--- | :--- | :--- |\n")
        for inc in incidents:
            mf.write(
                f"| **{inc['attack_type']}** | `{inc['mitre_tactic']}` | `{inc['source_ip']}` "
                f"| `{inc['http_status']}` | `{inc['evidence']}` |\n"
            )

        mf.write("\n## 🔧 Recommended Remediation Actions (SOC Playbook)\n")
        mf.write("1. **Immediate Firewall Block:** Add all identified Threat Actor IPs to the perimeter WAF/Firewall blocklist.\n")
        mf.write("2. **Mitigate Brute Force (`T1110`):** Implement rate-limiting, account lockout policies, and Multi-Factor Authentication (MFA) on `/login.php`.\n")
        mf.write("3. **Mitigate SQL Injection (`T1190`):** Refactor backend database queries in `/products.php` to use Parameterized Queries (Prepared Statements).\n")
        mf.write("4. **Mitigate Directory Traversal (`T1083`):** Sanitize file input parameters in `/download.php` using `os.path.basename()` and enforce strict chroot/file permissions.\n")

    print(f"[+] JSON SIEM Alerts saved to: '{ALERT_JSON}'")
    print(f"[+] Markdown Incident Report saved to: '{REPORT_MD}'")

if __name__ == "__main__":
    total, incidents, intel = analyze_logs()
    generate_reports(total, incidents, intel)
    print("\n[SUCCESS] Threat Hunting Analysis Complete! Check the 'reports/' folder.")