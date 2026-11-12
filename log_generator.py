# log_generator.py
import random
from datetime import datetime, timedelta

LOG_FILE = "logs/server_access.log"

# Normal internal/customer IPs
NORMAL_IPS = [
    "192.168.1.10", "192.168.1.25", "10.0.0.14", "172.16.0.5", "192.168.1.99"
]

# Real public IPs known for scanning/hosting (used for live GeoIP enrichment later)
ATTACKER_IPS = {
    "brute_force": "185.220.101.1",     # Known Tor Exit Node (Germany)
    "sqli": "45.33.32.156",             # Nmap Scanme Server / Linode (USA)
    "traversal": "118.25.6.39",         # Tencent Cloud (China)
    "scanner": "89.248.165.1"           # Known Internet Scanner (Netherlands)
}

NORMAL_ENDPOINTS = [
    "/index.html", "/about.html", "/products.php?id=10", 
    "/products.php?id=24", "/contact.html", "/assets/style.css", "/dashboard"
]

NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safri/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
]

def generate_log_line(ip, timestamp, method, endpoint, status, size, agent):
    time_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{time_str}] "{method} {endpoint} HTTP/1.1" {status} {size} "{agent}"\n'

def main():
    start_time = datetime.now() - timedelta(hours=2)
    log_entries = []

    print("[*] Generating simulated server traffic and cyber attacks...")

    # 1. Generate 400 lines of normal user traffic
    for i in range(400):
        t = start_time + timedelta(seconds=i * 15)
        ip = random.choice(NORMAL_IPS)
        endpoint = random.choice(NORMAL_ENDPOINTS)
        agent = random.choice(NORMAL_AGENTS)
        log_entries.append((t, generate_log_line(ip, t, "GET", endpoint, 200, random.randint(500, 5000), agent)))

    # 2. Inject Attack #1: Automated Credential Brute-Force (25 rapid failed POST logins)
    bf_time = start_time + timedelta(minutes=20)
    for i in range(25):
        t = bf_time + timedelta(seconds=i * 2)
        log_entries.append((t, generate_log_line(
            ATTACKER_IPS["brute_force"], t, "POST", "/login.php", 401, 340, NORMAL_AGENTS[0]
        )))

    # 3. Inject Attack #2: SQL Injection (SQLi) Attempts
    sqli_payloads = [
        "/products.php?id=1' OR '1'='1",
        "/products.php?id=1; DROP TABLE users--",
        "/products.php?id=1 UNION SELECT username, password FROM users--",
        "/login.php?user=admin'--&pass=123"
    ]
    sqli_time = start_time + timedelta(minutes=45)
    for i, payload in enumerate(sqli_payloads):
        t = sqli_time + timedelta(seconds=i * 5)
        log_entries.append((t, generate_log_line(
            ATTACKER_IPS["sqli"], t, "GET", payload, 500, 1200, NORMAL_AGENTS[2]
        )))

    # 4. Inject Attack #3: Directory Traversal (Attempting to steal Linux /etc/passwd)
    traversal_payloads = [
        "/download.php?file=../../etc/passwd",
        "/download.php?file=../../../../etc/shadow",
        "/view.php?page=..%2F..%2F..%2Fetc%2Fpasswd"
    ]
    trav_time = start_time + timedelta(minutes=70)
    for i, payload in enumerate(traversal_payloads):
        t = trav_time + timedelta(seconds=i * 4)
        log_entries.append((t, generate_log_line(
            ATTACKER_IPS["traversal"], t, "GET", payload, 403, 210, NORMAL_AGENTS[1]
        )))

    # 5. Inject Attack #4: Vulnerability Scanner Reconnaissance (Nikto / Sqlmap)
    scanner_agents = ["sqlmap/1.7.2#stable (https://sqlmap.org)", "Mozilla/5.00 (Nikto/2.1.6)"]
    scan_time = start_time + timedelta(minutes=95)
    for i in range(8):
        t = scan_time + timedelta(seconds=i * 3)
        log_entries.append((t, generate_log_line(
            ATTACKER_IPS["scanner"], t, "GET", f"/admin/config_{i}.bak", 404, 150, random.choice(scanner_agents)
        )))

    # Sort all logs chronologically and write to file
    log_entries.sort(key=lambda x: x[0])

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        for _, line in log_entries:
            f.write(line)

    print(f"[+] Successfully generated {len(log_entries)} log entries in '{LOG_FILE}'!")

if __name__ == "__main__":
    main()