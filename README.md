# Phishing Triage & Threat Intelligence Automation Tool

An automated SOC analyst utility designed to parse raw `.eml` email files, extract indicators of compromise (IoCs), defang malicious URLs, and enrich IP addresses with threat intelligence metrics using the AbuseIPDB API.

---

## Key Features

- **Email Parsing:** Extracts headers (`From`, `To`, `Subject`, `Authentication-Results`) and body text from raw `.eml` files.
- **IoC Extraction & Defanging:** Uses regex to pull public IPv4 addresses and automatically defangs URLs (`http://` to `hxxp://`, `.` to `[.]`) to prevent accidental clicks during triage.
- **Threat Intelligence Enrichment:** Leverages the **AbuseIPDB API v2** to retrieve real-time abuse confidence scores, country codes, and ISP details.
- **SOC Workflow Alignment:** Built to align with **NIST SP 800-61** incident handling standards for rapid Tier 1 triage.

---

## Sample Incident Ticket

**Incident ID:** INC-2026-0929  
**Severity:** High  
**Category:** Phishing / Credential Harvesting  
**Sender:** `security@fake-bank.com`  
**Target:** `victim@company.com`  
**Source IP:** `185.220.101.5` (Abuse Score: 100% — Known Tor Exit Node / Malicious Proxy)  
**Authentication Result:** SPF `FAIL`  
**Defanged URL:** `hxxp://verify-secure-login[.]com`  

### Analysis Verdict
Social engineering attack impersonating financial services to steal user credentials. The failed SPF check confirms header spoofing, while the destination domain points to an untrusted endpoint.

### Recommended Containment Actions
1. Block IP address `185.220.101.5` at the perimeter firewall.
2. Add domain `verify-secure-login.com` to the Secure Email Gateway (SEG) blocklist.
3. Search and purge instances of this message across Exchange/Microsoft 365 mailboxes.

---

## How to Run

1. Clone the repository:
   ```bash
   git clone [https://github.com/ajx77/Phish-Triage-Automation.git](https://github.com/ajx77/Phish-Triage-Automation.git)
   cd Phish-Triage-Automation
