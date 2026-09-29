import re 
import sys
import email
from email import policy
from email.parser import BytesParser
import requests

# Insert your API keys here
ABUSEIPDB_API_KEY = "417cdf19937bca995beb2f6cd31712ceb18e2cf15a21f6c598a3f0692291e6c7770754f423b4303f"
VIRUSTOTAL_API_KEY = "d700a78c1cabc0f9fbdd74d68fb009794db914a4c76e2f90a038eec4a3f46509"

def extract_iocs(text):
    """Extract public IP addresses and URLs from raw text."""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'

    ips = set(re.findall(ip_pattern, text))
    urls = set(re.findall(url_pattern, text))

    # Filter out private/loopback IPs
    public_ips = [
        ip for ip in ips 
        if not (ip.startswith('127.') or ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.16.'))
    ]
    return public_ips, urls

def check_ip_abuseipdb(ip):
    """Query AbuseIPDB API for IP reputation score."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}

    try:
        res = requests.get(url, headers=headers, params=params)
        if res.status_code == 200:
            data = res.json()['data']
            return {
                "IP": ip,
                "Abuse Score": f"{data['abuseConfidenceScore']}%",
                "Country": data.get('countryCode', 'N/A'),
                "ISP": data.get('isp', 'N/A')
            }
    except Exception as e:
        return {"IP": ip, "Error": str(e)}
    return {"IP": ip, "Status": "Failed"}

def defang_url(url):
    """Defang URLs to safely display in ticket reports."""
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")

def parse_eml_file(file_path):
    """Parse an .eml file and extract headers and body content."""
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        "From": msg.get("From", "N/A"),
        "To": msg.get("To", "N/A"),
        "Subject": msg.get("Subject", "N/A"),
        "Date": msg.get("Date", "N/A"),
        "Authentication-Results": msg.get("Authentication-Results", "N/A")
    }

    # Extract body content
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors='ignore')
    else:
        body = msg.get_payload(decode=True).decode(errors='ignore')

    return headers, body

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 phish_triage.py <path_to_eml_file>")
        sys.exit(1)

    eml_path = sys.argv[1]
    headers, body = parse_eml_file(eml_path)

    print("=== SOC Phishing Triage Tool ===")
    print("\n--- Parsed Email Headers ---")
    for k, v in headers.items():
        print(f"  {k}: {v}")

    full_content = str(headers) + "\n" + body
    ips, urls = extract_iocs(full_content)

    print(f"\n[+] Extracted Public IPs: {list(ips)}")
    print("\n[+] Extracted & Defanged URLs:")
    for u in urls:
        print(f"    - {defang_url(u)}")

    print("\n--- Threat Intelligence Lookups (AbuseIPDB) ---")
    for ip in ips:
        print(f"  {check_ip_abuseipdb(ip)}")
