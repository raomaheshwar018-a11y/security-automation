import re
import requests
import json
import os
import ipaddress
from datetime import datetime

# --- CONFIGURATION LINKING ---
def load_config():
    config_path = "config.json"
    
    # FIX: Check if file exists and is NOT empty
    if not os.path.exists(config_path) or os.stat(config_path).st_size == 0:
        print("📁 Generating default config.json...")
        default_config = {
            "project_name": "Developing Security Automation Tools with Python for SOC Operations",
            "api_settings": {"vt_api_key": "PLACEHOLDER", "timeout": 5},
            "detection_settings": {"log_file_path": "auth_logs.txt", "threshold": 3}
        }
        with open(config_path, "w") as f:
            json.dump(default_config, f, indent=4)
        return default_config
    
    with open(config_path, "r") as f:
        return json.load(f)

# --- THREAT INTELLIGENCE ---
def get_intel(ip, api_key):
    """Enriches public IPs via VirusTotal API."""
    try:
        if ipaddress.ip_address(ip).is_private:
            return "Internal IP - Skipping Lookup", 0
    except ValueError:
        return "Invalid IP", 0

    if api_key == "PLACEHOLDER":
        return "API Key not set", 0

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats, stats.get('malicious', 0)
        return f"API Error: {response.status_code}", 0
    except:
        return "Network Error", 0

# --- CORE LOGIC ---
def run_soc_tool():
    config = load_config()
    print(f"🚀 Project: {config['project_name']}")
    
    log_path = config['detection_settings']['log_file_path']
    threshold = config['detection_settings']['threshold']
    api_key = config['api_settings']['vt_api_key']

    # Create dummy logs if file doesn't exist
    if not os.path.exists(log_path):
        with open(log_path, "w") as f:
            f.write("Feb 07 12:00:01 sshd: Failed password for root from 8.8.8.8\n" * 5)
            f.write("Feb 07 12:05:01 sshd: Failed password for admin from 192.168.1.5\n" * 5)

    # 1. Parsing
    failed_attempts = {}
    pattern = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
    with open(log_path, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    # 2. Enrichment & Severity
    incident_report = []
    for ip, count in failed_attempts.items():
        if count >= threshold:
            print(f"🔍 Analyzing IP: {ip}...")
            intel, m_score = get_intel(ip, api_key)
            
            severity = "MEDIUM"
            if m_score > 0: severity = "HIGH"
            if m_score > 10: severity = "CRITICAL"

            incident_report.append({
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "count": count,
                "severity": severity,
                "intel": intel
            })

    # 3. Final JSON Report
    with open("soc_final_report.json", "w") as f:
        json.dump(incident_report, f, indent=4)
    print("✅ Success: soc_final_report.json created.")

if __name__ == "__main__":
    run_soc_tool()