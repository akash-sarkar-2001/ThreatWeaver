import win32evtlog
import time
import re
import socket
import requests
import urllib3
from datetime import datetime
import dotenv
import os

# Suppress the warning that we are using a self-signed certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
dotenv.load_dotenv()

# ====================================================
# CONFIGURATION & CACHE
# ====================================================
SERVER_URL = os.getenv("SERVER_URL")
API_KEY = os.getenv("API_KEY")
LOG_TYPE = "Security"
TARGET_EVENTS = [4624, 4625, 4688]

# Force the file to be created exactly where this Python script lives
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(SCRIPT_DIR, ".client_watermark")

def load_watermark():
    """Load the last read RecordNumber from the cache file."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return int(f.read().strip())
        except Exception:
            return 0
    return 0

def save_watermark(record_number):
    """Save the highest RecordNumber to the cache file."""
    try:
        with open(CACHE_FILE, "w") as f:
            f.write(str(record_number))
    except Exception as e:
        print(f"[-] Failed to save cache: {e}")

# Load the memory tracker from the file on startup
LAST_RECORD_NUMBER = load_watermark()

# ====================================================
# HELPERS
# ====================================================
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

def sanitize_ip(raw_ip):
    if not raw_ip or not isinstance(raw_ip, str): return "127.0.0.1"
    ip = raw_ip.strip()
    if ip in ("-", "", "::1", "0.0.0.0", "::", "0:0:0:0:0:0:0:1"): return "127.0.0.1"
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(ipv4_pattern, ip): return ip
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$"
    if re.match(ipv6_pattern, ip):
        if ip.startswith("fe80"): return "127.0.0.1"
        return ip
    return "127.0.0.1"

# ====================================================
# MAIN LOGIC
# ====================================================
def fetch_and_send_logs():
    global LAST_RECORD_NUMBER
    server = 'localhost'
    hand = win32evtlog.OpenEventLog(server, LOG_TYPE)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    events = []
    newest_record_in_this_run = LAST_RECORD_NUMBER
    reached_old_logs = False
    
    while True:
        records = win32evtlog.ReadEventLog(hand, flags, 0)
        if not records:
            break
            
        for record in records:
            if LAST_RECORD_NUMBER > 0 and record.RecordNumber <= LAST_RECORD_NUMBER:
                reached_old_logs = True
                break
                
            if record.RecordNumber > newest_record_in_this_run:
                newest_record_in_this_run = record.RecordNumber

            event_id = record.EventID & 0xFFFF
            if event_id not in TARGET_EVENTS:
                continue
                
            time_generated = record.TimeGenerated.Format()
            strings = record.StringInserts
            username = "N/A"
            source_ip = "127.0.0.1"
            process_name = "N/A"
            command_line = "N/A"
            
            if strings:
                if event_id in (4624, 4625):
                    username = strings[5] if len(strings) > 5 else "N/A"
                    raw_ip = strings[18] if len(strings) > 18 else "127.0.0.1"
                    source_ip = sanitize_ip(raw_ip)
                elif event_id == 4688:
                    username = strings[1] if len(strings) > 1 else "N/A"
                    process_name = strings[5] if len(strings) > 5 else "N/A"
                    command_line = strings[8] if len(strings) > 8 else "N/A"
                    source_ip = LOCAL_IP

            events.append({
                "timestamp": time_generated, "event_id": event_id, "username": username,
                "source_ip": source_ip, "process_name": process_name, "command_line": command_line,
                "source_machine": "CLIENT_MACHINE"
            })
            
        if reached_old_logs:
            break

    win32evtlog.CloseEventLog(hand)

    # Update global variable and save to cache file if we found new logs
    if newest_record_in_this_run > LAST_RECORD_NUMBER:
        LAST_RECORD_NUMBER = newest_record_in_this_run
        save_watermark(LAST_RECORD_NUMBER)

    if events:
        print(f"[*] Preparing to send {len(events)} NEW events...")
        try:
            headers = {"X-API-KEY": API_KEY, "Content-Type": "application/json"}
            response = requests.post(SERVER_URL, json=events, headers=headers, verify=False)
            if response.status_code == 200:
                print(f"[+] Successfully sent {len(events)} events to server.")
            else:
                print(f"[-] Server rejected payload: {response.text}")
        except requests.exceptions.SSLError:
            print("[-] TLS verification failed. Check your certificate.")
        except Exception as e:
            print(f"[-] Connection Error: {e}")

if __name__ == "__main__":
    print(f"🛡️ ThreatWeaver Client Agent Started. IP: {LOCAL_IP}")
    print(f"[*] Resuming from cached log ID: {LAST_RECORD_NUMBER}")
    
    # Do an immediate save if it's our very first run so the file is visibly created!
    if LAST_RECORD_NUMBER == 0:
        save_watermark(0)
        
    while True:
        fetch_and_send_logs()
        time.sleep(60)
