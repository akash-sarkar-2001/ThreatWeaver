import win32evtlog
import time
import re
from datetime import datetime
import psycopg2
from psycopg2 import extras
import os
import dotenv

dotenv.load_dotenv()

# =====================================================
# CONFIGURATION & CACHE
# =====================================================
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "threatweaver_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS")
DB_PORT = os.getenv("DB_PORT", "5432")

LOG_TYPE = "Security"
TARGET_EVENTS = [4624, 4625, 4672, 4768, 4769, 4688]
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(SCRIPT_DIR, ".server_watermark")

def load_watermark():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return int(f.read().strip())
        except Exception:
            return 0
    return 0

def save_watermark(record_number):
    try:
        with open(CACHE_FILE, "w") as f:
            f.write(str(record_number))
    except Exception as e:
        print(f"[-] Failed to save cache: {e}")

LAST_RECORD_NUMBER = load_watermark()

# =====================================================
# DATABASE SETUP
# =====================================================
def setup_database():
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS, port=DB_PORT)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS raw_logs (
                timestamp TIMESTAMP NOT NULL, event_id INTEGER, username VARCHAR(255),
                source_ip VARCHAR(255), process_name TEXT, command_line TEXT, source_machine VARCHAR(255)
            );
        ''')
        cursor.execute("SELECT create_hypertable('raw_logs', by_range('timestamp'), if_not_exists => TRUE);")
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[-] Database Setup Error: {e}")

# =====================================================
# IP ADDRESS SANITIZER
# =====================================================
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IPV6_LIKE_RE = re.compile(r"^([0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}$")

def looks_like_ip(s: str) -> bool:
    if not s: return False
    s = str(s).strip()
    s2 = s[7:] if s.lower().startswith("::ffff:") else s
    return bool(IPV4_RE.match(s2) or IPV6_LIKE_RE.match(s))

def find_ip_in_strings(strings):
    for item in strings or []:
        if not item: continue
        item = str(item).strip()
        if looks_like_ip(item): return sanitize_ip(item)
    return "127.0.0.1"

def sanitize_ip(raw_ip):
    if not raw_ip or not isinstance(raw_ip, str): return "127.0.0.1"
    ip = raw_ip.strip()
    if ip in ("-", "", "::1", "0.0.0.0", "::"): return "127.0.0.1"
    if ip.lower().startswith("::ffff:"): return ip[7:]
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip): return ip
    if ip.startswith("::") or ip == "0:0:0:0:0:0:0:1": return "127.0.0.1"
    return ip if len(ip) > 1 else "127.0.0.1"

def safe_get(strings, index, default="N/A"):
    if len(strings) > index and strings[index]:
        val = str(strings[index]).strip()
        return val if val and val != "-" else default
    return default

# =====================================================
# LOG COLLECTION & DB INSERTION
# =====================================================
def collect_dc_logs():
    global LAST_RECORD_NUMBER
    hand = win32evtlog.OpenEventLog(None, LOG_TYPE)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = []
    newest_record_in_this_run = LAST_RECORD_NUMBER
    reached_old_logs = False

    while True:
        records = win32evtlog.ReadEventLog(hand, flags, 0)
        if not records:
            break

        for event in records:
            if LAST_RECORD_NUMBER > 0 and event.RecordNumber <= LAST_RECORD_NUMBER:
                reached_old_logs = True
                break
                
            if event.RecordNumber > newest_record_in_this_run:
                newest_record_in_this_run = event.RecordNumber

            event_id = event.EventID & 0xFFFF
            if event_id not in TARGET_EVENTS:
                continue

            time_generated = event.TimeGenerated.Format()
            strings = event.StringInserts or []
            username, source_ip, process_name, command_line = "N/A", "N/A", "N/A", "N/A"

            if event_id in [4624, 4625]:
                username = safe_get(strings, 5)
                source_ip = sanitize_ip(safe_get(strings, 18, default=""))
                if safe_get(strings, 8, default="0") in ("2", "0"): source_ip = "127.0.0.1"
            elif event_id == 4672:
                username, source_ip = safe_get(strings, 1), "127.0.0.1"
            elif event_id in [4768, 4769]:
                username = safe_get(strings, 0)
                candidate = safe_get(strings, 9, default="")
                source_ip = sanitize_ip(candidate) if looks_like_ip(candidate) else find_ip_in_strings(strings)
            elif event_id == 4688:
                username, process_name, command_line, source_ip = safe_get(strings, 1), safe_get(strings, 5), safe_get(strings, 8, default=""), "127.0.0.1"

            events.append((time_generated, event_id, username, source_ip, process_name, command_line, "DOMAIN_CONTROLLER"))
            
        if reached_old_logs:
            break

    win32evtlog.CloseEventLog(hand)
    
    # Save cache if we processed new logs
    if newest_record_in_this_run > LAST_RECORD_NUMBER:
        LAST_RECORD_NUMBER = newest_record_in_this_run
        save_watermark(LAST_RECORD_NUMBER)

    if events:
        try:
            conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS, port=DB_PORT)
            cursor = conn.cursor()
            insert_query = "INSERT INTO raw_logs (timestamp, event_id, username, source_ip, process_name, command_line, source_machine) VALUES %s"
            extras.execute_values(cursor, insert_query, events)
            conn.commit()
            cursor.close()
            conn.close()
            print(f"[DC] Pushed {len(events)} NEW events to database at {datetime.now()}")
        except Exception as e:
            print(f"[-] Failed to push logs to database: {e}")

if __name__ == "__main__":
    print("🛡️ ThreatWeaver Server Agent Started.")
    print(f"[*] Resuming from cached log ID: {LAST_RECORD_NUMBER}")
    setup_database()
    while True:
        collect_dc_logs()
        time.sleep(60)
