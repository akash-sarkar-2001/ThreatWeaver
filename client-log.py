import win32evtlog
import csv
import time
import re
import socket
from datetime import datetime

LOG_TYPE = "Security"
# Now also capture authentication events on the client for IP data
TARGET_EVENTS = [4624, 4625, 4688]
OUTPUT_FILE = "client_logs.csv"

# Get this machine's IP for local process events
def get_local_ip():
    """Get the local machine's actual IP address."""
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
    """Normalize IP addresses from Windows Security logs."""
    if not raw_ip or not isinstance(raw_ip, str):
        return "127.0.0.1"

    ip = raw_ip.strip()

    if ip in ("-", "", "::1", "0.0.0.0", "::"):
        return "127.0.0.1"

    if ip.lower().startswith("::ffff:"):
        return ip[7:]

    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return ip

    if ip.startswith("::") or ip == "0:0:0:0:0:0:0:1":
        return "127.0.0.1"

    return ip if len(ip) > 1 else "127.0.0.1"


def safe_get(strings, index, default="N/A"):
    """Safely extract a value from StringInserts with validation."""
    if len(strings) > index and strings[index]:
        val = strings[index].strip()
        return val if val and val != "-" else default
    return default


def collect_client_logs():
    hand = win32evtlog.OpenEventLog(None, LOG_TYPE)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = []

    while True:
        records = win32evtlog.ReadEventLog(hand, flags, 0)
        if not records:
            break

        for event in records:
            event_id = event.EventID & 0xFFFF
            if event_id not in TARGET_EVENTS:
                continue

            time_generated = event.TimeGenerated.Format()
            strings = event.StringInserts or []

            username = "N/A"
            process_name = "N/A"
            command_line = ""
            source_ip = "127.0.0.1"

            if event_id == 4688:
                # Process Creation — no IP in this event
                # Use local machine IP since processes run locally
                username = safe_get(strings, 1)
                process_name = safe_get(strings, 5)
                command_line = safe_get(strings, 8, default="")
                source_ip = LOCAL_IP

            elif event_id in [4624, 4625]:
                # Logon events on client machine
                username = safe_get(strings, 5)
                process_name = "N/A"
                command_line = ""

                raw_ip = safe_get(strings, 18, default="")
                source_ip = sanitize_ip(raw_ip)

                logon_type = safe_get(strings, 8, default="0")
                if logon_type in ("2", "0"):
                    source_ip = "127.0.0.1"

            events.append([time_generated, event_id, username, process_name, command_line, source_ip])

    win32evtlog.CloseEventLog(hand)

    # Write CSV — NOW includes source_ip column!
    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event_id", "username", "process_name", "command_line", "source_ip"])
        writer.writerows(events)

    print(f"[CLIENT] Log snapshot saved at {datetime.now()} | Events: {len(events)}")


# =========================
# Run every 60 seconds
# =========================

while True:
    collect_client_logs()
    time.sleep(60)
