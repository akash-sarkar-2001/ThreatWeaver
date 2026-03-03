import win32evtlog
import csv
import time
from datetime import datetime

LOG_TYPE = "Security"
TARGET_EVENTS = [4624, 4625, 4672, 4768, 4769]  # Authentication events
OUTPUT_FILE = "dc_logs.csv"

def collect_dc_logs():
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
            source_ip = "N/A"

            if event_id in [4624, 4625]:
                username = strings[5] if len(strings) > 5 else "N/A"
                source_ip = strings[18] if len(strings) > 18 else "N/A"

            elif event_id == 4672:
                username = strings[1] if len(strings) > 1 else "N/A"

            elif event_id in [4768, 4769]:
                username = strings[0] if len(strings) > 0 else "N/A"
                source_ip = strings[9] if len(strings) > 9 else "N/A"

            events.append([time_generated, event_id, username, source_ip])

    # Write CSV
    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event_id", "username", "source_ip"])
        writer.writerows(events)

    print(f"[DC] Log snapshot saved at {datetime.now()} | Events: {len(events)}")

# =========================
# Run every 60 seconds
# =========================

while True:
    collect_dc_logs()
    time.sleep(60)
