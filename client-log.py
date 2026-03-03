import win32evtlog
import csv
import time
from datetime import datetime

LOG_TYPE = "Security"
TARGET_EVENTS = [4688]  # Process creation events
OUTPUT_FILE = "client_logs.csv"

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

            username = strings[1] if len(strings) > 1 else "N/A"
            process_name = strings[5] if len(strings) > 5 else "N/A"
            command_line = strings[8] if len(strings) > 8 else ""

            events.append([time_generated, event_id, username, process_name, command_line])

    # Write CSV
    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event_id", "username", "process_name", "command_line"])
        writer.writerows(events)

    print(f"[CLIENT] Log snapshot saved at {datetime.now()} | Events: {len(events)}")

# =========================
# Run every 60 seconds
# =========================

while True:
    collect_client_logs()
    time.sleep(60)
