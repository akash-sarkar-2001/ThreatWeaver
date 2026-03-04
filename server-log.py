import win32evtlog
import csv
import time
import re
from datetime import datetime

LOG_TYPE = "Security"

# Added 4688 so DC-side process execution is collected too
TARGET_EVENTS = [4624, 4625, 4672, 4768, 4769, 4688]

OUTPUT_FILE = "dc_logs.csv"

# =====================================================
# IP ADDRESS SANITIZER
# =====================================================
# Windows logs IPs inconsistently:
#   - Local logons: "-", "", "::1", or blank
#   - IPv6-mapped: "::ffff:192.168.1.10"
#   - Network logons: proper IPv4

def sanitize_ip(raw_ip):
    """Normalize IP addresses from Windows Security logs."""
    if not raw_ip or not isinstance(raw_ip, str):
        return "127.0.0.1"

    ip = raw_ip.strip()

    # Local/missing indicators → localhost
    if ip in ("-", "", "::1", "0.0.0.0", "::"):
        return "127.0.0.1"

    # IPv6-mapped IPv4 (e.g., "::ffff:192.168.1.10")
    if ip.lower().startswith("::ffff:"):
        return ip[7:]  # Strip the ::ffff: prefix

    # Already a valid-looking IPv4
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return ip

    # IPv6 localhost variants
    if ip.startswith("::") or ip == "0:0:0:0:0:0:0:1":
        return "127.0.0.1"

    # Return as-is if it looks like a real IPv6 or hostname
    return ip if len(ip) > 1 else "127.0.0.1"


def safe_get(strings, index, default="N/A"):
    """Safely extract a value from StringInserts with validation."""
    if len(strings) > index and strings[index]:
        val = str(strings[index]).strip()
        return val if val and val != "-" else default
    return default


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
            process_name = "N/A"
            command_line = "N/A"

            if event_id in [4624, 4625]:
                # 4624/4625: Logon Success/Failure
                #   [5]  = TargetUserName
                #   [8]  = LogonType (2=Interactive, 3=Network, 10=RemoteInteractive)
                #   [18] = IpAddress (Network Source Address)
                username = safe_get(strings, 5)

                raw_ip = safe_get(strings, 18, default="")
                source_ip = sanitize_ip(raw_ip)

                # For Logon Type 2 (Interactive/Console), IP is always local
                logon_type = safe_get(strings, 8, default="0")
                if logon_type in ("2", "0"):
                    source_ip = "127.0.0.1"

            elif event_id == 4672:
                # 4672: Special Privileges Assigned (no source IP by design)
                username = safe_get(strings, 1)
                source_ip = "127.0.0.1"

            elif event_id in [4768, 4769]:
                # 4768/4769 Kerberos:
                #   [0] = TargetUserName
                #   [9] = IpAddress
                username = safe_get(strings, 0)
                raw_ip = safe_get(strings, 9, default="")
                source_ip = sanitize_ip(raw_ip)

            elif event_id == 4688:
                # 4688: Process creation
                # Common layout (matches your client-log.py approach):
                #   [1] = SubjectUserName
                #   [5] = NewProcessName
                #   [8] = CommandLine (if enabled in policy)
                username = safe_get(strings, 1)
                process_name = safe_get(strings, 5)
                command_line = safe_get(strings, 8, default="")

                # Most 4688 events will be local
                source_ip = "127.0.0.1"

            events.append([time_generated, event_id, username, source_ip, process_name, command_line])

    win32evtlog.CloseEventLog(hand)

    # Write CSV
    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event_id", "username", "source_ip", "process_name", "command_line"])
        writer.writerows(events)

    print(f"[DC] Log snapshot saved at {datetime.now()} | Events: {len(events)}")


# =========================
# Run every 60 seconds
# =========================

while True:
    collect_dc_logs()
    time.sleep(60)
