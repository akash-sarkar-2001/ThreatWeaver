import sys
import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest

# =====================================================
# CONFIGURATION CONSTANTS
# =====================================================

# Contamination: expected ~3% anomaly rate in enterprise security logs
CONTAMINATION_RATE = 0.03

BRUTE_FORCE_LIFETIME_THRESHOLD = 10   # total failures per user lifetime
BRUTE_FORCE_WINDOW_THRESHOLD = 5      # failures within a 10-minute window
MIN_UNIQUE_IPS_FOR_BRUTE_FORCE = 1    # must have >1 source IP to flag brute force
LATERAL_MOVEMENT_MACHINE_THRESHOLD = 3  # unique machines accessed
CREDENTIAL_STUFFING_FAILURE_THRESHOLD = 5  # prior failures before a success
PRIVILEGE_ESC_FAILURE_THRESHOLD = 0   # must have had at least 1 prior failure (> 0)
AFTER_HOURS_START = 20                # hour >= this value is after-hours
AFTER_HOURS_END = 6                   # hour < this value is after-hours

# Placeholder for IPs without a recognisable subnet
UNKNOWN_SUBNET = "N/A"

# =====================================================
# STEP 1 — LOAD DATA (with validation)
# =====================================================

print("[*] STEP 1 — Loading and validating data...")

REQUIRED_COLS = {"timestamp", "event_id", "username"}

for path in ["dc_logs.csv", "client_logs.csv"]:
    if not os.path.isfile(path):
        print(f"[ERROR] Required file not found: {path}")
        sys.exit(1)

try:
    dc = pd.read_csv("dc_logs.csv")
    client = pd.read_csv("client_logs.csv")
except Exception as e:
    print(f"[ERROR] Failed to read CSV files: {e}")
    sys.exit(1)

if dc.empty and client.empty:
    print("[ERROR] Both dc_logs.csv and client_logs.csv are empty. Nothing to process.")
    sys.exit(1)

for label, frame in [("dc_logs.csv", dc), ("client_logs.csv", client)]:
    missing = REQUIRED_COLS - set(frame.columns)
    if missing:
        print(f"[ERROR] {label} is missing required columns: {missing}")
        sys.exit(1)

dc["machine"] = "DC"
client["machine"] = "CLIENT"

for col in ["process_name", "command_line", "source_ip"]:
    if col not in dc.columns:
        dc[col] = "N/A"
    if col not in client.columns:
        client[col] = "N/A"

df = pd.concat([dc, client], ignore_index=True)

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df["login_hour"] = df["timestamp"].dt.hour.fillna(0).astype(int)
df["day"] = df["timestamp"].dt.day.fillna(0).astype(int)

print(f"[+] Loaded {len(df)} total events ({len(dc)} DC + {len(client)} client)")

# =====================================================
# STEP 2 — BASIC FLAGS
# =====================================================

print("[*] STEP 2 — Building basic event flags...")

df["is_failed_login"] = (df["event_id"] == 4625).astype(int)
df["is_successful_login"] = (df["event_id"] == 4624).astype(int)
df["is_privileged"] = (df["event_id"] == 4672).astype(int)
df["is_process_exec"] = (df["event_id"] == 4688).astype(int)

SUSPICIOUS_PROCESS_PATTERN = (
    r"powershell|cmd|wmic|psexec|mimikatz|procdump|ntdsutil|secretsdump|"
    r"bloodhound|sharphound|rubeus|certutil|bitsadmin|mshta|regsvr32|"
    r"rundll32|wscript|cscript|net\.exe|net1\.exe|nltest|dsquery|csvde|ldifde"
)

df["suspicious_process"] = df["process_name"].str.contains(
    SUSPICIOUS_PROCESS_PATTERN,
    case=False,
    na=False
).astype(int)

# After-hours and weekend flags
df["after_hours_flag"] = (
    (df["login_hour"] < AFTER_HOURS_END) | (df["login_hour"] >= AFTER_HOURS_START)
).astype(int)
df["is_weekend"] = df["timestamp"].dt.dayofweek.isin([5, 6]).astype(int)

print(f"[+] Failed logins: {df['is_failed_login'].sum()}")
print(f"[+] Successful logins: {df['is_successful_login'].sum()}")
print(f"[+] Privileged events: {df['is_privileged'].sum()}")
print(f"[+] Process executions: {df['is_process_exec'].sum()}")
print(f"[+] Suspicious processes: {df['suspicious_process'].sum()}")
print(f"[+] After-hours events: {df['after_hours_flag'].sum()}")
print(f"[+] Weekend events: {df['is_weekend'].sum()}")

# =====================================================
# STEP 3 — BEHAVIORAL AGGREGATION
# =====================================================

print("[*] STEP 3 — Computing behavioral aggregations...")

df["user_event_count"] = df.groupby("username")["event_id"].transform("count")
df["user_failed_count"] = df.groupby("username")["is_failed_login"].transform("sum")
df["user_unique_machines"] = df.groupby("username")["machine"].transform("nunique")
df["user_unique_ips"] = df.groupby("username")["source_ip"].transform("nunique")
df["ip_event_count"] = df.groupby("source_ip")["event_id"].transform("count")

user_avg_hour = df.groupby("username")["login_hour"].transform("mean")
df["hour_deviation"] = abs(df["login_hour"] - user_avg_hour)

# Rolling 10-minute brute force window per user
# Sort only by username so each group is kept together; timestamp sort happens inside _rolling_10min
_sorted = df.sort_values("username").copy()
_sorted["_orig_idx"] = _sorted.index

def _rolling_10min(g):
    g = g.sort_values("timestamp")
    valid = g["timestamp"].notna()
    result = pd.Series(0, index=g["_orig_idx"].values)
    if valid.any():
        s = g[valid].set_index("timestamp")["is_failed_login"]
        rolled = s.rolling("10min").sum().fillna(0).astype(int)
        result[g[valid]["_orig_idx"].values] = rolled.values
    return result

failed_10min = (
    _sorted.groupby("username", group_keys=False)
    .apply(_rolling_10min)
)
df["failed_last_10min"] = failed_10min.reindex(df.index).fillna(0).astype(int)

# IP subnet extraction (first 3 octets); non-IP addresses get UNKNOWN_SUBNET
df["ip_subnet"] = df["source_ip"].str.extract(r"^(\d+\.\d+\.\d+)\.", expand=False).fillna(UNKNOWN_SUBNET)

numeric_cols = df.select_dtypes(include=[np.number]).columns
df[numeric_cols] = df[numeric_cols].fillna(0)

print(f"[+] Unique users: {df['username'].nunique()}")
print(f"[+] Max user failed count: {df['user_failed_count'].max()}")
print(f"[+] Max failed_last_10min: {df['failed_last_10min'].max()}")

# =====================================================
# STEP 4 — ENCODING
# =====================================================

print("[*] STEP 4 — Encoding categorical features...")

le_subnet = LabelEncoder()
df["ip_subnet_enc"] = le_subnet.fit_transform(df["ip_subnet"].astype(str))

print(f"[+] Unique IP subnets encoded: {df['ip_subnet'].nunique()}")

# =====================================================
# STEP 5 — ISOLATION FOREST
# =====================================================

print("[*] STEP 5 — Running Isolation Forest anomaly detection...")

features = df[[
    "login_hour",
    "day",
    "is_failed_login",
    "is_privileged",
    "is_process_exec",
    "suspicious_process",
    "ip_subnet_enc",
    "user_event_count",
    "user_failed_count",
    "user_unique_machines",
    "user_unique_ips",
    "ip_event_count",
    "hour_deviation",
    "failed_last_10min",
    "after_hours_flag",
    "is_weekend"
]]

contamination_rate = CONTAMINATION_RATE

iso = IsolationForest(
    n_estimators=300,
    contamination=contamination_rate,
    random_state=42,
    n_jobs=-1
)

iso.fit(features)

df["anomaly_score_raw"] = iso.decision_function(features)
df["is_anomaly"] = iso.predict(features)
df["is_anomaly"] = (df["is_anomaly"] == -1).astype(int)

print(f"[+] Isolation Forest complete. Anomalies detected: {df['is_anomaly'].sum()} ({df['is_anomaly'].mean()*100:.1f}%)")

# =====================================================
# STEP 6 — ADVANCED DETECTION LAYERS
# =====================================================

print("[*] STEP 6 — Applying advanced rule-based detection layers...")

# 1️⃣ Brute Force Detection — time-windowed burst OR lifetime threshold
df["brute_force_flag"] = (
    (
        (df["user_failed_count"] > BRUTE_FORCE_LIFETIME_THRESHOLD) |
        (df["failed_last_10min"] >= BRUTE_FORCE_WINDOW_THRESHOLD)
    ) &
    (df["user_unique_ips"] > MIN_UNIQUE_IPS_FOR_BRUTE_FORCE)
).astype(int)

# 2️⃣ Privilege Escalation Pattern — only when failures preceded the success
df["privilege_escalation_flag"] = (
    (df["is_successful_login"] == 1) &
    (df["is_privileged"] == 1) &
    (df["user_failed_count"] > PRIVILEGE_ESC_FAILURE_THRESHOLD)
).astype(int)

# 3️⃣ Lateral Movement
df["lateral_movement_flag"] = (
    df["user_unique_machines"] > LATERAL_MOVEMENT_MACHINE_THRESHOLD
).astype(int)

# 4️⃣ Process-Based Attack
df["malicious_process_flag"] = (
    df["suspicious_process"] == 1
).astype(int)

# 5️⃣ Credential Stuffing — successful login after >N prior failures
df["credential_stuffing_flag"] = (
    (df["is_successful_login"] == 1) &
    (df["user_failed_count"] > CREDENTIAL_STUFFING_FAILURE_THRESHOLD)
).astype(int)

print(f"[+] Brute force flags: {df['brute_force_flag'].sum()}")
print(f"[+] Privilege escalation flags: {df['privilege_escalation_flag'].sum()}")
print(f"[+] Lateral movement flags: {df['lateral_movement_flag'].sum()}")
print(f"[+] Malicious process flags: {df['malicious_process_flag'].sum()}")
print(f"[+] Credential stuffing flags: {df['credential_stuffing_flag'].sum()}")
print(f"[+] After-hours flags: {df['after_hours_flag'].sum()}")

# =====================================================
# STEP 7 — MITRE ATT&CK MAPPING (vectorized)
# =====================================================

print("[*] STEP 7 — Mapping MITRE ATT&CK techniques (vectorized)...")

_brute       = np.where(df["brute_force_flag"] == 1,         "T1110 - Brute Force", "")
_priv_esc    = np.where(df["privilege_escalation_flag"] == 1, "T1078 - Valid Accounts", "")
_lateral     = np.where(df["lateral_movement_flag"] == 1,     "T1021 - Remote Services", "")
_malicious   = np.where(df["malicious_process_flag"] == 1,    "T1059 - Command & Scripting Interpreter", "")
_cred_stuff  = np.where(df["credential_stuffing_flag"] == 1,  "T1110.001 - Password Guessing", "")
_after_priv  = np.where(
    (df["after_hours_flag"] == 1) & (df["is_privileged"] == 1),
    "T1078.002 - Domain Accounts", ""
)

df["mitre_techniques"] = [
    ", ".join(v for v in row if v)
    for row in zip(_brute, _priv_esc, _lateral, _malicious, _cred_stuff, _after_priv)
]

events_with_techniques = (df["mitre_techniques"] != "").sum()
print(f"[+] Events with MITRE techniques mapped: {events_with_techniques}")

# =====================================================
# STEP 8 — CONFIDENCE SCORING SYSTEM
# =====================================================

print("[*] STEP 8 — Computing confidence and risk scores...")

df["rule_score"] = (
    df["brute_force_flag"] * 3 +
    df["privilege_escalation_flag"] * 1 +
    df["lateral_movement_flag"] * 3 +
    df["malicious_process_flag"] * 2 +
    df["credential_stuffing_flag"] * 3 +
    df["after_hours_flag"] * 1
)

df["ml_score"] = np.where(df["is_anomaly"] == 1, 3, 0)

df["total_threat_score"] = df["rule_score"] + df["ml_score"]

df["final_risk_level"] = np.select(
    [
        df["total_threat_score"] >= 7,
        df["total_threat_score"] >= 4,
        df["total_threat_score"] >= 2,
    ],
    ["CRITICAL", "HIGH", "MEDIUM"],
    default="LOW"
)

# =====================================================
# STEP 9 — EXPORT
# =====================================================

print("[*] STEP 9 — Exporting results...")

df.sort_values("total_threat_score", ascending=False, inplace=True)

df.to_csv("advanced_security_analysis.csv", index=False)

high_risk_df = df[df["final_risk_level"].isin(["CRITICAL", "HIGH"])]
high_risk_df.to_csv("high_risk_incidents.csv", index=False)

print(f"[+] Exported {len(df)} events to advanced_security_analysis.csv")
print(f"[+] Exported {len(high_risk_df)} high-risk incidents to high_risk_incidents.csv")

# =====================================================
# FINAL SUMMARY
# =====================================================

print("\n" + "=" * 55)
print("   ADVANCED SECURITY ENGINE v4 — DETECTION SUMMARY")
print("=" * 55)
print(f"  Total Events Analyzed    : {len(df)}")
print(f"  ML Anomalies Detected    : {df['is_anomaly'].sum()}")
print(f"  Brute Force Incidents    : {df['brute_force_flag'].sum()}")
print(f"  Credential Stuffing      : {df['credential_stuffing_flag'].sum()}")
print(f"  Privilege Escalation     : {df['privilege_escalation_flag'].sum()}")
print(f"  Lateral Movement         : {df['lateral_movement_flag'].sum()}")
print(f"  Malicious Processes      : {df['malicious_process_flag'].sum()}")
print(f"  After-Hours Activity     : {df['after_hours_flag'].sum()}")
print(f"  Weekend Activity         : {df['is_weekend'].sum()}")
print("-" * 55)
print(f"  CRITICAL Risk Events     : {(df['final_risk_level'] == 'CRITICAL').sum()}")
print(f"  HIGH Risk Events         : {(df['final_risk_level'] == 'HIGH').sum()}")
print(f"  MEDIUM Risk Events       : {(df['final_risk_level'] == 'MEDIUM').sum()}")
print(f"  LOW Risk Events          : {(df['final_risk_level'] == 'LOW').sum()}")
print("=" * 55)
print("[+] ADVANCED SECURITY ENGINE v4 COMPLETE")
