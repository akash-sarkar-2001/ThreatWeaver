import sys
import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest

# =====================================================
# CONFIGURATION CONSTANTS
# =====================================================

CONTAMINATION_RATE = 0.03

BRUTE_FORCE_LIFETIME_THRESHOLD = 10   # total failures per user lifetime
BRUTE_FORCE_WINDOW_THRESHOLD = 5      # failures within a 10-minute window
MIN_UNIQUE_IPS_FOR_BRUTE_FORCE = 1    # must have >1 source IP to flag brute force

# v3/v4 originally used 3; in a 2-machine lab this often never triggers.
LATERAL_MOVEMENT_MACHINE_THRESHOLD = 1  # flag if user touches >= 2 machines total

CREDENTIAL_STUFFING_FAILURE_THRESHOLD = 5
PRIVILEGE_ESC_FAILURE_THRESHOLD = 0

AFTER_HOURS_START = 20
AFTER_HOURS_END = 6

UNKNOWN_SUBNET = "N/A"

# IP-based detections
PASSWORD_SPRAY_IP_UNIQUE_USERS_THRESHOLD = 6
ACCOUNT_ENUM_IP_UNIQUE_USERS_THRESHOLD = 12

# Kerberoast indicator
KERBEROAST_TGS_PER_USER_THRESHOLD = 6

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

# Normalize types
df["source_ip"] = df["source_ip"].fillna("N/A").astype(str)
df["process_name"] = df["process_name"].fillna("N/A").astype(str)
df["command_line"] = df["command_line"].fillna("").astype(str)

print(f"[+] Loaded {len(df)} total events ({len(dc)} DC + {len(client)} client)")

# =====================================================
# STEP 2 — BASIC FLAGS
# =====================================================

print("[*] STEP 2 — Building basic event flags...")

df["is_failed_login"] = (df["event_id"] == 4625).astype(int)
df["is_successful_login"] = (df["event_id"] == 4624).astype(int)
df["is_privileged"] = (df["event_id"] == 4672).astype(int)
df["is_process_exec"] = (df["event_id"] == 4688).astype(int)

df["is_kerberos_tgt"] = (df["event_id"] == 4768).astype(int)
df["is_kerberos_tgs"] = (df["event_id"] == 4769).astype(int)

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

# command-line based suspicion (helps when process_name is generic)
SUSPICIOUS_CMDLINE_PATTERN = (
    r"mimikatz|sekurlsa|lsadump|dcsync|rubeus|kerberoast|asreproast|"
    r"ntdsutil|vssadmin|wmic\s+process|psexec|procdump|comsvcs\.dll|"
    r"reg\s+save|lsass|sam|system|security"
)

df["suspicious_commandline"] = df["command_line"].str.contains(
    SUSPICIOUS_CMDLINE_PATTERN,
    case=False,
    na=False
).astype(int)

df["after_hours_flag"] = (
    (df["login_hour"] < AFTER_HOURS_END) | (df["login_hour"] >= AFTER_HOURS_START)
).astype(int)

df["is_weekend"] = df["timestamp"].dt.dayofweek.isin([5, 6]).astype(int)

print(f"[+] Failed logins: {df['is_failed_login'].sum()}")
print(f"[+] Successful logins: {df['is_successful_login'].sum()}")
print(f"[+] Privileged events: {df['is_privileged'].sum()}")
print(f"[+] Process executions: {df['is_process_exec'].sum()}")
print(f"[+] Suspicious processes: {df['suspicious_process'].sum()}")
print(f"[+] Suspicious command lines: {df['suspicious_commandline'].sum()}")
print(f"[+] Kerberos TGT (4768): {df['is_kerberos_tgt'].sum()}")
print(f"[+] Kerberos TGS (4769): {df['is_kerberos_tgs'].sum()}")
print(f"[+] After-hours events: {df['after_hours_flag'].sum()}")
print(f"[+] Weekend events: {df['is_weekend'].sum()}")

# =====================================================
# STEP 3 — BEHAVIORAL AGGREGATION
# =====================================================

print("[*] STEP 3 — Computing behavioral aggregations...")

df["user_event_count"] = df.groupby("username")["event_id"].transform("count")
df["user_failed_count"] = df.groupby("username")["is_failed_login"].transform("sum")
df["user_success_count"] = df.groupby("username")["is_successful_login"].transform("sum")

df["user_unique_machines"] = df.groupby("username")["machine"].transform("nunique")
df["user_unique_ips"] = df.groupby("username")["source_ip"].transform("nunique")
df["ip_event_count"] = df.groupby("source_ip")["event_id"].transform("count")

user_avg_hour = df.groupby("username")["login_hour"].transform("mean")
df["hour_deviation"] = abs(df["login_hour"] - user_avg_hour)

# Rolling 10-minute brute force window per user
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

# NEW: IP-based unique failed users (spraying/enumeration)
_failed = df[df["is_failed_login"] == 1]
ip_unique_failed_users = _failed.groupby("source_ip")["username"].nunique()
df["ip_unique_failed_users"] = df["source_ip"].map(ip_unique_failed_users).fillna(0).astype(int)

# NEW: Kerberoast indicator (TGS requests per user)
_tgs = df[df["is_kerberos_tgs"] == 1]
user_tgs_count = _tgs.groupby("username")["event_id"].count()
df["user_tgs_count"] = df["username"].map(user_tgs_count).fillna(0).astype(int)

numeric_cols = df.select_dtypes(include=[np.number]).columns
df[numeric_cols] = df[numeric_cols].fillna(0)

print(f"[+] Unique users: {df['username'].nunique()}")
print(f"[+] Max user failed count: {df['user_failed_count'].max()}")
print(f"[+] Max failed_last_10min: {df['failed_last_10min'].max()}")
print(f"[+] Max ip_unique_failed_users: {df['ip_unique_failed_users'].max()}")
print(f"[+] Max user_tgs_count: {df['user_tgs_count'].max()}")

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
    "suspicious_commandline",
    "is_kerberos_tgt",
    "is_kerberos_tgs",
    "ip_subnet_enc",
    "user_event_count",
    "user_failed_count",
    "user_unique_machines",
    "user_unique_ips",
    "ip_event_count",
    "hour_deviation",
    "failed_last_10min",
    "after_hours_flag",
    "is_weekend",
    "ip_unique_failed_users",
    "user_tgs_count"
]]

iso = IsolationForest(
    n_estimators=300,
    contamination=CONTAMINATION_RATE,
    random_state=42,
    n_jobs=-1
)

iso.fit(features)

df["anomaly_score_raw"] = iso.decision_function(features)
df["is_anomaly"] = (iso.predict(features) == -1).astype(int)

print(f"[+] Isolation Forest complete. Anomalies detected: {df['is_anomaly'].sum()} ({df['is_anomaly'].mean()*100:.1f}%)")

# =====================================================
# STEP 6 — ADVANCED DETECTION LAYERS
# =====================================================

print("[*] STEP 6 — Applying advanced rule-based detection layers...")

# 1️⃣ Brute Force — burst OR lifetime threshold
df["brute_force_flag"] = (
    (
        (df["user_failed_count"] > BRUTE_FORCE_LIFETIME_THRESHOLD) |
        (df["failed_last_10min"] >= BRUTE_FORCE_WINDOW_THRESHOLD)
    ) &
    (df["user_unique_ips"] > MIN_UNIQUE_IPS_FOR_BRUTE_FORCE)
).astype(int)

# 2️⃣ Privilege escalation pattern (privileged success after at least some failures)
df["privilege_escalation_flag"] = (
    (df["is_successful_login"] == 1) &
    (df["is_privileged"] == 1) &
    (df["user_failed_count"] > PRIVILEGE_ESC_FAILURE_THRESHOLD)
).astype(int)

# 3️⃣ Lateral movement (lab-friendly)
df["lateral_movement_flag"] = (
    df["user_unique_machines"] > LATERAL_MOVEMENT_MACHINE_THRESHOLD
).astype(int)

# 4️⃣ Process-based attack (process OR cmdline)
df["malicious_process_flag"] = (
    (df["suspicious_process"] == 1) |
    (df["suspicious_commandline"] == 1)
).astype(int)

# 5️⃣ Credential stuffing (successful login after many failures)
df["credential_stuffing_flag"] = (
    (df["is_successful_login"] == 1) &
    (df["user_failed_count"] > CREDENTIAL_STUFFING_FAILURE_THRESHOLD)
).astype(int)

# 6️⃣ Password spraying (per-IP)
df["password_spray_flag"] = (
    (df["ip_unique_failed_users"] >= PASSWORD_SPRAY_IP_UNIQUE_USERS_THRESHOLD) &
    (df["is_failed_login"] == 1)
).astype(int)

# 7️⃣ Account enumeration (stronger per-IP)
df["account_enumeration_flag"] = (
    (df["ip_unique_failed_users"] >= ACCOUNT_ENUM_IP_UNIQUE_USERS_THRESHOLD) &
    (df["is_failed_login"] == 1)
).astype(int)

# 8️⃣ Success after fail (non-privileged correlation)
df["success_after_fail_flag"] = (
    (df["user_failed_count"] >= 5) &
    (df["user_success_count"] >= 1) &
    (df["is_successful_login"] == 1)
).astype(int)

# 9️⃣ Kerberoasting indicator
df["kerberoasting_flag"] = (
    (df["user_tgs_count"] >= KERBEROAST_TGS_PER_USER_THRESHOLD) &
    (df["is_kerberos_tgs"] == 1)
).astype(int)

print(f"[+] Brute force flags: {df['brute_force_flag'].sum()}")
print(f"[+] Privilege escalation flags: {df['privilege_escalation_flag'].sum()}")
print(f"[+] Lateral movement flags: {df['lateral_movement_flag'].sum()}")
print(f"[+] Malicious process flags: {df['malicious_process_flag'].sum()}")
print(f"[+] Credential stuffing flags: {df['credential_stuffing_flag'].sum()}")
print(f"[+] Password spray flags: {df['password_spray_flag'].sum()}")
print(f"[+] Account enumeration flags: {df['account_enumeration_flag'].sum()}")
print(f"[+] Success-after-fail flags: {df['success_after_fail_flag'].sum()}")
print(f"[+] Kerberoasting flags: {df['kerberoasting_flag'].sum()}")
print(f"[+] After-hours flags: {df['after_hours_flag'].sum()}")

# =====================================================
# STEP 7 — MITRE ATT&CK MAPPING (vectorized)
# =====================================================

print("[*] STEP 7 — Mapping MITRE ATT&CK techniques (vectorized)...")

_brute        = np.where(df["brute_force_flag"] == 1, "T1110 - Brute Force", "")
_spray        = np.where(df["password_spray_flag"] == 1, "T1110.003 - Brute Force: Password Spraying", "")
_enum         = np.where(df["account_enumeration_flag"] == 1, "T1087.002 - Account Discovery: Domain Account", "")
_priv_esc     = np.where(df["privilege_escalation_flag"] == 1, "T1078 - Valid Accounts", "")
_success_af   = np.where(df["success_after_fail_flag"] == 1, "T1078 - Valid Accounts", "")
_lateral      = np.where(df["lateral_movement_flag"] == 1, "T1021 - Remote Services", "")
_malicious    = np.where(df["malicious_process_flag"] == 1, "T1059 - Command & Scripting Interpreter", "")
_cred_stuff   = np.where(df["credential_stuffing_flag"] == 1, "T1110.004 - Brute Force: Credential Stuffing", "")
_kerberoast   = np.where(df["kerberoasting_flag"] == 1, "T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting", "")

_after_priv = np.where(
    (df["after_hours_flag"] == 1) & (df["is_privileged"] == 1),
    "T1078.002 - Domain Accounts",
    ""
)

df["mitre_techniques"] = [
    ", ".join(v for v in row if v)
    for row in zip(_brute, _spray, _enum, _priv_esc, _success_af, _lateral, _malicious, _cred_stuff, _kerberoast, _after_priv)
]

events_with_techniques = (df["mitre_techniques"] != "").sum()
print(f"[+] Events with MITRE techniques mapped: {events_with_techniques}")

# =====================================================
# STEP 8 — CONFIDENCE SCORING SYSTEM
# =====================================================

print("[*] STEP 8 — Computing confidence and risk scores...")

df["rule_score"] = (
    df["brute_force_flag"] * 3 +
    df["password_spray_flag"] * 2 +
    df["account_enumeration_flag"] * 1 +
    df["credential_stuffing_flag"] * 3 +
    df["success_after_fail_flag"] * 2 +
    df["privilege_escalation_flag"] * 2 +
    df["lateral_movement_flag"] * 3 +
    df["malicious_process_flag"] * 2 +
    df["kerberoasting_flag"] * 3 +
    df["after_hours_flag"] * 1
)

df["ml_score"] = np.where(df["is_anomaly"] == 1, 3, 0)
df["total_threat_score"] = df["rule_score"] + df["ml_score"]

df["final_risk_level"] = np.select(
    [
        df["total_threat_score"] >= 9,
        df["total_threat_score"] >= 6,
        df["total_threat_score"] >= 3,
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

print("\n" + "=" * 60)
print("   ADVANCED SECURITY ENGINE v4 — DETECTION SUMMARY (UPDATED)")
print("=" * 60)
print(f"  Total Events Analyzed    : {len(df)}")
print(f"  ML Anomalies Detected    : {df['is_anomaly'].sum()}")
print(f"  Brute Force Incidents    : {df['brute_force_flag'].sum()}")
print(f"  Password Spraying        : {df['password_spray_flag'].sum()}")
print(f"  Account Enumeration      : {df['account_enumeration_flag'].sum()}")
print(f"  Credential Stuffing      : {df['credential_stuffing_flag'].sum()}")
print(f"  Success After Fail       : {df['success_after_fail_flag'].sum()}")
print(f"  Privilege Escalation     : {df['privilege_escalation_flag'].sum()}")
print(f"  Lateral Movement         : {df['lateral_movement_flag'].sum()}")
print(f"  Malicious Processes      : {df['malicious_process_flag'].sum()}")
print(f"  Kerberoasting            : {df['kerberoasting_flag'].sum()}")
print(f"  After-Hours Activity     : {df['after_hours_flag'].sum()}")
print(f"  Weekend Activity         : {df['is_weekend'].sum()}")
print("-" * 60)
print(f"  CRITICAL Risk Events     : {(df['final_risk_level'] == 'CRITICAL').sum()}")
print(f"  HIGH Risk Events         : {(df['final_risk_level'] == 'HIGH').sum()}")
print(f"  MEDIUM Risk Events       : {(df['final_risk_level'] == 'MEDIUM').sum()}")
print(f"  LOW Risk Events          : {(df['final_risk_level'] == 'LOW').sum()}")
print("=" * 60)
print("[+] ADVANCED SECURITY ENGINE v4 COMPLETE")
