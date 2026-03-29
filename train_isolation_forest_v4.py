import os
import sys
import time
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest
import urllib.parse
from sqlalchemy import create_engine
import os
import dotenv

dotenv.load_dotenv()

# =====================================================
# DATABASE CONFIGURATION
# =====================================================
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "threatweaver_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS")
DB_PORT = os.getenv("DB_PORT", "5432")

# Safely encode the password to handle special characters (like # or @)
SAFE_DB_PASS = urllib.parse.quote_plus(DB_PASS)

# SQLAlchemy connection string for reading and writing DataFrames cleanly
DB_URI = f"postgresql://{DB_USER}:{SAFE_DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Create a global database engine
engine = create_engine(DB_URI)

# =====================================================
# CONFIGURATION CONSTANTS
# =====================================================
CONTAMINATION_RATE = 0.03

BRUTE_FORCE_LIFETIME_THRESHOLD = 10   # total failures per user lifetime
BRUTE_FORCE_WINDOW_THRESHOLD = 5      # failures within a 10-minute window
MIN_UNIQUE_IPS_FOR_BRUTE_FORCE = 1    # must have >1 source IP to flag brute force
LATERAL_MOVEMENT_MACHINE_THRESHOLD = 1  # flag if user touches >= 2 machines total

CREDENTIAL_STUFFING_FAILURE_THRESHOLD = 5
PRIVILEGE_ESC_FAILURE_THRESHOLD = 0

AFTER_HOURS_START = 20
AFTER_HOURS_END = 6

UNKNOWN_SUBNET = "N/A"

PASSWORD_SPRAY_IP_UNIQUE_USERS_THRESHOLD = 6
ACCOUNT_ENUM_IP_UNIQUE_USERS_THRESHOLD = 12
KERBEROAST_TGS_PER_USER_THRESHOLD = 6

# Rolling 10-minute brute force window per user
def _rolling_10min(g):
    g = g.sort_values("timestamp")
    valid = g["timestamp"].notna()
    result = pd.Series(0, index=g["_orig_idx"].values)
    if valid.any():
        s = g[valid].set_index("timestamp")["is_failed_login"]
        rolled = s.rolling("10min").sum().fillna(0).astype(int)
        result[g[valid]["_orig_idx"].values] = rolled.values
    return result

def main():
    # =====================================================
    # STEP 1 — LOAD DATA FROM DATABASE
    # =====================================================
    print("[*] STEP 1 — Loading and validating data from Database (in batches)...")

    try:
        # Fetch only the most recent 100,000 events to ensure stable memory usage on the 4GB VM
        query = "SELECT * FROM raw_logs ORDER BY timestamp DESC LIMIT 100000;"
        
        # Read the data in chunks of 10,000 rows to prevent memory overload
        chunk_iterator = pd.read_sql(query, engine, chunksize=10000)
        
        # Stitch the chunks together safely into one final DataFrame
        df = pd.concat(chunk_iterator, ignore_index=True)

    except Exception as e:
        print(f"[ERROR] Failed to read from database: {e}")
        sys.exit(1)

    if df.empty:
        print("[ERROR] The raw_logs database table is empty. Ensure log collectors are running.")
        sys.exit(1)

    # Convert the DB 'source_machine' column to 'machine' to match existing ML logic
    if "source_machine" in df.columns:
        df.rename(columns={"source_machine": "machine"}, inplace=True)
    
        # Map the new tags back to the shorter versions the code expects
        df["machine"] = df["machine"].replace({
            "DOMAIN_CONTROLLER": "DC",
            "CLIENT_MACHINE": "CLIENT"
        })
    else:
        df["machine"] = "UNKNOWN"

    # Ensure required columns exist and handle N/A formatting
    for col in ["process_name", "command_line", "source_ip", "username"]:
        if col not in df.columns:
            df[col] = "N/A"

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["login_hour"] = df["timestamp"].dt.hour.fillna(0).astype(int)
    df["day"] = df["timestamp"].dt.day.fillna(0).astype(int)

    # Normalize types
    df["source_ip"] = df["source_ip"].fillna("N/A").astype(str)
    df["process_name"] = df["process_name"].fillna("N/A").astype(str)
    df["command_line"] = df["command_line"].fillna("").astype(str)

    print(f"[+] Loaded {len(df)} total events from database.")

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
        SUSPICIOUS_PROCESS_PATTERN, case=False, na=False
    ).astype(int)

    SUSPICIOUS_CMDLINE_PATTERN = (
        r"mimikatz|sekurlsa|lsadump|dcsync|rubeus|kerberoast|asreproast|"
        r"ntdsutil|vssadmin|wmic\s+process|psexec|procdump|comsvcs\.dll|"
        r"reg\s+save|lsass|sam|system|security"
    )

    df["suspicious_commandline"] = df["command_line"].str.contains(
        SUSPICIOUS_CMDLINE_PATTERN, case=False, na=False
    ).astype(int)

    df["after_hours_flag"] = (
        (df["login_hour"] < AFTER_HOURS_END) | (df["login_hour"] >= AFTER_HOURS_START)
    ).astype(int)

    df["is_weekend"] = df["timestamp"].dt.dayofweek.isin([5, 6]).astype(int)

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

    df["_orig_idx"] = df.index
    
    # Only copy the 4 columns we actually need! Drops memory usage from ~1.5GB to ~30MB.
    _sorted = df[["username", "timestamp", "is_failed_login", "_orig_idx"]].sort_values("username")
    
    # include_groups=False resolves the Pandas apply() deprecation warning
    failed_10min = (
        _sorted.groupby("username", group_keys=False)
        .apply(_rolling_10min, include_groups=False)
    )
    df["failed_last_10min"] = failed_10min.reindex(df.index).fillna(0).astype(int)

    df["ip_subnet"] = df["source_ip"].str.extract(r"^(\d+\.\d+\.\d+)\.", expand=False).fillna(UNKNOWN_SUBNET)

    _failed = df[df["is_failed_login"] == 1]
    ip_unique_failed_users = _failed.groupby("source_ip")["username"].nunique()
    df["ip_unique_failed_users"] = df["source_ip"].map(ip_unique_failed_users).fillna(0).astype(int)

    _tgs = df[df["is_kerberos_tgs"] == 1]
    user_tgs_count = _tgs.groupby("username")["event_id"].count()
    df["user_tgs_count"] = df["username"].map(user_tgs_count).fillna(0).astype(int)

    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)

    # =====================================================
    # STEP 4 — ENCODING
    # =====================================================
    print("[*] STEP 4 — Encoding categorical features...")
    le_subnet = LabelEncoder()
    df["ip_subnet_enc"] = le_subnet.fit_transform(df["ip_subnet"].astype(str))

    # =====================================================
    # STEP 5 — ISOLATION FOREST
    # =====================================================
    print("[*] STEP 5 — Running Isolation Forest anomaly detection...")

    features = df[[
        "login_hour", "day", "is_failed_login", "is_privileged", "is_process_exec",
        "suspicious_process", "suspicious_commandline", "is_kerberos_tgt", "is_kerberos_tgs",
        "ip_subnet_enc", "user_event_count", "user_failed_count", "user_unique_machines",
        "user_unique_ips", "ip_event_count", "hour_deviation", "failed_last_10min",
        "after_hours_flag", "is_weekend", "ip_unique_failed_users", "user_tgs_count"
    ]]

    iso = IsolationForest(
        n_estimators=100,       # Lowered from 300 to save RAM (100 is the industry standard)
        contamination=CONTAMINATION_RATE,
        random_state=42,
        n_jobs=1                # Changed from -1 to 1 to stop memory-hogging multiprocessing
    )

    iso.fit(features)

    df["anomaly_score_raw"] = iso.decision_function(features)
    df["is_anomaly"] = (iso.predict(features) == -1).astype(int)

    # =====================================================
    # STEP 6 — ADVANCED DETECTION LAYERS
    # =====================================================
    print("[*] STEP 6 — Applying advanced rule-based detection layers...")

    df["brute_force_flag"] = (
        (
            (df["user_failed_count"] > BRUTE_FORCE_LIFETIME_THRESHOLD) |
            (df["failed_last_10min"] >= BRUTE_FORCE_WINDOW_THRESHOLD)
        ) &
        (df["user_unique_ips"] > MIN_UNIQUE_IPS_FOR_BRUTE_FORCE)
    ).astype(int)

    df["privilege_escalation_flag"] = (
        (df["is_successful_login"] == 1) &
        (df["is_privileged"] == 1) &
        (df["user_failed_count"] > PRIVILEGE_ESC_FAILURE_THRESHOLD)
    ).astype(int)

    df["lateral_movement_flag"] = (
        df["user_unique_machines"] > LATERAL_MOVEMENT_MACHINE_THRESHOLD
    ).astype(int)

    df["malicious_process_flag"] = (
        (df["suspicious_process"] == 1) |
        (df["suspicious_commandline"] == 1)
    ).astype(int)

    df["credential_stuffing_flag"] = (
        (df["is_successful_login"] == 1) &
        (df["user_failed_count"] > CREDENTIAL_STUFFING_FAILURE_THRESHOLD)
    ).astype(int)

    df["password_spray_flag"] = (
        (df["ip_unique_failed_users"] >= PASSWORD_SPRAY_IP_UNIQUE_USERS_THRESHOLD) &
        (df["is_failed_login"] == 1)
    ).astype(int)

    df["account_enumeration_flag"] = (
        (df["ip_unique_failed_users"] >= ACCOUNT_ENUM_IP_UNIQUE_USERS_THRESHOLD) &
        (df["is_failed_login"] == 1)
    ).astype(int)

    df["success_after_fail_flag"] = (
        (df["user_failed_count"] >= 5) &
        (df["user_success_count"] >= 1) &
        (df["is_successful_login"] == 1)
    ).astype(int)

    df["kerberoasting_flag"] = (
        (df["user_tgs_count"] >= KERBEROAST_TGS_PER_USER_THRESHOLD) &
        (df["is_kerberos_tgs"] == 1)
    ).astype(int)

    # =====================================================
    # STEP 7 — MITRE ATT&CK MAPPING (vectorized)
    # =====================================================
    print("[*] STEP 7 — Mapping MITRE ATT&CK techniques...")

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
    # STEP 9 — EXPORT TO DATABASE
    # =====================================================
    print("[*] STEP 9 — Exporting results to Database (in stable batches)...")
    df.sort_values("total_threat_score", ascending=False, inplace=True)

    try:
        # Convert timestamp to a standard string to prevent PostgreSQL timezone crashes
        df["timestamp"] = df["timestamp"].astype(str)
        
        # Lower chunksize and REMOVE method="multi" to bypass the psycopg2 memory crash
        df.to_sql(
            "analyzed_logs", 
            engine, 
            if_exists="replace", 
            index=False, 
            chunksize=1000  
        )
        print(f"[+] Successfully exported {len(df)} analyzed events to the 'analyzed_logs' database table.")
        
    except Exception as e:
        import traceback
        print(f"[-] Database Error during export: {e}")
        traceback.print_exc()

    # =====================================================
    # FINAL SUMMARY
    # =====================================================
    print("\n" + "=" * 60)
    print("   ADVANCED SECURITY ENGINE v4 — DETECTION SUMMARY (DATABASE)")
    print("=" * 60)
    print(f"  Total Events Analyzed    : {len(df)}")
    print(f"  CRITICAL Risk Events     : {(df['final_risk_level'] == 'CRITICAL').sum()}")
    print(f"  HIGH Risk Events         : {(df['final_risk_level'] == 'HIGH').sum()}")
    print("=" * 60)
    print("[+] ADVANCED SECURITY ENGINE COMPLETE")

if __name__ == "__main__":
    print("[*] Scheduler started: running every 60 seconds. Press Ctrl+C to stop.")
    try:
        while True:
            cycle_start = time.time()
            main()
            elapsed = time.time() - cycle_start
            sleep_for = max(0, 60 - elapsed)
            print(f"[*] Sleeping for {sleep_for:.1f} seconds before next run...")
            time.sleep(sleep_for)
    except KeyboardInterrupt:
        print("\n[+] Scheduler stopped by user.")
