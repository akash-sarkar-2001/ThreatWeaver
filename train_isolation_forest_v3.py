import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest

# =====================================================
# STEP 1 — LOAD DATA
# =====================================================

dc = pd.read_csv("dc_logs.csv")
client = pd.read_csv("client_logs.csv")

dc["machine"] = "DC"
client["machine"] = "CLIENT"

for col in ["process_name", "command_line", "source_ip"]:
    if col not in dc.columns:
        dc[col] = "N/A"
    if col not in client.columns:
        client[col] = "N/A"

df = pd.concat([dc, client], ignore_index=True)

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df["login_hour"] = df["timestamp"].dt.hour.fillna(0)
df["day"] = df["timestamp"].dt.day.fillna(0)

# =====================================================
# STEP 2 — BASIC FLAGS
# =====================================================

df["is_failed_login"] = (df["event_id"] == 4625).astype(int)
df["is_successful_login"] = (df["event_id"] == 4624).astype(int)
df["is_privileged"] = (df["event_id"] == 4672).astype(int)
df["is_process_exec"] = (df["event_id"] == 4688).astype(int)

df["suspicious_process"] = df["process_name"].str.contains(
    "powershell|cmd|wmic|psexec|mimikatz",
    case=False,
    na=False
).astype(int)

# =====================================================
# STEP 3 — BEHAVIORAL AGGREGATION
# =====================================================

df["user_event_count"] = df.groupby("username")["event_id"].transform("count")
df["user_failed_count"] = df.groupby("username")["is_failed_login"].transform("sum")
df["user_unique_machines"] = df.groupby("username")["machine"].transform("nunique")
df["user_unique_ips"] = df.groupby("username")["source_ip"].transform("nunique")
df["ip_event_count"] = df.groupby("source_ip")["event_id"].transform("count")

user_avg_hour = df.groupby("username")["login_hour"].transform("mean")
df["hour_deviation"] = abs(df["login_hour"] - user_avg_hour)

df.fillna(0, inplace=True)

# =====================================================
# STEP 4 — ENCODING
# =====================================================

le_user = LabelEncoder()
le_machine = LabelEncoder()

df["user_enc"] = le_user.fit_transform(df["username"].astype(str))
df["machine_enc"] = le_machine.fit_transform(df["machine"].astype(str))

# =====================================================
# STEP 5 — ISOLATION FOREST
# =====================================================

features = df[[
    "login_hour",
    "day",
    "is_failed_login",
    "is_privileged",
    "is_process_exec",
    "suspicious_process",
    "user_enc",
    "machine_enc",
    "user_event_count",
    "user_failed_count",
    "user_unique_machines",
    "user_unique_ips",
    "ip_event_count",
    "hour_deviation"
]]

contamination_rate = 0.03

iso = IsolationForest(
    n_estimators=300,
    contamination=contamination_rate,
    random_state=42,
    n_jobs=-1
)

iso.fit(features)

df["anomaly_score_raw"] = iso.decision_function(features)
df["is_anomaly"] = iso.predict(features)
df["is_anomaly"] = df["is_anomaly"].apply(lambda x: 1 if x == -1 else 0)

# =====================================================
# STEP 6 — ADVANCED DETECTION LAYERS
# =====================================================

# 1️⃣ Brute Force Detection
df["brute_force_flag"] = (
    (df["user_failed_count"] > 10) &
    (df["user_unique_ips"] > 1)
).astype(int)

# 2️⃣ Privilege Escalation Pattern
df["privilege_escalation_flag"] = (
    (df["is_successful_login"] == 1) &
    (df["is_privileged"] == 1)
).astype(int)

# 3️⃣ Lateral Movement
df["lateral_movement_flag"] = (
    df["user_unique_machines"] > 3
).astype(int)

# 4️⃣ Process-Based Attack
df["malicious_process_flag"] = (
    df["suspicious_process"] == 1
).astype(int)

# =====================================================
# STEP 7 — MITRE ATT&CK MAPPING
# =====================================================

def map_mitre(row):
    techniques = []

    if row["brute_force_flag"] == 1:
        techniques.append("T1110 - Brute Force")

    if row["privilege_escalation_flag"] == 1:
        techniques.append("T1078 - Valid Accounts")

    if row["lateral_movement_flag"] == 1:
        techniques.append("T1021 - Remote Services")

    if row["malicious_process_flag"] == 1:
        techniques.append("T1059 - Command & Scripting Interpreter")

    return ", ".join(techniques)

df["mitre_techniques"] = df.apply(map_mitre, axis=1)

# =====================================================
# STEP 8 — CONFIDENCE SCORING SYSTEM
# =====================================================

df["rule_score"] = (
    df["brute_force_flag"] * 2 +
    df["privilege_escalation_flag"] * 2 +
    df["lateral_movement_flag"] * 2 +
    df["malicious_process_flag"] * 2
)

df["ml_score"] = np.where(df["is_anomaly"] == 1, 3, 0)

df["total_threat_score"] = df["rule_score"] + df["ml_score"]

def classify_risk(score):
    if score >= 7:
        return "CRITICAL"
    elif score >= 4:
        return "HIGH"
    elif score >= 2:
        return "MEDIUM"
    else:
        return "LOW"

df["final_risk_level"] = df["total_threat_score"].apply(classify_risk)

# =====================================================
# STEP 9 — EXPORT
# =====================================================

df.sort_values("total_threat_score", ascending=False, inplace=True)

df.to_csv("advanced_security_analysis.csv", index=False)

df[df["final_risk_level"].isin(["CRITICAL", "HIGH"])].to_csv(
    "high_risk_incidents.csv", index=False
)

print("\n[+] ADVANCED SECURITY ENGINE COMPLETE")
print("[+] Total Anomalies:", df["is_anomaly"].sum())
print("[+] Critical Incidents:", len(df[df["final_risk_level"] == "CRITICAL"]))
print("[+] High Incidents:", len(df[df["final_risk_level"] == "HIGH"]))