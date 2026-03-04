#!/usr/bin/env python3
"""
ThreatWeaver SOC Dashboard — Flask Backend
Reads advanced_security_analysis.csv and high_risk_incidents.csv
and exposes REST API endpoints for the dashboard frontend.
"""

import os
import sys
from collections import defaultdict

import pandas as pd
from flask import Flask, jsonify, render_template

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ANALYSIS_CSV = os.path.join(BASE_DIR, "advanced_security_analysis.csv")
HIGH_RISK_CSV = os.path.join(BASE_DIR, "high_risk_incidents.csv")
DC_LOGS_CSV = os.path.join(BASE_DIR, "dc_logs.csv")
CLIENT_LOGS_CSV = os.path.join(BASE_DIR, "client_logs.csv")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_analysis():
    """Return the main analysis DataFrame, or None if unavailable."""
    if not os.path.exists(ANALYSIS_CSV):
        return None
    try:
        return pd.read_csv(ANALYSIS_CSV, low_memory=False)
    except Exception:
        return None


def _load_high_risk():
    """Return the high-risk incidents DataFrame, or None if unavailable."""
    if not os.path.exists(HIGH_RISK_CSV):
        return None
    try:
        return pd.read_csv(HIGH_RISK_CSV, low_memory=False)
    except Exception:
        return None


def _safe_str(val):
    if pd.isna(val):
        return ""
    return str(val)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/summary")
def api_summary():
    df = _load_analysis()
    if df is None:
        return jsonify({"no_data": True})

    for col in ["is_anomaly", "final_risk_level", "total_threat_score", "username", "source_ip", "mitre_techniques"]:
        if col not in df.columns:
            df[col] = None

    total_events = int(len(df))
    anomalies = df[df["is_anomaly"] == 1]
    total_anomalies = int(len(anomalies))
    anomaly_rate = round((total_anomalies / total_events) * 100, 2) if total_events else 0

    risk_distribution = df["final_risk_level"].value_counts().to_dict()
    avg_threat_score = round(float(df["total_threat_score"].mean()), 2) if total_events else 0

    high_confidence_cases = int(len(df[df["total_threat_score"] >= 7]))
    medium_confidence_cases = int(len(df[df["total_threat_score"].between(4, 6)]))
    low_confidence_cases = int(len(df[df["total_threat_score"] <= 3]))

    high_risk = df[df["final_risk_level"].isin(["CRITICAL", "HIGH"])]
    unique_high_users = int(high_risk["username"].nunique())
    unique_high_ips = int(high_risk["source_ip"].nunique())
    unique_mitre = int(high_risk["mitre_techniques"].nunique())

    multi_user_flag = unique_high_users > 1
    multi_ip_flag = unique_high_ips > 1
    multi_technique_flag = unique_mitre > 1

    if high_confidence_cases > 5 and multi_user_flag and multi_ip_flag and multi_technique_flag:
        machine_verdict = "STRONG_CORRELATED_ATTACK"
    elif medium_confidence_cases > 0:
        machine_verdict = "MODERATE_CORRELATION_NO_CONFIRMED_COMPROMISE"
    else:
        machine_verdict = "LOW_CONFIDENCE_ACTIVITY"

    confidence_score = min(
        100,
        round(
            (high_confidence_cases * 5) +
            (medium_confidence_cases * 2) +
            (unique_mitre * 3) +
            (unique_high_ips * 2),
            2
        )
    )

    return jsonify({
        "total_events": total_events,
        "total_anomalies": total_anomalies,
        "anomaly_rate": anomaly_rate,
        "avg_threat_score": avg_threat_score,
        "high_confidence_cases": high_confidence_cases,
        "medium_confidence_cases": medium_confidence_cases,
        "low_confidence_cases": low_confidence_cases,
        "risk_distribution": risk_distribution,
        "machine_verdict": machine_verdict,
        "confidence_score": confidence_score,
    })


@app.route("/api/risk-distribution")
def api_risk_distribution():
    df = _load_analysis()
    if df is None:
        return jsonify({"no_data": True})

    if "final_risk_level" not in df.columns:
        return jsonify({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for level, cnt in df["final_risk_level"].value_counts().items():
        if level in counts:
            counts[level] = int(cnt)
    return jsonify(counts)


@app.route("/api/top-incidents")
def api_top_incidents():
    df = _load_analysis()
    if df is None:
        return jsonify({"no_data": True, "incidents": []})

    for col in ["username", "source_ip", "final_risk_level", "total_threat_score", "mitre_techniques"]:
        if col not in df.columns:
            df[col] = None

    top = (
        df.sort_values("total_threat_score", ascending=False)
        .head(20)[["username", "source_ip", "final_risk_level", "total_threat_score", "mitre_techniques"]]
        .copy()
    )

    records = []
    for _, row in top.iterrows():
        records.append({
            "username": _safe_str(row["username"]),
            "source_ip": _safe_str(row["source_ip"]),
            "risk_level": _safe_str(row["final_risk_level"]),
            "threat_score": float(row["total_threat_score"]) if pd.notna(row["total_threat_score"]) else 0,
            "mitre_techniques": _safe_str(row["mitre_techniques"]),
        })
    return jsonify({"incidents": records})


@app.route("/api/mitre-techniques")
def api_mitre_techniques():
    df = _load_analysis()
    if df is None:
        return jsonify({"no_data": True, "techniques": {}})

    if "mitre_techniques" not in df.columns:
        return jsonify({"techniques": {}})

    technique_counts: dict = defaultdict(int)
    for val in df["mitre_techniques"].dropna():
        for tech in str(val).split(","):
            tech = tech.strip()
            if tech:
                technique_counts[tech] += 1

    sorted_techs = dict(sorted(technique_counts.items(), key=lambda x: x[1], reverse=True))
    return jsonify({"techniques": sorted_techs})


@app.route("/api/timeline")
def api_timeline():
    df = _load_analysis()
    if df is None:
        return jsonify({"no_data": True, "timeline": []})

    if "timestamp" not in df.columns:
        return jsonify({"timeline": []})

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["hour_bucket"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:00")

    timeline = (
        df.groupby("hour_bucket")
        .size()
        .reset_index(name="count")
        .sort_values("hour_bucket")
    )

    return jsonify({
        "timeline": [
            {"hour": row["hour_bucket"], "count": int(row["count"])}
            for _, row in timeline.iterrows()
            if pd.notna(row["hour_bucket"])
        ]
    })


@app.route("/api/user-risk")
def api_user_risk():
    df = _load_analysis()
    if df is None:
        return jsonify({"no_data": True, "users": []})

    if "username" not in df.columns or "total_threat_score" not in df.columns:
        return jsonify({"users": []})

    user_risk = (
        df.groupby("username")["total_threat_score"]
        .max()
        .reset_index()
        .sort_values("total_threat_score", ascending=False)
        .head(10)
    )

    return jsonify({
        "users": [
            {"username": _safe_str(row["username"]), "max_threat_score": float(row["total_threat_score"])}
            for _, row in user_risk.iterrows()
        ]
    })


@app.route("/api/ip-analysis")
def api_ip_analysis():
    df = _load_analysis()
    if df is None:
        return jsonify({"no_data": True, "ips": []})

    if "source_ip" not in df.columns:
        return jsonify({"ips": []})

    ip_counts = (
        df[df["source_ip"].notna() & (df["source_ip"] != "N/A")]
        .groupby("source_ip")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
        .head(10)
    )

    return jsonify({
        "ips": [
            {"ip": _safe_str(row["source_ip"]), "count": int(row["count"])}
            for _, row in ip_counts.iterrows()
        ]
    })


@app.route("/api/detection-flags")
def api_detection_flags():
    """Return counts for all v4 rule-based detection flags."""
    df = _load_analysis()
    if df is None:
        return jsonify({"no_data": True})

    flag_cols = [
        "brute_force_flag", "password_spray_flag", "account_enumeration_flag",
        "credential_stuffing_flag", "success_after_fail_flag", "privilege_escalation_flag",
        "lateral_movement_flag", "malicious_process_flag", "kerberoasting_flag",
        "after_hours_flag", "is_weekend",
    ]

    result = {}
    for col in flag_cols:
        if col in df.columns:
            result[col] = int(df[col].sum())
        else:
            result[col] = 0
    return jsonify(result)


@app.route("/api/high-risk-incidents")
def api_high_risk_incidents():
    """Return top 20 rows from high_risk_incidents.csv as JSON records."""
    df = _load_high_risk()
    if df is None:
        return jsonify({"no_data": True, "incidents": []})

    key_cols = [
        "timestamp", "username", "source_ip", "final_risk_level",
        "total_threat_score", "mitre_techniques", "machine",
    ]
    cols = [c for c in key_cols if c in df.columns]
    top = df[cols].head(20).copy()

    records = []
    for _, row in top.iterrows():
        records.append({col: _safe_str(row[col]) for col in cols})
    return jsonify({"incidents": records})


@app.route("/api/log-metrics")
def api_log_metrics():
    """Return basic telemetry counts from dc_logs.csv and client_logs.csv."""
    result = {}

    for prefix, path in [("dc", DC_LOGS_CSV), ("client", CLIENT_LOGS_CSV)]:
        if not os.path.exists(path):
            result[f"{prefix}_rows"] = 0
            result[f"{prefix}_unique_users"] = 0
            result[f"{prefix}_unique_ips"] = 0
            result[f"{prefix}_brute_force_suspects"] = 0
            continue
        try:
            df = pd.read_csv(path, low_memory=False)
        except Exception:
            result[f"{prefix}_rows"] = 0
            result[f"{prefix}_unique_users"] = 0
            result[f"{prefix}_unique_ips"] = 0
            result[f"{prefix}_brute_force_suspects"] = 0
            continue

        result[f"{prefix}_rows"] = int(len(df))
        result[f"{prefix}_unique_users"] = int(df["username"].nunique()) if "username" in df.columns else 0
        result[f"{prefix}_unique_ips"] = int(df["source_ip"].nunique()) if "source_ip" in df.columns else 0

        if "username" in df.columns:
            user_fail_counts = df.groupby("username").size()
            result[f"{prefix}_brute_force_suspects"] = int((user_fail_counts >= 5).sum())
        else:
            result[f"{prefix}_brute_force_suspects"] = 0

    return jsonify(result)


@app.route("/api/sentinel-report")
def api_sentinel_report():
    """Trigger the SENTINEL AI engine and return the generated report."""
    try:
        sys.path.insert(0, BASE_DIR)
        from testollama_v4 import load_and_analyze, generate_report, sanitize_output  # noqa: PLC0415

        if not os.path.exists(ANALYSIS_CSV):
            return jsonify({"error": "No analysis data available. Run the ML pipeline first."}), 404

        summary = load_and_analyze(ANALYSIS_CSV, dc_logs_path=DC_LOGS_CSV, client_logs_path=CLIENT_LOGS_CSV)
        raw_output, rejection_reasons = generate_report(summary)
        allowed = summary.get("allowed_mitre_techniques", []) or []
        # rejection_reasons is None when validation passed; sanitize only when it failed
        if rejection_reasons:
            report = sanitize_output(raw_output, allowed)
        else:
            report = raw_output
        return jsonify({"report": report})

    except ImportError as exc:
        return jsonify({"error": f"Could not import SENTINEL engine: {exc}"}), 500
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("🛡️  ThreatWeaver SOC Dashboard starting on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
