#!/usr/bin/env python3
"""
SENTINEL AI Threat Intelligence Engine v4
MITRE-Aware | Confidence-Scored | SOC-Grade Output
Optimized for Ollama + Qwen2.5
"""

import pandas as pd
import requests
from typing import Dict, Any

# -------------------------------------------------
# CONFIG
# -------------------------------------------------

CSV_FILE = "advanced_security_analysis.csv"
OLLAMA_URL = "http://Akash:11434/api/generate"
MODEL_NAME = "qwen2.5:3b"

# -------------------------------------------------
# LOAD DATA
# -------------------------------------------------

def load_and_analyze(csv_path: str) -> Dict[str, Any]:
    df = pd.read_csv(csv_path, low_memory=False)

    # -------------------------------------------------
    # SAFETY CHECKS
    # -------------------------------------------------

    required_cols = [
        "is_anomaly",
        "final_risk_level",
        "total_threat_score",
        "username",
        "source_ip",
        "mitre_techniques"
    ]

    for col in required_cols:
        if col not in df.columns:
            df[col] = None

    # -------------------------------------------------
    # BASIC METRICS
    # -------------------------------------------------

    anomalies = df[df["is_anomaly"] == 1]
    high_risk = df[df["final_risk_level"].isin(["CRITICAL", "HIGH"])]

    total_events = len(df)
    total_anomalies = len(anomalies)
    anomaly_rate = round((total_anomalies / total_events) * 100, 2) if total_events else 0

    risk_distribution = df["final_risk_level"].value_counts().to_dict()
    avg_threat_score = round(df["total_threat_score"].mean(), 2)

    # -------------------------------------------------
    # CONFIDENCE TIERS
    # -------------------------------------------------

    high_confidence_cases = len(df[df["total_threat_score"] >= 7])
    medium_confidence_cases = len(df[df["total_threat_score"].between(4, 6)])
    low_confidence_cases = len(df[df["total_threat_score"] <= 3])

    # -------------------------------------------------
    # CORRELATION ANALYSIS
    # -------------------------------------------------

    unique_high_users = high_risk["username"].nunique()
    unique_high_ips = high_risk["source_ip"].nunique()
    unique_mitre = high_risk["mitre_techniques"].nunique()

    # Multi-dimensional correlation indicators
    multi_user_flag = unique_high_users > 1
    multi_ip_flag = unique_high_ips > 1
    multi_technique_flag = unique_mitre > 1

    # -------------------------------------------------
    # MACHINE VERDICT LOGIC
    # -------------------------------------------------

    if (
        high_confidence_cases > 5 and
        multi_user_flag and
        multi_ip_flag and
        multi_technique_flag
    ):
        machine_verdict = "STRONG_CORRELATED_ATTACK"

    elif medium_confidence_cases > 0:
        machine_verdict = "MODERATE_CORRELATION_NO_CONFIRMED_COMPROMISE"

    else:
        machine_verdict = "LOW_CONFIDENCE_ACTIVITY"

    # -------------------------------------------------
    # NUMERIC CONFIDENCE SCORE (0–100)
    # -------------------------------------------------

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

    # -------------------------------------------------
    # TOP 10 MOST SEVERE INCIDENTS
    # -------------------------------------------------

    top_incidents = (
        high_risk
        .sort_values("total_threat_score", ascending=False)
        .head(10)[[
            "username",
            "source_ip",
            "final_risk_level",
            "total_threat_score",
            "mitre_techniques"
        ]]
        .to_dict(orient="records")
    )

    # -------------------------------------------------
    # RETURN STRUCTURED SUMMARY
    # -------------------------------------------------

    return {
        "total_events": total_events,
        "total_anomalies": total_anomalies,
        "anomaly_rate": anomaly_rate,
        "risk_distribution": risk_distribution,
        "avg_threat_score": avg_threat_score,
        "high_confidence_cases": high_confidence_cases,
        "medium_confidence_cases": medium_confidence_cases,
        "low_confidence_cases": low_confidence_cases,
        "unique_high_users": unique_high_users,
        "unique_high_ips": unique_high_ips,
        "unique_mitre_techniques": unique_mitre,
        "machine_verdict": machine_verdict,
        "confidence_score": confidence_score,
        "top_incidents": top_incidents
    }

# -------------------------------------------------
# PROMPT BUILDER (MULTI-LAYERED)
# -------------------------------------------------

def build_prompt(summary: Dict[str, Any]) -> str:
    return f"""
You are SENTINEL, a Tier-3 SOC threat intelligence analyst.

You are interpreting structured detection results produced by a hybrid ML + rule-based engine.
You MUST align your interpretation with the deterministic machine verdict.

You are NOT allowed to escalate severity beyond the machine verdict.

====================================================
DETECTION ENGINE OUTPUT
====================================================

Total Events: {summary['total_events']}
Total ML Anomalies: {summary['total_anomalies']}
Anomaly Rate: {summary['anomaly_rate']}%

Average Threat Score: {summary['avg_threat_score']}
High Confidence Cases (Score ≥7): {summary['high_confidence_cases']}
Medium Confidence Cases (Score 4–6): {summary['medium_confidence_cases']}
Low Confidence Cases (Score ≤3): {summary['low_confidence_cases']}

Unique High-Risk Users: {summary['unique_high_users']}
Unique High-Risk IPs: {summary['unique_high_ips']}
Unique MITRE Techniques Observed: {summary['unique_mitre_techniques']}

Risk Distribution:
{summary['risk_distribution']}

Machine Correlation Verdict:
{summary['machine_verdict']}

Calculated Threat Confidence Score:
{summary['confidence_score']}%

Top Correlated High-Risk Incidents (Structured Evidence Only):
{summary['top_incidents']}

====================================================
MANDATORY REASONING RULES
====================================================

1. You MUST align your interpretation with the Machine Correlation Verdict.
2. You may NOT escalate severity beyond the machine verdict.
3. Do NOT invent additional MITRE techniques.
4. Do NOT expand MITRE techniques beyond those provided.
5. Do NOT assume insider threat without multi-user or multi-IP evidence.
6. Privileged account activity alone does NOT imply compromise.
7. Absence of source IP does NOT imply concealment.
8. If threat score < 7 and no multi-dimensional spread exists,
   state clearly: "Correlation is moderate and does not confirm compromise."
9. If verdict is MODERATE_CORRELATION_NO_CONFIRMED_COMPROMISE,
   explicitly state that no confirmed breach is observed.
10. Base conclusions ONLY on provided structured evidence.

====================================================
THREAT SCORE INTERPRETATION
====================================================

0–1  = Low
2–3  = Weak anomaly
4–6  = Moderate correlation
7+   = Strong correlated attack signal

====================================================
RESPONSE FORMAT (STRICT)
====================================================

### EXECUTIVE THREAT SUMMARY
- Summarize overall posture
- Reference machine verdict explicitly

### CORRELATED ATTACK PATTERNS
- Describe only patterns supported by evidence
- Mention user/IP spread if present
- Do NOT speculate

### MITRE ATT&CK OBSERVATIONS
- List only observed techniques
- No expansion or sub-technique invention

### RISK CONFIDENCE LEVEL
- Use calculated confidence score
- Explain whether evidence supports strong or moderate correlation
- Clearly state if no confirmed compromise

### PRIORITY RESPONSE ACTIONS
- Evidence-based actions only

### ZERO TRUST HARDENING RECOMMENDATIONS
- Long-term architectural improvements
- No fear-based language

Keep output under 1000 words.
"""

# -------------------------------------------------
# CALL OLLAMA
# -------------------------------------------------

def call_llm(prompt: str) -> str:
    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.05,
                "top_p": 0.8,
                "num_ctx": 4096,
                "num_predict": 1000,
                "repeat_penalty": 1.15
            }
        },
        timeout=180
    )

    response.raise_for_status()
    return response.json()["response"]

# -------------------------------------------------
# MAIN
# -------------------------------------------------

def main():
    print("🔍 Loading advanced security analysis...")
    summary = load_and_analyze(CSV_FILE)

    if summary["total_anomalies"] == 0:
        print("✅ No anomalies detected.")
        return

    print("🧠 Building SOC-grade intelligence prompt...")
    prompt = build_prompt(summary)

    print("🚀 Generating correlated threat intelligence...")
    output = call_llm(prompt)

    print("\n==================================================")
    print("🔥 SENTINEL AI CORRELATED THREAT REPORT")
    print("==================================================\n")
    print(output)


if __name__ == "__main__":
    main()