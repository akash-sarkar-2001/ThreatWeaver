#!/usr/bin/env python3
"""
SENTINEL AI Threat Intelligence Engine v4
MITRE-Aware | Confidence-Scored | SOC-Grade Output
Optimized for Ollama + Qwen2.5
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

import pandas as pd
import requests

# -------------------------------------------------
# CONFIG
# -------------------------------------------------

DEFAULT_ANALYSIS_CSV = "advanced_security_analysis.csv"
DEFAULT_DC_LOGS_CSV = "dc_logs.csv"
DEFAULT_CLIENT_LOGS_CSV = "client_logs.csv"

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://Akash:11434/api/generate")
MODEL_NAME = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")

# -------------------------------------------------
# HELPERS
# -------------------------------------------------


def _safe_read_csv(path: str) -> Optional[pd.DataFrame]:
    if not path:
        return None
    if not os.path.exists(path):
        return None
    try:
        return pd.read_csv(path, low_memory=False)
    except Exception:
        return None


def _parse_mixed_timestamp(value: Any) -> Optional[pd.Timestamp]:
    """Parse timestamps that may look like:
    - '2026-03-04 22:44:58'
    - 'Wed Mar  4 23:07:54 2026'
    """
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None

    s = str(value).strip()
    if not s:
        return None

    # Try pandas flexible parse first
    try:
        ts = pd.to_datetime(s, errors="coerce")
        if not pd.isna(ts):
            return ts
    except Exception:
        pass

    # Fallback explicit formats
    for fmt in ("%Y-%m-%d %H:%M:%S", "%a %b %d %H:%M:%S %Y"):
        try:
            return pd.Timestamp(datetime.strptime(s, fmt))
        except Exception:
            continue

    return None


def _normalize_ip(ip: Any) -> str:
    if ip is None or (isinstance(ip, float) and pd.isna(ip)):
        return ""
    return str(ip).strip()


def _top_counts(series: pd.Series, n: int = 10) -> Dict[str, int]:
    if series is None or series.empty:
        return {}
    series = series.fillna("").astype(str)
    vc = series.value_counts().head(n)
    return {str(k): int(v) for k, v in vc.items() if str(k).strip()}

@dataclass
class LogMetrics:
    rows: int = 0
    event_id_counts: Dict[str, int] = None  # type: ignore[assignment]
    top_processes: Dict[str, int] = None  # type: ignore[assignment]
    top_commands: Dict[str, int] = None  # type: ignore[assignment]
    unique_users: int = 0
    unique_ips: int = 0
    brute_force_suspects: int = 0
    top_bruteforce_pairs: Dict[str, int] = None  # type: ignore[assignment]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rows": self.rows,
            "event_id_counts": self.event_id_counts or {},
            "top_processes": self.top_processes or {},
            "top_commands": self.top_commands or {},
            "unique_users": self.unique_users,
            "unique_ips": self.unique_ips,
            "brute_force_suspects": self.brute_force_suspects,
            "top_bruteforce_pairs": self.top_bruteforce_pairs or {},
        }


def analyze_raw_logs(df: Optional[pd.DataFrame]) -> LogMetrics:
    if df is None or df.empty:
        return LogMetrics(
            rows=0,
            event_id_counts={},
            top_processes={},
            top_commands={},
            unique_users=0,
            unique_ips=0,
            brute_force_suspects=0,
            top_bruteforce_pairs={},
        )

    # normalize expected columns
    for col in ["timestamp", "event_id", "username", "source_ip", "process_name", "command_line"]:
        if col not in df.columns:
            df[col] = None

    df = df.copy()

    # parse timestamps for potential future correlation
    df["_ts"] = df["timestamp"].apply(_parse_mixed_timestamp)

    df["_user"] = df["username"].fillna("{}").astype(str)
    df["_ip"] = df["source_ip"].apply(_normalize_ip)

    event_id_counts = _top_counts(df["event_id"].astype(str), n=50)
    top_processes = _top_counts(df["process_name", n=15)
    top_commands = _top_counts(df["command_line", n=10)

    unique_users = int(df["_user"].nunique())
    unique_ips = int(df["_ip"].nunique())

    # Heuristic: repeated 4624 events from same (user, ip)
    brute_df = df[df["event_id"].astype(str) == "4624"].copy()
    brute_force_suspects = 0
    top_pairs: Dict[str, int] = {}
    if not brute_df.empty:
        brute_df["pair"] = brute_df["_user"].astype(str) + "@" + brute_df["_ip"].astype(str)
        pair_counts = brute_df["pair"].value_counts()
        suspects = pair_counts[pair_counts >= 5]  # threshold
        brute_force_suspects = int(len(suspects))
        top_pairs = {str(k): int(v) for k, v in suspects.head(10).items()}

    return LogMetrics(
        rows=int(len(df)),
        event_id_counts=event_id_counts,
        top_processes=top_processes,
        top_commands=top_commands,
        unique_users=unique_users,
        unique_ips=unique_ips,
        brute_force_suspects=brute_force_suspects,
        top_bruteforce_pairs=top_pairs,
    )


def compute_process_exec_near_anomalies(
    analysis_df: pd.DataFrame,
    logs_df: Optional[pd.DataFrame],
    window_minutes: int = 15,
) -> Dict[str, Any]:
    """Correlate analysis anomalies to raw 4688 process events within a time window."""
    if logs_df is None or logs_df.empty or analysis_df is None or analysis_df.empty:
        return {"window_minutes": window_minutes, "matches": 0, "top_processes": {}}

    if "timestamp" not in analysis_df.columns:
        return {"window_minutes": window_minutes, "matches": 0, "top_processes": {}}

    logs_df = logs_df.copy()

    for col in ["timestamp", "event_id", "process_name"]:
        if col not in logs_df.columns:
            logs_df[col] = None

    # parse
    analysis_df = analysis_df.copy()
    analysis_df["_ts"] = analysis_df["timestamp"].apply(_parse_mixed_timestamp)
    logs_df["_ts"] = logs_df["timestamp"].apply(_parse_mixed_timestamp)

    anomalies = analysis_df
    if "is_anomaly" in analysis_df.columns:
        anomalies = analysis_df[analysis_df["is_anomaly"] == 1]

    anomalies = anomalies.dropna(subset=["_ts"])
    if anomalies.empty:
        return {"window_minutes": window_minutes, "matches": 0, "top_processes": {}}

    proc_events = logs_df[logs_df["event_id"].astype(str) == "4688"].dropna(subset=["_ts"]).copy()
    if proc_events.empty:
        return {"window_minutes": window_minutes, "matches": 0, "top_processes": {}}

    # Create time window joins (simple loop; logs are usually not huge)
    window = pd.Timedelta(minutes=window_minutes)
    matched = []
    for ts in anomalies["_ts"].tolist():
        start = ts - window
        end = ts + window
        sub = proc_events[(proc_events["_ts"] >= start) & (proc_events["_ts"] <= end)]
        if not sub.empty:
            matched.append(sub)

    if not matched:
        return {"window_minutes": window_minutes, "matches": 0, "top_processes": {}}

    matched_df = pd.concat(matched, ignore_index=True)
    top_proc = _top_counts(matched_df["process_name"], n=10)

    return {
        "window_minutes": window_minutes,
        "matches": int(len(matched_df)),
        "top_processes": top_proc,
    }


# -------------------------------------------------
# LOAD & ANALYZE ADVANCED SECURITY ANALYSIS
# -------------------------------------------------


def load_and_analyze(analysis_csv_path: str, dc_logs_path: str = "", client_logs_path: str = "") -> Dict[str, Any]:
    df = pd.read_csv(analysis_csv_path, low_memory=False)

    # -------------------------------------------------
    # SAFETY CHECKS
    # -------------------------------------------------

    required_cols = [
        "timestamp",
        "is_anomaly",
        "final_risk_level",
        "total_threat_score",
        "username",
        "source_ip",
        "mitre_techniques",
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
    avg_threat_score = round(df["total_threat_score"].mean(), 2) if total_events else 0

    # -------------------------------------------------
    # CONFIDENCE TIERS
    # -------------------------------------------------

    scores = pd.to_numeric(df["total_threat_score"], errors="coerce")
    high_confidence_cases = int(len(df[scores >= 7]))
    medium_confidence_cases = int(len(df[scores.between(4, 6, inclusive="both")]))
    low_confidence_cases = int(len(df[scores <= 3]))

    # -------------------------------------------------
    # CORRELATION ANALYSIS
    # -------------------------------------------------

    unique_high_users = int(high_risk["username"].nunique())
    unique_high_ips = int(high_risk["source_ip"].nunique())
    unique_mitre = int(high_risk["mitre_techniques"].nunique())

    # Multi-dimensional correlation indicators
    multi_user_flag = unique_high_users > 1
    multi_ip_flag = unique_high_ips > 1
    multi_technique_flag = unique_mitre > 1

    # -------------------------------------------------
    # MACHINE VERDICT LOGIC
    # -------------------------------------------------

    if (
        high_confidence_cases > 5
        and multi_user_flag
        and multi_ip_flag
        and multi_technique_flag
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
            (high_confidence_cases * 5)
            + (medium_confidence_cases * 2)
            + (unique_mitre * 3)
            + (unique_high_ips * 2),
            2,
        ),
    )

    # -------------------------------------------------
    # TOP 10 MOST SEVERE INCIDENTS
    # -------------------------------------------------

    top_incidents = (
        high_risk.sort_values("total_threat_score", ascending=False)
        .head(10)[
            [
                "username",
                "source_ip",
                "final_risk_level",
                "total_threat_score",
                "mitre_techniques",
            ]
        ]
        .to_dict(orient="records")
    )

    # -------------------------------------------------
    # RAW LOG METRICS
    # -------------------------------------------------

    dc_df = _safe_read_csv(dc_logs_path)
    client_df = _safe_read_csv(client_logs_path)

    dc_metrics = analyze_raw_logs(dc_df)
    client_metrics = analyze_raw_logs(client_df)

    proc_corr = compute_process_exec_near_anomalies(df, dc_df if dc_df is not None else client_df, window_minutes=15)

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
        "multi_user_flag": multi_user_flag,
        "multi_ip_flag": multi_ip_flag,
        "multi_technique_flag": multi_technique_flag,
        "machine_verdict": machine_verdict,
        "confidence_score": confidence_score,
        "top_incidents": top_incidents,
        "dc_log_metrics": dc_metrics.to_dict(),
        "client_log_metrics": client_metrics.to_dict(),
        "process_exec_near_anomalies": proc_corr,
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

Multi-dimensional spread flags:
- multi_user_flag: {summary.get('multi_user_flag')}
- multi_ip_flag: {summary.get('multi_ip_flag')}
- multi_technique_flag: {summary.get('multi_technique_flag')}

Risk Distribution:
{summary['risk_distribution']}

Machine Correlation Verdict:
{summary['machine_verdict']}

Calculated Threat Confidence Score:
{summary['confidence_score']}%

Top Correlated High-Risk Incidents (Structured Evidence Only):
{summary['top_incidents']}

====================================================
RAW LOG CONTEXT (DC + CLIENT)
====================================================

DC Log Metrics:
{summary.get('dc_log_metrics', {})}

Client Log Metrics:
{summary.get('client_log_metrics', {})}

Process execution near anomalies (±{summary.get('process_exec_near_anomalies', {}).get('window_minutes', 15)} min):
{summary.get('process_exec_near_anomalies', {})}

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

Additional strict constraints (to prevent hallucinations):
- Do NOT call any IP "known compromised" unless the provided evidence explicitly labels it compromised.
- Do NOT claim "credential stuffing" unless the evidence explicitly says "credential stuffing".
  If you see brute force, call it "brute force" only.
- Do NOT infer lateral movement / remote services unless a technique indicating it is present in mitre_techniques.
- If Machine Correlation Verdict is STRONG_CORRELATED_ATTACK, your narrative MUST acknowledge multi-user, multi-IP,
  and multi-technique spread (as shown by the flags). If any flag is false, say the verdict might be inconsistent.

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
                "repeat_penalty": 1.15,
            },
        },
        timeout=180,
    )
    response.raise_for_status()
    return response.json()["response"]


# -------------------------------------------------
# MAIN
# -------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SENTINEL AI Threat Intelligence Engine")
    p.add_argument("--analysis-csv", default=os.getenv("ANALYSIS_CSV", DEFAULT_ANALYSIS_CSV))
    p.add_argument("--dc-logs", default=os.getenv("DC_LOGS_CSV", DEFAULT_DC_LOGS_CSV))
    p.add_argument("--client-logs", default=os.getenv("CLIENT_LOGS_CSV", DEFAULT_CLIENT_LOGS_CSV))
    return p.parse_args()


def main() -> None:
    args = parse_args()

    print("Loading advanced security analysis...")
    if not os.path.exists(args.analysis_csv):
        raise SystemExit(f"Missing analysis CSV: {args.analysis_csv}")

    summary = load_and_analyze(args.analysis_csv, dc_logs_path=args.dc_logs, client_logs_path=args.client_logs)

    if summary["total_anomalies"] == 0:
        print("No anomalies detected.")
        return

    print("Building SOC-grade intelligence prompt...")
    prompt = build_prompt(summary)

    print("Generating correlated threat intelligence...")
    output = call_llm(prompt)

    print("\n==================================================")
    print("SENTINEL AI CORRELATED THREAT REPORT")
    print("==================================================\n")
    print(output)


if __name__ == "__main__":
    main()