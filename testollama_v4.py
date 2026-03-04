#!/usr/bin/env python3
"""
SENTINEL AI Threat Intelligence Engine v4
MITRE-Aware | Confidence-Scored | SOC-Grade Output
Optimized for Ollama + Qwen2.5
"""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

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

MAX_LLM_ATTEMPTS = 2  # still try once to correct, but we will sanitize regardless

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

    try:
        ts = pd.to_datetime(s, errors="coerce")
        if not pd.isna(ts):
            return ts
    except Exception:
        pass

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


def _split_mitre_field(raw: str) -> List[str]:
    if raw is None:
        return []
    s = str(raw).strip()
    if not s:
        return []
    s = s.replace("\n", ";").replace("|", ";")
    parts = [p.strip() for p in s.split(";") if p.strip()]
    out: List[str] = []
    for p in parts:
        if "," in p and "T" in p:
            out.extend([x.strip() for x in p.split(",") if x.strip()])
        else:
            out.append(p)
    return [x for x in out if x]


def extract_allowed_mitre_techniques(high_risk_df: pd.DataFrame) -> List[str]:
    if high_risk_df is None or high_risk_df.empty:
        return []
    if "mitre_techniques" not in high_risk_df.columns:
        return []

    techniques: set[str] = set()
    for raw in high_risk_df["mitre_techniques"].fillna("").astype(str).tolist():
        for t in _split_mitre_field(raw):
            t = re.sub(r"\s+", " ", t).strip()
            if t:
                techniques.add(t)

    def sort_key(x: str) -> tuple:
        m = re.search(r"\b(T\d{4,5}(?:\.\d{3})?)\b", x)
        return (m.group(1) if m else "ZZZZZ", x)

    return sorted(techniques, key=sort_key)


def extract_technique_ids(text: str) -> List[str]:
    if not text:
        return []
    ids = re.findall(r"\bT\d{4,5}(?:\.\d{3})?\b", text)
    seen: set[str] = set()
    out: List[str] = []
    for x in ids:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def allowed_ids_from_allowed_list(allowed: List[str]) -> set[str]:
    ids: set[str] = set()
    for item in allowed or []:
        for tid in extract_technique_ids(item):
            ids.add(tid)
    return ids


def validate_llm_output(output: str, allowed_mitre: List[str]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    out_lower = (output or "").lower()

    if "known compromised" in out_lower or "compromised ip" in out_lower:
        reasons.append("Output claims 'known compromised' / 'compromised IP' without explicit evidence labeling.")

    allowed_ids = allowed_ids_from_allowed_list(allowed_mitre)
    for tid in extract_technique_ids(output or ""):
        if tid not in allowed_ids:
            reasons.append(f"Output mentions technique id not in allowed list: {tid}")

    allowed_text = " ".join(allowed_mitre or []).lower()
    if "credential stuffing" in out_lower and "credential stuffing" not in allowed_text:
        reasons.append("Output mentions 'credential stuffing' but it is not present in allowed MITRE techniques.")

    ok = len(reasons) == 0
    return ok, reasons


# -------------------------------------------------
# OUTPUT SANITIZATION (HARD ENFORCEMENT)
# -------------------------------------------------


def sanitize_output(output: str, allowed_mitre: List[str]) -> str:
    """
    Make final output compliant even if model violates constraints.
    - Remove "known compromised" / "compromised IP" claims
    - Remove "credential stuffing" unless allowed
    - Remove any technique IDs not in allowed list
    - Force MITRE section to list only allowed techniques (by ID)
    """
    text = output or ""
    allowed_ids = allowed_ids_from_allowed_list(allowed_mitre)
    allowed_text = " ".join(allowed_mitre or []).lower()
    stuffing_allowed = "credential stuffing" in allowed_text

    # 1) Remove compromised claims (soft rewrite)
    # Replace phrases rather than deleting entire sentence to keep readability.
    replacements = [
        (r"\bknown compromised\b", "suspicious"),
        (r"\bcompromised ip(?: addresses?)?\b", "suspicious IP addresses"),
        (r"\bknown compromised accounts?\b", "suspicious accounts"),
    ]
    for pat, repl in replacements:
        text = re.sub(pat, repl, text, flags=re.IGNORECASE)

    # 2) Remove 'credential stuffing' phrase if not allowed
    if not stuffing_allowed:
        text = re.sub(r"\bcredential stuffing\b", "brute force", text, flags=re.IGNORECASE)

    # 3) Drop any technique IDs not allowed (replace with nothing)
    def _strip_disallowed_ids(m: re.Match) -> str:
        tid = m.group(0)
        return tid if tid in allowed_ids else ""

    text = re.sub(r"\bT\d{4,5}(?:\.\d{3})?\b", _strip_disallowed_ids, text)

    # 4) Force MITRE section lines to only allowed items
    # If there is a MITRE section, rewrite it to list allowed techniques only.
    # We detect headings like "### MITRE ATT&CK OBSERVATIONS" until next "###".
    mitre_heading = r"###\s+MITRE ATT&CK OBSERVATIONS\s*\n"
    m = re.search(mitre_heading, text, flags=re.IGNORECASE)
    if m:
        start = m.end()
        rest = text[start:]
        next_heading = re.search(r"\n###\s+", rest)
        end = start + (next_heading.start() if next_heading else len(rest))

        allowed_lines = []
        if allowed_mitre:
            for item in allowed_mitre:
                # only include if item still has an allowed ID
                ids = extract_technique_ids(item)
                if any(tid in allowed_ids for tid in ids) or not ids:
                    allowed_lines.append(f"- **{item}**")
        else:
            allowed_lines = ["No MITRE techniques provided in evidence."]

        new_mitre_block = "\n".join(allowed_lines) + "\n"
        text = text[:start] + new_mitre_block + text[end:]

    # 5) Cleanup: remove double spaces and leftover "()" etc.
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"\(\s*\)", "", text)

    return text.strip() + "\n"


# -------------------------------------------------
# RAW LOG METRICS
# -------------------------------------------------


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

    for col in ["timestamp", "event_id", "username", "source_ip", "process_name", "command_line"]:
        if col not in df.columns:
            df[col] = None

    df = df.copy()
    df["_ts"] = df["timestamp"].apply(_parse_mixed_timestamp)
    df["_user"] = df["username"].fillna("").astype(str)
    df["_ip"] = df["source_ip"].apply(_normalize_ip)

    event_id_counts = _top_counts(df["event_id"].astype(str), n=50)
    top_processes = _top_counts(df["process_name"], n=15)
    top_commands = _top_counts(df["command_line"], n=10)

    unique_users = int(df["_user"].nunique())
    unique_ips = int(df["_ip"].nunique())

    brute_df = df[df["event_id"].astype(str) == "4624"].copy()
    brute_force_suspects = 0
    top_pairs: Dict[str, int] = {}
    if not brute_df.empty:
        brute_df["pair"] = brute_df["_user"].astype(str) + "@" + brute_df["_ip"].astype(str)
        pair_counts = brute_df["pair"].value_counts()
        suspects = pair_counts[pair_counts >= 5]
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
    if logs_df is None or logs_df.empty or analysis_df is None or analysis_df.empty:
        return {"window_minutes": window_minutes, "matches": 0, "top_processes": {}}

    if "timestamp" not in analysis_df.columns:
        return {"window_minutes": window_minutes, "matches": 0, "top_processes": {}}

    logs_df = logs_df.copy()
    for col in ["timestamp", "event_id", "process_name"]:
        if col not in logs_df.columns:
            logs_df[col] = None

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
    return {"window_minutes": window_minutes, "matches": int(len(matched_df)), "top_processes": top_proc}


# -------------------------------------------------
# LOAD & ANALYZE
# -------------------------------------------------


def load_and_analyze(analysis_csv_path: str, dc_logs_path: str = "", client_logs_path: str = "") -> Dict[str, Any]:
    df = pd.read_csv(analysis_csv_path, low_memory=False)

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

    anomalies = df[df["is_anomaly"] == 1]
    high_risk = df[df["final_risk_level"].isin(["CRITICAL", "HIGH"])]

    total_events = len(df)
    total_anomalies = len(anomalies)
    anomaly_rate = round((total_anomalies / total_events) * 100, 2) if total_events else 0
    risk_distribution = df["final_risk_level"].value_counts().to_dict()

    scores = pd.to_numeric(df["total_threat_score"], errors="coerce")
    avg_threat_score = round(scores.mean(), 2) if total_events else 0
    high_confidence_cases = int((scores >= 7).sum())
    medium_confidence_cases = int(scores.between(4, 6, inclusive="both").sum())
    low_confidence_cases = int((scores <= 3).sum())

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
            (high_confidence_cases * 5)
            + (medium_confidence_cases * 2)
            + (unique_mitre * 3)
            + (unique_high_ips * 2),
            2,
        ),
    )

    top_incidents = (
        high_risk.sort_values("total_threat_score", ascending=False)
        .head(10)[["username", "source_ip", "final_risk_level", "total_threat_score", "mitre_techniques"]]
        .to_dict(orient="records")
    )

    allowed_mitre_techniques = extract_allowed_mitre_techniques(high_risk)

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
        "allowed_mitre_techniques": allowed_mitre_techniques,
        "dc_log_metrics": dc_metrics.to_dict(),
        "client_log_metrics": client_metrics.to_dict(),
        "process_exec_near_anomalies": proc_corr,
    }


# -------------------------------------------------
# PROMPT BUILDER
# -------------------------------------------------


def build_prompt(summary: Dict[str, Any]) -> str:
    return f"""
You are SENTINEL, a Tier-3 SOC threat intelligence analyst.

You MUST follow these rules exactly:

AUTHORITATIVE machine verdict: {summary['machine_verdict']}
AUTHORITATIVE confidence score: {summary['confidence_score']}%

Allowed MITRE techniques (closed list; do NOT add anything else):
{summary.get('allowed_mitre_techniques', [])}

Evidence (top incidents):
{summary.get('top_incidents', [])}

Hard rules:
- Do NOT mention any MITRE technique ID not in the allowed list.
- Do NOT mention "credential stuffing" unless it literally appears in the allowed list.
- Do NOT call any IP "known compromised" or "compromised IP".

Output format:
### EXECUTIVE THREAT SUMMARY
### CORRELATED ATTACK PATTERNS
### MITRE ATT&CK OBSERVATIONS
### RISK CONFIDENCE LEVEL
### PRIORITY RESPONSE ACTIONS
### ZERO TRUST HARDENING RECOMMENDATIONS
""".strip()


def build_correction_prompt(original_prompt: str, bad_output: str, reasons: List[str], allowed: List[str]) -> str:
    return f"""
You previously generated an invalid report.

Reasons it was rejected:
{reasons}

Allowed MITRE techniques (closed list):
{allowed}

Rewrite the entire report and remove all rejected content.
Do NOT say "known compromised" or "compromised IP".
Do NOT mention credential stuffing unless it is in the allowed list.

Original prompt:
{original_prompt}

Invalid output (for reference only):
{bad_output}
""".strip()


# -------------------------------------------------
# OLLAMA CALL
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


def generate_report(summary: Dict[str, Any]) -> Tuple[str, Optional[List[str]]]:
    base_prompt = build_prompt(summary)
    allowed = summary.get("allowed_mitre_techniques", []) or []

    prompt = base_prompt
    last_output = ""
    last_reasons: Optional[List[str]] = None

    for attempt in range(1, MAX_LLM_ATTEMPTS + 1):
        out = call_llm(prompt)
        last_output = out

        ok, reasons = validate_llm_output(out, allowed)
        if ok:
            return out, None

        last_reasons = reasons
        if attempt < MAX_LLM_ATTEMPTS:
            prompt = build_correction_prompt(base_prompt, out, reasons, allowed)

    return last_output, last_reasons


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
    print("Generating correlated threat intelligence...")

    raw_output, rejection_reasons = generate_report(summary)
    allowed = summary.get("allowed_mitre_techniques", []) or []

    if rejection_reasons:
        print("\n==================================================")
        print("SENTINEL AI CORRELATED THREAT REPORT")
        print("==================================================\n")
        print("WARNING: Model output violated strict constraints; printing sanitized report.")
        print(f"Rejection reasons: {rejection_reasons}\n")
        print(sanitize_output(raw_output, allowed))
        return

    print("\n==================================================")
    print("SENTINEL AI CORRELATED THREAT REPORT")
    print("==================================================\n")
    print(raw_output)


if __name__ == "__main__":
    main()
