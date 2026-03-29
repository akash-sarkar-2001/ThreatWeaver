#!/usr/bin/env python3
"""
SENTINEL AI Threat Intelligence Engine v4
MITRE-Aware | Confidence-Scored | SOC-Grade Output
Optimized for Ollama + Qwen2.5 (PostgreSQL Database Edition)
"""

from __future__ import annotations

import os
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import time
import pandas as pd
import requests
from sqlalchemy import create_engine
import dotenv

dotenv.load_dotenv()

# -------------------------------------------------
# DATABASE & OLLAMA CONFIG
# -------------------------------------------------
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "threatweaver_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS")
DB_PORT = os.getenv("DB_PORT", "5432")

# Safely encode the password
SAFE_DB_PASS = urllib.parse.quote_plus(DB_PASS)
DB_URI = f"postgresql://{DB_USER}:{SAFE_DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(DB_URI)

OLLAMA_URL = os.getenv("OLLAMA_URL")
MODEL_NAME = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")

MAX_LLM_ATTEMPTS = 2  # still try once to correct, but we will sanitize regardless

# -------------------------------------------------
# HELPERS
# -------------------------------------------------

def sanitize_for_prompt(text: Any) -> str:
    """Sanitize arbitrary input to prevent LLM prompt injection."""
    if pd.isna(text) or text is None:
        return "N/A"
    s = str(text)
    s = re.sub(r"<\|.*?\|>", "", s)
    s = re.sub(r"(?i)\b(ignore|system\s+prompt|new\s+instructions|sysprompt)\b", "[REDACTED]", s)
    if len(s) > 200:
        s = s[:197] + "..."
    return s.replace("\n", " ").replace("\r", " ").strip()


def _parse_mixed_timestamp(value: Any) -> Optional[pd.Timestamp]:
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
            t = sanitize_for_prompt(t)
            if t and t != "N/A":
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
    text = output or ""
    allowed_ids  = allowed_ids_from_allowed_list(allowed_mitre)
    allowed_text = " ".join(allowed_mitre or []).lower()
    stuffing_allowed = "credential stuffing" in allowed_text

    text = re.sub(r"\[VERIFY before finishing.*?\]\.?", "", text, flags=re.IGNORECASE | re.DOTALL)
    
    closing_pats = [
        r"By following these recommendations[^\n]*",
        r"By implementing these[^\n]*",
        r"These measures will[^\n]*",
        r"In summary[,\.][^\n]*",
    ]
    for pat in closing_pats:
        text = re.sub(pat, "", text, flags=re.IGNORECASE)

    replacements = [
        (r"\bknown compromised\b",           "suspicious"),
        (r"\bcompromised ip(?: addresses?)?\b", "suspicious IP addresses"),
        (r"\bknown compromised accounts?\b",  "suspicious accounts"),
    ]
    for pat, repl in replacements:
        text = re.sub(pat, repl, text, flags=re.IGNORECASE)

    if not stuffing_allowed:
        text = re.sub(r"\bcredential stuffing\b", "brute force", text, flags=re.IGNORECASE)

    def _line_contains_only_disallowed_id(line: str) -> bool:
        ids = extract_technique_ids(line)
        return bool(ids) and all(tid not in allowed_ids for tid in ids)

    clean_lines = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        is_list_line = stripped.startswith(("-", "*", "•")) or re.match(r"^\d+[.)]", stripped)
        if is_list_line and _line_contains_only_disallowed_id(line):
            continue          
        clean_lines.append(line)
    text = "\n".join(clean_lines)

    def _strip_disallowed_ids(m: re.Match) -> str:
        tid = m.group(0)
        return tid if tid in allowed_ids else ""
    text = re.sub(r"\bT\d{4,5}(?:\.\d{3})?\b", _strip_disallowed_ids, text)

    mitre_heading = r"###\s+MITRE ATT&CK OBSERVATIONS\s*\n"
    m = re.search(mitre_heading, text, flags=re.IGNORECASE)
    if m:
        start = m.end()
        rest  = text[start:]
        next_heading = re.search(r"\n###\s+", rest)
        end = start + (next_heading.start() if next_heading else len(rest))

        if allowed_mitre:
            allowed_lines = [
                f"- **{item}** — observed in incident data."
                for item in allowed_mitre
                if any(tid in allowed_ids for tid in extract_technique_ids(item))
                or not extract_technique_ids(item)
            ]
        else:
            allowed_lines = ["No MITRE techniques observed in evidence."]

        new_mitre_block = "\n".join(allowed_lines) + "\n"
        text = text[:start] + new_mitre_block + text[end:]

    text = re.sub(r"[ \t]+",  " ", text)
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
        return LogMetrics(rows=0, event_id_counts={}, top_processes={}, top_commands={}, unique_users=0, unique_ips=0, brute_force_suspects=0, top_bruteforce_pairs={})

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


# =====================================================
# IN-MEMORY CACHE SYSTEM
# =====================================================
LLM_CACHE_TTL = 120  # Keep LLM context cached for 2 minutes
_SUMMARY_CACHE = None
_SUMMARY_CACHE_TIME = 0

def load_and_analyze() -> Dict[str, Any]:
    global _SUMMARY_CACHE, _SUMMARY_CACHE_TIME
    current_time = time.time()

    # 1. Check if we already calculated the metrics recently
    if _SUMMARY_CACHE is not None and (current_time - _SUMMARY_CACHE_TIME) < LLM_CACHE_TTL:
        print("[*] Fast-loading CACHED database metrics for SENTINEL AI...")
        return _SUMMARY_CACHE

    print("[*] Fetching analyzed_logs from database...")
    try:
        df = pd.read_sql("SELECT * FROM analyzed_logs", engine)
    except Exception as e:
        print(f"[-] Database Error (analyzed_logs): {e}")
        raise SystemExit("Ensure train_isolation_forest.py has run successfully.")

    print("[*] Fetching raw_logs from database...")
    try:
        raw_df = pd.read_sql("SELECT * FROM raw_logs", engine)
        dc_df = raw_df[raw_df["source_machine"] == "DOMAIN_CONTROLLER"]
        client_df = raw_df[raw_df["source_machine"] == "CLIENT_MACHINE"]
    except Exception as e:
        print(f"[-] Database Error (raw_logs): {e}")
        dc_df, client_df, raw_df = None, None, None

    # ... (Keep ALL of your existing dataframe processing logic here exactly as it was) ...
    
    required_cols = ["timestamp", "is_anomaly", "final_risk_level", "total_threat_score", "username", "source_ip", "mitre_techniques"]
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

    confidence_score = min(100, round((high_confidence_cases * 5) + (medium_confidence_cases * 2) + (unique_mitre * 3) + (unique_high_ips * 2), 2))

    top_incidents = high_risk.sort_values("total_threat_score", ascending=False).head(10)[["username", "source_ip", "final_risk_level", "total_threat_score", "mitre_techniques"]].to_dict(orient="records")
    allowed_mitre_techniques = extract_allowed_mitre_techniques(high_risk)

    dc_metrics = analyze_raw_logs(dc_df)
    client_metrics = analyze_raw_logs(client_df)
    proc_corr = compute_process_exec_near_anomalies(df, dc_df if (dc_df is not None and not dc_df.empty) else client_df, window_minutes=15)

    # Compile the final dictionary
    final_summary = {
        "total_events": total_events, "total_anomalies": total_anomalies, "anomaly_rate": anomaly_rate,
        "risk_distribution": risk_distribution, "avg_threat_score": avg_threat_score,
        "high_confidence_cases": high_confidence_cases, "medium_confidence_cases": medium_confidence_cases,
        "low_confidence_cases": low_confidence_cases, "unique_high_users": unique_high_users,
        "unique_high_ips": unique_high_ips, "unique_mitre_techniques": unique_mitre,
        "multi_user_flag": multi_user_flag, "multi_ip_flag": multi_ip_flag, "multi_technique_flag": multi_technique_flag,
        "machine_verdict": machine_verdict, "confidence_score": confidence_score, "top_incidents": top_incidents,
        "allowed_mitre_techniques": allowed_mitre_techniques, "dc_log_metrics": dc_metrics.to_dict(),
        "client_log_metrics": client_metrics.to_dict(), "process_exec_near_anomalies": proc_corr,
    }

    # 2. Save the result to RAM for the next 2 minutes
    _SUMMARY_CACHE = final_summary
    _SUMMARY_CACHE_TIME = current_time
    
    return final_summary

# -------------------------------------------------
# PROMPT BUILDER
# -------------------------------------------------

def _fmt_incidents(incidents: list) -> str:
    if not incidents:
        return "  (no high-risk incidents)"
    lines = []
    for i, inc in enumerate(incidents[:8], 1):         
        user  = sanitize_for_prompt(inc.get("username", "N/A"))
        ip    = sanitize_for_prompt(inc.get("source_ip", "N/A"))
        risk  = str(inc.get("final_risk_level", "N/A"))
        score = str(inc.get("total_threat_score", "N/A"))
        mitre = sanitize_for_prompt(inc.get("mitre_techniques", "N/A"))
        lines.append(
            f"  {i}. User={user} | IP={ip} | Risk={risk} "
            f"| Score={score} | Techniques={mitre}"
        )
    return "\n".join(lines)


def _fmt_mitre(allowed: list) -> str:
    if not allowed:
        return "  (no techniques observed)"
    return "\n".join(f"  {i}. {t}" for i, t in enumerate(allowed, 1))


def _fmt_log_metrics(label: str, m: dict) -> str:
    if not m or m.get("rows", 0) == 0:
        return f"  {label}: no data"
    top_ev = ", ".join(
        f"{sanitize_for_prompt(k)}:{v}" for k, v in list(m.get("event_id_counts", {}).items())[:6]
    ) or "N/A"
    top_pr = ", ".join(
        f"{sanitize_for_prompt(k)}:{v}" for k, v in list(m.get("top_processes", {}).items())[:5]
    ) or "N/A"
    return (
        f"  {label}: rows={m['rows']:,} | users={m['unique_users']} "
        f"| IPs={m['unique_ips']} | brute-suspects={m['brute_force_suspects']}\n"
        f"    Top Event IDs: {top_ev}\n"
        f"    Top Processes: {top_pr}"
    )


def build_prompt(summary: Dict[str, Any]) -> str:
    verdict        = summary["machine_verdict"].replace("_", " ")
    confidence     = summary["confidence_score"]
    anomaly_rate   = summary.get("anomaly_rate", 0)
    total_events   = summary.get("total_events", 0)
    total_anomalies= summary.get("total_anomalies", 0)
    high_conf      = summary.get("high_confidence_cases", 0)
    med_conf       = summary.get("medium_confidence_cases", 0)
    unique_users   = summary.get("unique_high_users", 0)
    unique_ips     = summary.get("unique_high_ips", 0)
    allowed_mitre  = summary.get("allowed_mitre_techniques", []) or []
    top_incidents  = summary.get("top_incidents", []) or []
    dc_m           = summary.get("dc_log_metrics", {}) or {}
    cl_m           = summary.get("client_log_metrics", {}) or {}
    proc_corr      = summary.get("process_exec_near_anomalies", {}) or {}

    proc_matches   = proc_corr.get("matches", 0)
    proc_window    = proc_corr.get("window_minutes", 15)
    top_proc_str   = ", ".join(
        f"{sanitize_for_prompt(k)}:{v}" for k, v in list(proc_corr.get("top_processes", {}).items())[:5]
    ) or "none"

    allowed_str   = _fmt_mitre(allowed_mitre)
    incidents_str = _fmt_incidents(top_incidents)
    dc_str        = _fmt_log_metrics("DC logs",     dc_m)
    cl_str        = _fmt_log_metrics("Client logs", cl_m)

    risk_sentence = (
        f"The ML model flagged {total_anomalies:,} anomalies out of {total_events:,} events "
        f"({anomaly_rate:.1f}% anomaly rate), with {high_conf} high-confidence and "
        f"{med_conf} medium-confidence cases across {unique_users} distinct user(s) and "
        f"{unique_ips} distinct source IP(s)."
    )

    stuffing_allowed   = any(
        "credential stuffing" in t.lower() for t in allowed_mitre
    )
    stuffing_constraint = (
        "3. 'credential stuffing' IS in the allowed technique list — you MAY reference it."
        if stuffing_allowed else
        "3. STRICT BAN: Do NOT write the words 'credential stuffing' ANYWHERE in the report "
        "— not in the summary, not in patterns, not in MITRE, nowhere. "
        "The allowed list does not contain it."
    )

    mitre_count = len(allowed_mitre)
    mitre_count_note = (
        f"There are exactly {mitre_count} technique(s) in the allowed list. "
        f"Your MITRE ATT&CK OBSERVATIONS section MUST list exactly these {mitre_count} "
        f"technique(s) — no more, no fewer."
        if mitre_count > 0 else
        "There are NO allowed techniques. Write 'No MITRE techniques observed.' in that section."
    )

    return f"""<|im_start|>system
You are SENTINEL, a Tier-3 SOC analyst. Write evidence-based threat intelligence reports.
NEVER add techniques not in the allowed list. NEVER echo back input data as report sections.
<|im_end|>
<|im_start|>user
Write a SOC threat report. Use ONLY the EVIDENCE below. Write all six sections.

--- EVIDENCE (do NOT repeat this as output) ---
Verdict    : {verdict}
Confidence : {confidence}%
{risk_sentence}

Log telemetry:
{dc_str}
{cl_str}
Process matches near anomalies: {proc_matches} (window={proc_window}m), top: {top_proc_str}

Top incidents:
{incidents_str}

Allowed MITRE techniques (ONLY these, numbered for reference):
{allowed_str}
--- END EVIDENCE ---

RULES (strictly enforced):
1. In the MITRE ATT&CK OBSERVATIONS section, you MUST list exactly {mitre_count} technique(s).
   These are: {', '.join(allowed_mitre) if allowed_mitre else 'none'}.
   Do NOT add T1059 or any other technique not in that list.
2. Do NOT write "known compromised" or "compromised IP". Write "suspicious" instead.
{stuffing_constraint}
4. Do NOT invent any username, IP, or threat actor not present in the incident data above.
5. Do NOT write anything after the ZERO TRUST HARDENING RECOMMENDATIONS section.

Write the following six sections in order. Each section MUST have the exact heading shown:

### EXECUTIVE THREAT SUMMARY
2-4 sentences. State verdict, confidence %, anomaly count, scope (users, IPs).

### CORRELATED ATTACK PATTERNS
3-5 bullet points. Describe observed patterns using usernames and IPs from the incident data.

### MITRE ATT&CK OBSERVATIONS
One bullet per allowed technique. Format: `- <ID> - <Name>: <one sentence why it applies>.`
Only use the {mitre_count} techniques listed above.

### RISK CONFIDENCE LEVEL
1-2 sentences. Justify the {confidence}% confidence and the {verdict} verdict.

### PRIORITY RESPONSE ACTIONS
Numbered list, 4-6 items. Specific actions referencing the identified users and IPs.

### ZERO TRUST HARDENING RECOMMENDATIONS
Numbered list, 4-6 items. Strategic hardening measures to prevent recurrence.
<|im_end|>
<|im_start|>assistant
""".strip()


def build_correction_prompt(original_prompt: str, bad_output: str, reasons: List[str], allowed: List[str]) -> str:
    reasons_str = "\n".join(f"  - {r}" for r in reasons)
    allowed_str = _fmt_mitre(allowed)

    offending = []
    for r in reasons:
        m = re.search(r"'([^']+)'|: (.+)", r)
        if m:
            offending.append((m.group(1) or m.group(2)).strip())

    offending_str = "\n".join(f"  • '{o}'" for o in offending) if offending else "  (see reasons above)"

    return f"""<|im_start|>system
You are SENTINEL, a Tier-3 SOC analyst. You write strict, evidence-based reports.
NEVER add techniques not in the allowed list. NEVER echo input data as report sections.
<|im_end|>
<|im_start|>user
Your previous report was REJECTED. Rewrite it fixing ALL issues below.

Rejection reasons:
{reasons_str}

Specific content to fix:
{offending_str}

Fix rules:
1. Remove every item listed in the rejection reasons.
2. MITRE section must contain ONLY the techniques listed below — no T1059, no others.
3. Replace "known compromised" / "compromised IP" with "suspicious".
4. Do NOT write anything after ZERO TRUST HARDENING RECOMMENDATIONS.
5. Keep all six sections with the exact headings shown.

Allowed MITRE techniques (the ONLY ones permitted):
{allowed_str}

Original context:
{original_prompt}

Rejected output (rewrite this completely, fixing all violations):
{bad_output}

Write the corrected report with all six sections:
### EXECUTIVE THREAT SUMMARY
### CORRELATED ATTACK PATTERNS
### MITRE ATT&CK OBSERVATIONS
### RISK CONFIDENCE LEVEL
### PRIORITY RESPONSE ACTIONS
### ZERO TRUST HARDENING RECOMMENDATIONS
<|im_end|>
<|im_start|>assistant
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
                "num_predict": 1500,
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

def main() -> None:
    print("Building SOC-grade intelligence prompt from Database...")
    summary = load_and_analyze()

    if summary["total_anomalies"] == 0:
        print("No anomalies detected in the database.")
        return

    print("Generating correlated threat intelligence via Ollama...")

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
