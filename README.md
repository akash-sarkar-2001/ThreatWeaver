# ThreatWeaver

ThreatWeaver is a correlated Zero Trust security engine that fuses ML anomaly detection, behavioral rules, MITRE ATT&CK mapping, and constrained AI reporting to convert raw AD logs into structured, explainable, and evidence-driven threat intelligence.

**Pipeline:**
1. **Ingest** AD/DC + client endpoint logs (CSV)
2. **Detect & correlate** using **Isolation Forest** + **9 behavioral rule layers**
3. **Map** detections to **MITRE ATT&CK** techniques
4. **Score & prioritize** with a deterministic risk/confidence model (LOW → CRITICAL)
5. **Present** via a lightweight **SOC dashboard** (Flask + REST API)
6. **Generate** a constrained, SOC-style narrative report via a local LLM (Ollama)

---

## Key Capabilities

- **Hybrid Detection**: Isolation Forest ML anomaly detection + 9 rule-based detection layers.
- **MITRE ATT&CK Mapping**: Brute Force, Password Spraying, Kerberoasting, Lateral Movement, and more.
- **High-Accuracy AI Reporting (SENTINEL)**: Hardened prompt engineering system forces local LLMs (Qwen2.5:3b) to strictly adhere to observed evidence, preventing hallucinated techniques and speculation.
- **Premium SOC Dashboard**: A "Glassmorphism 2.0" responsive web UI with a dynamic particle background, real-time risk distribution, event timelines, and interactive tooltips.
- **Actionable Workflows**: 
  - One-click **CSV Export** for forensic analysis in Excel/Splunk.
  - One-click **Print Report** for generating clean, branded, PDF-ready threat briefs.
- **Secure Log Transfer**: Optional HTTPS-based client → server log uploader.

---

## Repository Structure

```
ThreatWeaver/
├── train_isolation_forest_v4.py   # Main ML pipeline (load → detect → score → export)
├── testollama_v4.py               # SENTINEL AI reporting engine (Ollama/Qwen2.5)
├── dashboard.py                   # Flask SOC dashboard backend + REST API
├── templates/dashboard.html       # Dashboard frontend
├── static/                        # CSS/JS assets
│
├── secure_log_server.py           # HTTPS log upload receiver
├── secure_log_uploader.py         # Periodic client-side log uploader (60s interval)
├── generate_cert.py               # Self-signed certificate generator
│
├── attack.sh                      # Lab attack simulation script
├── requirements.txt               # Python dependencies
│
├── dc_logs.csv                    # Input: Domain Controller logs
├── client_logs.csv                # Input: Client endpoint logs
├── advanced_security_analysis.csv # Output: All events, enriched (pipeline-generated)
└── high_risk_incidents.csv        # Output: CRITICAL/HIGH events only (pipeline-generated)
```

---

## Quick Start

### 1) Prerequisites

- Python 3.9+ (tested up to 3.14)
- [Ollama](https://ollama.com/) with `qwen2.5:3b` pulled (required only for AI report generation)

Install Python dependencies:

```bash
pip install -r requirements.txt
```

### 2) Prepare Input Logs

Place the following files in the project root:

| File | Description |
|---|---|
| `dc_logs.csv` | Domain Controller event logs |
| `client_logs.csv` | Client endpoint event logs |

**Required columns** (pipeline will exit if missing):
- `timestamp`, `event_id`, `username`

**Optional columns** (defaults to `N/A` if absent):
- `process_name`, `command_line`, `source_ip`

### 3) Run the Detection Pipeline

```bash
python train_isolation_forest_v4.py
```

Outputs:
- `advanced_security_analysis.csv` — all events, enriched with risk scores and MITRE tags
- `high_risk_incidents.csv` — CRITICAL/HIGH events only

### 4) Launch the SOC Dashboard

```bash
python dashboard.py
```

Open **http://localhost:5000** in your browser.

**API endpoints:**

| Endpoint | Description |
|---|---|
| `GET /api/summary` | Overall stats, machine verdict, confidence score |
| `GET /api/risk-distribution` | Event counts by risk level |
| `GET /api/top-incidents` | Top 20 highest-threat events |
| `GET /api/mitre-techniques` | MITRE technique frequency counts |
| `GET /api/timeline` | Events bucketed by hour |
| `GET /api/user-risk` | Top 10 riskiest users |
| `GET /api/ip-analysis` | Top 10 most active IPs |
| `GET /api/sentinel-report` | Trigger SENTINEL AI report generation |

### 5) Generate AI Threat Report (Optional)

Requires Ollama running locally (or on a reachable host):

```bash
# Pull the model if needed
ollama pull qwen2.5:3b

# Run the SENTINEL engine
python testollama_v4.py

# Point to a remote Ollama instance
OLLAMA_URL=http://<host>:11434/api/generate python testollama_v4.py
```

### 6) Secure Log Transfer (Optional Lab Demo)

On the **server** (receiver):
```bash
python secure_log_server.py
```

On the **client** (sender — uploads `client_logs.csv` every 60s):
```bash
python secure_log_uploader.py
```

Generate self-signed TLS certs first if needed:
```bash
python generate_cert.py
```

---

## Detection Layers

| # | Detection | MITRE Technique |
|---|---|---|
| 1 | Brute Force (lifetime + burst window) | T1110 |
| 2 | Password Spraying (per-IP) | T1110.003 |
| 3 | Account Enumeration (per-IP) | T1087.002 |
| 4 | Credential Stuffing | T1110.004 |
| 5 | Privilege Escalation | T1078 |
| 6 | Success After Failure | T1078 |
| 7 | Lateral Movement | T1021 |
| 8 | Malicious Process / Command Line | T1059 |
| 9 | Kerberoasting | T1558.003 |
| +ML | Isolation Forest anomaly (300 trees) | — |

### Risk Scoring

| Score | Risk Level |
|---|---|
| ≥ 9 | CRITICAL |
| 6–8 | HIGH |
| 3–5 | MEDIUM |
| 0–2 | LOW |

ML anomaly adds +3 to any event's score. Isolation Forest contamination rate: `0.03` (3%).

---

## Configuration

Key constants in `train_isolation_forest_v4.py`:

```python
CONTAMINATION_RATE = 0.03                    # Isolation Forest anomaly rate
BRUTE_FORCE_LIFETIME_THRESHOLD = 10          # Total failures to flag brute force
BRUTE_FORCE_WINDOW_THRESHOLD = 5             # Failures within 10-min window
PASSWORD_SPRAY_IP_UNIQUE_USERS_THRESHOLD = 6 # Unique users from one IP = spray
KERBEROAST_TGS_PER_USER_THRESHOLD = 6        # TGS requests = Kerberoasting
AFTER_HOURS_START = 20                       # After-hours window (20:00–06:00)
```

Ollama config in `testollama_v4.py` (also overridable via environment variables):

```bash
OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=qwen2.5:3b
ANALYSIS_CSV=advanced_security_analysis.csv
```
