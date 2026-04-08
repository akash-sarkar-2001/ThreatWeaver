<div align="center">

# 🕸️ ThreatWeaver

**AI-Powered SOC Platform for Active Directory Threat Detection**

Isolation Forest ML · Rule-Based Detection · MITRE ATT&CK Mapping · LLM Threat Intelligence

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Web_Dashboard-000000?logo=flask)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/License-Research_Use-orange)](#disclaimer)

</div>

---

## 🔍 What is ThreatWeaver?

ThreatWeaver is an end-to-end threat detection platform built for Windows Active Directory environments. It collects security event logs from Domain Controllers and client machines, runs them through a multi-layered detection engine combining **unsupervised machine learning** and **deterministic rule-based heuristics**, and presents the results on a real-time SOC dashboard — complete with optional **AI-generated threat intelligence reports** powered by a local LLM.

---

## ⚙️ Architecture Overview

```
┌─────────────────────┐     ┌──────────────────────┐
│  Domain Controller  │     │    Client Machine    │
│   (server-log.py)   │     │   (client-log.py)    │
│                     │     │                      │
│  Reads Event IDs:   │     │  Reads Event IDs:    │
│  4624, 4625, 4672,  │     │  4624, 4625, 4688    │
│  4768, 4769, 4688   │     │                      │
└────────┬────────────┘     └───────────┬──────────┘
         │  Direct DB Insert            │  HTTPS + API Key
         │                              ▼
         │                    ┌────────────────────────────┐
         │                    │  secure_log_server.py      │
         │                    │  (Flask REST API on :5000) │
         │                    └────────────┬───────────────┘
         │                                 │
         ▼                                 ▼
┌──────────────────────────────────────────────────────┐
│            PostgreSQL (raw_logs table)               │
│               TimescaleDB Hypertable                 │
└────────────────────────┬─────────────────────────────┘
                         │
                         ▼
          ┌──────────────────────────────┐
          │   train_isolation_forest.py  │
          │   (ML + Rules Detection)     │
          │                              │
          │  • Isolation Forest Model    │
          │  • 9 Detection Rules         │
          │  • MITRE ATT&CK Mapping      │
          │  • Confidence Scoring        │
          └──────────────┬───────────────┘
                         │
                         ▼
          ┌───────────────────────────────┐
          │   PostgreSQL (analyzed_logs)  │
          └──────┬───────────────┬────────┘
                 │               │
                 ▼               ▼
     ┌────────────────┐  ┌───────────────────┐
     │ dashboard.py   │  │  testollama.py    │
     │ (SOC Dashboard │  │  (SENTINEL AI     │
     │  on :5001)     │  │  Threat Reports)  │
     │ GitHub OAuth   │  │  Ollama + Qwen2.5 │
     └────────────────┘  └───────────────────┘
```

---

## 🛡️ Detection Capabilities

### Machine Learning Layer
The **Isolation Forest** algorithm trains on behavioral features (login times, event frequencies, IP distributions) to establish a baseline of "normal" and flag statistical outliers as anomalies.

### Rule-Based Detection Layer (9 Rules)

| Rule | Detection Logic | MITRE ATT&CK |
|---|---|---|
| **Brute Force** | High failed logins from multiple IPs or within 10-min window | T1110 |
| **Password Spray** | Single IP failing against ≥6 unique users | T1110.003 |
| **Credential Stuffing** | Success login after ≥5 prior failures | T1110.004 |
| **Account Enumeration** | Single IP probing ≥12 unique accounts | T1087.002 |
| **Privilege Escalation** | Successful login + privilege assignment after failures | T1078 |
| **Lateral Movement** | Single user authenticating across ≥2 machines | T1021 |
| **Suspicious Process/Cmd** | Execution of known offensive tools (Mimikatz, PsExec, etc.) | T1059 |
| **Kerberoasting** | Abnormal volume of TGS ticket requests per user | T1558.003 |
| **After-Hours Privileged** | Privileged access outside 06:00–20:00 window | T1078.002 |

### Scoring System
Each event receives a weighted **rule score** + an **ML score** (if flagged as anomaly). The combined **total threat score** translates to risk levels:

| Score | Risk Level |
|---|---|
| ≥ 9 | 🔴 CRITICAL |
| 6 – 8 | 🟠 HIGH |
| 3 – 5 | 🟡 MEDIUM |
| 0 – 2 | 🟢 LOW |

---

## 📁 Repository Structure

| File | Purpose |
|---|---|
| `train_isolation_forest.py` | Core detection engine — loads raw logs, runs Isolation Forest + 9 rules, maps MITRE ATT&CK techniques, scores risks, writes results to `analyzed_logs` table. Runs on a 60-second loop. |
| `dashboard.py` | Flask web dashboard (port 5001) — serves REST APIs for summary stats, risk distributions, top incidents, MITRE technique breakdowns, timeline data, user/IP analysis, and SENTINEL AI reports. Protected by GitHub OAuth. |
| `testollama.py` | SENTINEL AI threat intelligence engine — aggregates metrics from both DB tables, builds a structured prompt, queries Ollama LLM, validates output against allowed MITRE techniques, and sanitizes the final report. Includes prompt injection defenses. |
| `server-log.py` | Domain Controller log collector — reads Windows Security Event Log (Event IDs 4624/4625/4672/4768/4769/4688), inserts directly into PostgreSQL. Uses a watermark file for incremental collection. |
| `client-log.py` | Client machine log collector — reads local Windows Security events (4624/4625/4688), forwards them over HTTPS to `secure_log_server.py` with API key authentication. |
| `secure_log_server.py` | Flask REST API (port 5000) — receives JSON log payloads from client agents over TLS, authenticates via `X-API-KEY` header, and inserts into PostgreSQL. |
| `generate_cert.py` | Generates self-signed SSL certificates (RSA 4096-bit, SHA-256) with SAN for server IP, 127.0.0.1, and localhost. |
| `attack.sh` | Bash attack simulator (designed for Termux) — cycles through 10 AD attack patterns (brute force, password spray, credential stuffing, lateral movement, Kerberoasting prep, etc.) against a target DC using `smbclient`. |
| `templates/dashboard.html` | Main SOC dashboard UI template with charts and incident tables. |
| `templates/login.html` | GitHub OAuth login page. |

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+**
- **PostgreSQL** with [TimescaleDB](https://www.timescale.com/) extension
- **Windows** machines for log collection (uses `pywin32` for the Windows Event Log API)
- **(Optional)** [Ollama](https://ollama.com/) with a model like `qwen2.5:3b` for AI-generated threat reports

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Create a `.env` file in the project root:

```ini
# Database
DB_HOST=localhost
DB_NAME=threatweaver_db
DB_USER=postgres
DB_PASS=your_db_password
DB_PORT=5432

# Client-to-Server log forwarding
API_KEY=your_secure_api_key
SERVER_URL=https://<your_server_ip>:5000/api/upload-logs

# GitHub OAuth (for SOC Dashboard)
SECRET_KEY=your_flask_secret_key
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
AUTHORIZED_ADMINS=your_email_id

# SSL certificate generation
CERT_DIR=.
SERVER_IP=your_server_ip
CERT_PATH = "Path_of_cert.pem"
KEY_PATH = "Path_of_key.pem"

# AI Threat Reports (optional)
OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=qwen2.5:3b
```

### 3. Generate SSL Certificates

```bash
python generate_cert.py
```

### 4. Set Up Database

Ensure your PostgreSQL instance has TimescaleDB enabled. The `raw_logs` hypertable is created automatically when `server-log.py` runs for the first time.

### 5. Start Log Collection

**On the Domain Controller:**
```bash
python server-log.py
```

**On each Client Machine** — first start the secure log receiver on the server:
```bash
python secure_log_server.py
```
Then on the client:
```bash
python client-log.py
```

### 6. Run the Detection Engine

```bash
python train_isolation_forest.py
```
This continuously analyzes new raw logs every 60 seconds and writes scored results to the `analyzed_logs` table.

### 7. Launch the SOC Dashboard

```bash
python dashboard.py
```
Open `https://localhost:5001` — you'll be prompted to authenticate via GitHub OAuth. Only whitelisted admin emails (configured in `dashboard.py`) can access the dashboard.

### 8. Generate AI Threat Reports (Optional)

With Ollama running locally:
```bash
python testollama.py
```
Or click the **SENTINEL AI** button on the dashboard to generate reports in-browser.

---

## 🧪 Attack Simulation

Use `attack.sh` from a Linux/Termux machine to simulate common AD attacks against your lab Domain Controller:

```bash
chmod +x attack.sh
./attack.sh
```

This runs 10 attack patterns in 30-second cycles: brute force, password spraying, credential stuffing, success-after-failure, privileged logon, lateral movement, SMB recon, account enumeration, Kerberoasting prep, and off-hours access.

---

## 🔐 Security Features

- **GitHub OAuth** — Zero-trust access control for the SOC dashboard with email-based admin whitelist
- **API Key Authentication** — Header-based auth (`X-API-KEY`) for the log ingestion endpoint
- **TLS Encryption** — Self-signed certificates for both the log server and dashboard
- **Prompt Injection Protection** — Input sanitization, output validation, and hard enforcement sanitization for LLM-generated reports
- **Incremental Log Collection** — Watermark-based tracking prevents duplicate log ingestion

---

## ⚠️ Disclaimer

This project is built for **lab, research, and educational environments**. Before using in production:

- Harden your PostgreSQL instance and rotate credentials
- Replace self-signed certificates with CA-signed ones
- Secure the `.env` file and restrict filesystem permissions
- Test ML model performance on larger datasets
- Update the `AUTHORIZED_ADMINS` list in `dashboard.py` with your own email
