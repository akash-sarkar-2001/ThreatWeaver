<div align="center">

# 🕸️ ThreatWeaver

**AI-Powered SOC Platform for Active Directory Threat Detection**

Isolation Forest ML · Rule-Based Detection · MITRE ATT&CK Mapping · RAG-Augmented LLM Threat Intelligence · Live Presentation Mode

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Web_Dashboard-000000?logo=flask)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-orange)](#license)

</div>

---

## 🔍 What is ThreatWeaver?

ThreatWeaver is an end-to-end threat detection platform built for Windows Active Directory environments. It collects security event logs from Domain Controllers and client machines, runs them through a multi-layered detection engine combining **unsupervised machine learning** and **deterministic rule-based heuristics**, and presents the results on a real-time SOC dashboard — complete with **AI-generated threat intelligence reports** powered by a local LLM augmented with a **Retrieval-Augmented Generation (RAG) pipeline** that grounds recommendations in your own SOC runbooks.

---

## ⚙️ Architecture Overview

```
┌─────────────────────┐     ┌───────────────────────┐
│  Domain Controller  │     │    Client Machine     │
│   (server-log.py)   │     │   (client-log.py)     │
│                     │     │                       │
│  Reads Event IDs:   │     │  Reads Event IDs:     │
│  4624, 4625, 4672,  │     │  4624, 4625, 4688     │
│  4768, 4769, 4688   │     │  Chunked HTTPS Upload │
└────────┬────────────┘     └───────────┬───────────┘
         │  Direct DB Insert            │  HTTPS + API Key
         │                              ▼
         │                    ┌────────────────────────────┐
         │                    │  secure_log_server.py      │
         │                    │  (Flask REST API on :5000) │
         │                    │  Rate-Limited + 2MB Cap    │
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
     └────────────────┘  │                   │
                         │  ┌──────────────┐ │
                         │  │ RAG Pipeline │ │
                         │  │ ChromaDB +   │ │
                         │  │ HuggingFace  │ │
                         │  │ Embeddings   │ │
                         │  └──────────────┘ │
                         └───────────────────┘

┌──────────────────────────────────────────────┐
│  ingest_intel.py                             │
│  Ingests SOC runbooks (runbooks/*.md) into   │
│  ChromaDB vector store for RAG retrieval     │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│  Presentation Mode (Watermark System)        │
│  presentation_watermark table in PostgreSQL  │
│  Filters dashboard, ML, and AI to show       │
│  only post-watermark data for live demos     │
└──────────────────────────────────────────────┘
```

---

## 🧠 RAG-Augmented Threat Intelligence

ThreatWeaver implements a **Retrieval-Augmented Generation (RAG)** pipeline to ground the AI-generated threat reports in your organization's own internal runbooks and threat intelligence documentation.

### How It Works

1. **Ingest** — `ingest_intel.py` loads Markdown documents from the `runbooks/` directory, splits them into 500-character chunks with overlap, generates embeddings using the `all-MiniLM-L6-v2` sentence transformer model, and stores them in a local **ChromaDB** vector database.

2. **Retrieve** — When `testollama.py` generates a SENTINEL AI report, it uses the detected MITRE ATT&CK techniques as a search query against the vector store, retrieving the top 3 most relevant runbook chunks.

3. **Augment** — The retrieved context is injected into the LLM prompt under an `INTERNAL RUNBOOK CONTEXT` section. The LLM is explicitly instructed to base its `PRIORITY RESPONSE ACTIONS` and `ZERO TRUST HARDENING RECOMMENDATIONS` on the provided runbook content.

This ensures that generated recommendations are **specific to your environment** rather than generic security advice.

---

## 🎯 Presentation Mode

ThreatWeaver includes a **Presentation Mode** designed for live demonstrations. It allows you to show a clean dashboard to your audience, then run a simulated attack and watch the detections appear in real-time — all without deleting any historical data.

### How It Works

Presentation Mode uses a **database watermark** — a timestamp stored in a single-row PostgreSQL table (`presentation_watermark`). When activated, every component in the pipeline filters its queries to only return data generated **after** the watermark:

| Component | Behavior When Active |
|---|---|
| `dashboard.py` | All API endpoints return only post-watermark analyzed data |
| `train_isolation_forest.py` | ML model trains exclusively on post-watermark raw logs |
| `testollama.py` | SENTINEL AI generates reports from post-watermark data only |
| Dashboard UI | Polls every **10 seconds** (vs. 30s normally) for near-real-time updates |

### Demo Workflow

1. **Toggle ON** — Click the **Presentation Mode** button in the dashboard header. The watermark is set to `NOW()`, all caches are invalidated, and the dashboard shows a clean zero state.
2. **Simulate Attack** — Run `attack.sh` from a Linux/Termux machine. The generated Windows Security events flow through the log collectors into the database.
3. **Watch Detections** — Within 60 seconds, `train_isolation_forest.py` picks up the new logs, trains the Isolation Forest on post-watermark data, and writes results to `analyzed_logs`. The dashboard auto-refreshes every 10 seconds to display live KPIs, charts, and incidents.
4. **Generate Report** — Click **Generate SENTINEL Report** to produce an AI threat intelligence report based solely on the demo attack data.
5. **Restore** — Click **Restore Full History** (in the amber banner) or toggle the button again to deactivate the watermark and return to the full historical view.

Historical logs are never deleted — the watermark is purely a temporal filter.

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
| `train_isolation_forest.py` | Core detection engine — loads raw logs (up to 100K events in memory-safe batches), runs Isolation Forest + 9 rules, maps MITRE ATT&CK techniques, scores risks, writes results to `analyzed_logs` table. Runs on a 60-second loop. Respects the Presentation Mode watermark when active. |
| `dashboard.py` | Flask web dashboard (port 5001) — serves REST APIs for summary stats, risk distributions, top incidents, MITRE technique breakdowns, timeline data, user/IP analysis, SENTINEL AI reports, and Presentation Mode watermark management. Protected by GitHub OAuth. Includes in-memory caching with configurable TTL. |
| `testollama.py` | SENTINEL AI threat intelligence engine — aggregates metrics from both DB tables, retrieves relevant context from the ChromaDB vector store via RAG, builds a structured prompt, queries Ollama LLM, validates output against allowed MITRE techniques, and sanitizes the final report. Includes prompt injection defenses, an in-memory cache, and Presentation Mode watermark awareness. |
| `ingest_intel.py` | RAG ingestion script — loads SOC runbooks and threat intel documents from `runbooks/`, splits them into chunks, embeds them with `all-MiniLM-L6-v2`, and stores the vectors in a local ChromaDB database (`chroma_db/`). |
| `server-log.py` | Domain Controller log collector — reads Windows Security Event Log (Event IDs 4624/4625/4672/4768/4769/4688), inserts directly into PostgreSQL. Uses a watermark file for incremental collection. |
| `client-log.py` | Client machine log collector — reads local Windows Security events (4624/4625/4688), forwards them over HTTPS to `secure_log_server.py` with API key authentication. Sends logs in chunks of 2,000 to stay within the server's 2MB payload limit. Uses a persistent watermark file for incremental collection across restarts. |
| `secure_log_server.py` | Flask REST API (port 5000) — receives JSON log payloads from client agents over TLS, authenticates via `X-API-KEY` header, and inserts into PostgreSQL. Includes rate limiting (20 requests/min, 200/hr, 1000/day) and a 2MB max payload cap. |
| `generate_cert.py` | Generates self-signed SSL certificates (RSA 4096-bit, SHA-256) with SAN for server IP, 127.0.0.1, and localhost. |
| `attack.sh` | Bash attack simulator (designed for Termux) — cycles through 10 AD attack patterns (brute force, password spray, credential stuffing, lateral movement, Kerberoasting prep, etc.) against a target DC using `smbclient`. |
| `runbooks/` | Directory containing SOC runbook Markdown files that are ingested into the RAG vector store by `ingest_intel.py`. Add your own `.md` playbooks here to customize SENTINEL AI recommendations. |
| `chroma_db/` | Local ChromaDB vector database (auto-generated by `ingest_intel.py`). Stores embedded runbook chunks for RAG retrieval. |
| `templates/dashboard.html` | Main SOC dashboard UI template with charts, incident tables, and Presentation Mode controls. |
| `templates/login.html` | GitHub OAuth login page. |
| `static/js/dashboard.js` | Dashboard frontend logic — Chart.js visualizations, table sort/filter/export, SENTINEL AI integration, particle canvas, and Presentation Mode state management with dynamic polling. |
| `static/css/dashboard.css` | Premium dark-theme styling — glassmorphism, neon accents, responsive layout, and Presentation Mode button/banner animations. |

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

### 5. Ingest SOC Runbooks (RAG Setup)

Place your SOC runbook Markdown files in the `runbooks/` directory, then run:

```bash
python ingest_intel.py
```

This embeds the runbooks into the local ChromaDB vector store. The SENTINEL AI engine will use these as grounding context when generating threat reports. Re-run this command whenever you add or update runbooks.

### 6. Start Log Collection

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

### 7. Run the Detection Engine

```bash
python train_isolation_forest.py
```
This continuously analyzes new raw logs every 60 seconds and writes scored results to the `analyzed_logs` table.

### 8. Launch the SOC Dashboard

```bash
python dashboard.py
```
Open `https://localhost:5001` — you'll be prompted to authenticate via GitHub OAuth. Only whitelisted admin emails (configured in `.env`) can access the dashboard.

### 9. Generate AI Threat Reports (Optional)

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
- **Rate Limiting** — Flask-Limiter on the log ingestion endpoint (20/min, 200/hr, 1000/day) with 2MB payload cap
- **Prompt Injection Protection** — Input sanitization, output validation, and hard enforcement sanitization for LLM-generated reports
- **Incremental Log Collection** — Persistent watermark file tracking prevents duplicate log ingestion across restarts
- **RAG Grounding** — LLM recommendations are anchored to your own SOC runbooks via retrieval-augmented generation, reducing hallucination
- **Presentation Mode** — Non-destructive database watermark system that filters all views to post-watermark data for clean live demonstrations without deleting historical logs

---

## ⚠️ Disclaimer

This project is built for **lab, research, and educational environments**. Before using in production:

- Harden your PostgreSQL instance and rotate credentials
- Replace self-signed certificates with CA-signed ones
- Secure the `.env` file and restrict filesystem permissions
- Test ML model performance on larger datasets
- Update the `AUTHORIZED_ADMINS` in `.env` with your own email

## ⚖️ License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details. This license provides a grant of patent rights and allows for both personal and commercial use while requiring preservation of copyright and license notices.

---
*Built with ❤️ for secure Active Directory environments.*
