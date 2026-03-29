# ThreatWeaver
An advanced AI-powered log analysis and threat detection system using Isolation Forest and MITRE ATT&CK mappings.

## Key Capabilities
- **Unsupervised Anomaly Detection:** Uses an Isolation Forest algorithm to baseline "normal" behavior and flag anomalies.
- **Rule-Based Heuristics:** Employs multiple deterministic rules tailored to catch lateral movement, privilege escalation, and specific command executions.
- **Correlated Scoring:** Combines Machine Learning confidence and rule hits into an overall incident risk score.
- **AI Triage Integration (Optional):** Sends summarized high-confidence events to an Ollama LLM for automated Tier-1 analysis.
- **Database Driven:** Built on top of robust PostgreSQL storage.
- **Zero Trust Dashboard:** Features GitHub OAuth authentication for secured insights.

## Repository Structure
- `train_isolation_forest.py`: The main engine. Connects to PostgreSQL, loads events, applies ML and rules, scores risks, maps to MITRE ATT&CK, and pushes analyzed logs back.
- `dashboard.py`: A Flask-based web application showing metrics and insights, protected by GitHub OAuth.
- `secure_log_server.py`: A REST API endpoint built with Flask to receive logs over an encrypted tunnel.
- `server-log.py`: Collects Domain Controller logs (Event IDs: 4624, 4625, 4672, 4768, 4769, 4688) and pushes directly to PostgreSQL.
- `client-log.py`: Collects Client logs and pushes them to `secure_log_server.py`.
- `testollama.py`: Prepares high-confidence incident context and submits it to an Ollama LLM (like Qwen2.5) for automated threat reports.
- `attack.sh`: A simple bash script to simulate rapid login failures (for testing purposes).
- `generate_cert.py`: A helper script for creating temporary SSL certificates.

## Quick Start

### 1) Prerequisites
1. Python 3.9+
2. A running PostgreSQL Server.
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### 2) Database Setup
ThreatWeaver now relies on PostgreSQL. You must have a database created (e.g., `threatweaver_db`). Provide the necessary connection variables via `.env` configuration.

Create a `.env` file in the root directory:
```ini
DB_HOST=localhost
DB_NAME=threatweaver_db
DB_USER=postgres
DB_PASS=your_db_password
DB_PORT=5432

# Client/Server log forwarding
API_KEY=your_secure_api_key
SERVER_URL=https://<your_server_ip>:5000/api/upload-logs

# GitHub OAuth credentials for dashboard
SECRET_KEY=your_flask_secret_key
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# AI Triage
OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=qwen2.5:3b
```

### 3) Start Log Forwarding
If you are testing on Windows machines:

**On the Server / Domain Controller:**
```bash
python server-log.py
```
This reads security event logs and inserts them directly into PostgreSQL.

**On the Client Machine:**
Start the secure log server API on your main server first:
```bash
python secure_log_server.py
```
Then on the client machine:
```bash
python client-log.py
```
This reads client security logs and posts them to your secure log server endpoint.

### 4) Run the Detection Pipeline
Run the analysis engine. This script continuously analyzes new raw logs from the database, runs the Isolation Forest model, scores the events, and saves the output back to an `analyzed_logs` database table.
```bash
python train_isolation_forest.py
```

### 5) Launch the SOC Dashboard
Start the Flask web dashboard:
```bash
python dashboard.py
```
Navigate to `http://localhost:5000`. You will be prompted to log in using your authorized GitHub account.

### 6) Generate AI Threat Report (Optional)
If you have an Ollama model running, you can run the LLM threat report engine:
```bash
python testollama.py
```
This will fetch the latest summarized metrics and incidents, and generate an executive threat intelligence report.

## Detection Layers
The engine (`train_isolation_forest.py`) uses a stacked approach:
1. **Unsupervised Baseline:** Isolation Forest identifies anomalous combinations of features (time, frequency, event ID distribution).
2. **Behavioral Flags:** Tracks variables over time (e.g., failed logins per 10 minutes, unique IPs).
3. **Deterministic Rules:** Detects specific conditions like:
    - **Brute Force:** High rate of failures from single or multiple IPs.
    - **Password Spray:** Failed logins targeting many users from the same IP.
    - **Credential Stuffing:** High failure count followed by success.
    - **Kerberoasting:** Abnormal volume of TGS requests.
    - **Lateral Movement:** Successes on multiple separate machines.

### Risk Scoring
Each incident receives a `rule_score` based on the rule hits and an `ml_score` if flagged by the Isolation Forest. The sum represents the `total_threat_score`, which is translated into `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` risk levels.

## Important Note
This application is designed for Lab and Research environments. Using it in production requires ensuring correct database hardening, managing the performance of the Python models on larger datasets, and properly securing API keys and OAuth secrets.