import os
import sys
import urllib.parse
from collections import defaultdict
import time
import pandas as pd
from flask import Flask, jsonify, render_template, redirect, url_for, session, abort, request
from authlib.integrations.flask_client import OAuth
from sqlalchemy import create_engine
import dotenv

dotenv.load_dotenv()

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# =====================================================
# ZERO TRUST OAUTH CONFIGURATION (GITHUB)
# =====================================================
app.secret_key = os.getenv("SECRET_KEY")

# IMPORTANT: Update this list with your actual GitHub email!
admin_env = os.getenv("AUTHORIZED_ADMINS", "")
AUTHORIZED_ADMINS = [email.strip() for email in admin_env.split(",") if email.strip()]

if not AUTHORIZED_ADMINS:
    print("[WARNING] No authorized admins configured in .env!")

oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'read:user user:email'},
)

# =====================================================
# DATABASE CONFIGURATION
# =====================================================
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "threatweaver_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS")
DB_PORT = os.getenv("DB_PORT", "5432")
# Safely encode the password
SAFE_DB_PASS = urllib.parse.quote_plus(DB_PASS)
DB_URI = f"postgresql://{DB_USER}:{SAFE_DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Create a global database engine
engine = create_engine(DB_URI)

# =====================================================
# IN-MEMORY CACHE SYSTEM
# =====================================================
CACHE_TTL = 60  # How long to keep data in memory (in seconds)

_DB_CACHE = None
_DB_CACHE_TIME = 0

_RAW_COUNT_CACHE = 0
_RAW_COUNT_TIME = 0

def _load_analysis():
    """Return the main analysis DataFrame from PostgreSQL with memory caching."""
    global _DB_CACHE, _DB_CACHE_TIME
    current_time = time.time()

    if _DB_CACHE is not None and (current_time - _DB_CACHE_TIME) < CACHE_TTL:
        return _DB_CACHE

    try:
        query = "SELECT * FROM analyzed_logs"
        df = pd.read_sql(query, engine)
        if df.empty:
            return None
            
        _DB_CACHE = df
        _DB_CACHE_TIME = current_time
        return df
    except Exception as e:
        print(f"Database error: {e}")
        return None

def _get_raw_total_events():
    """Fast, cached query to get the TRUE total number of logs in the database."""
    global _RAW_COUNT_CACHE, _RAW_COUNT_TIME
    current_time = time.time()

    if _RAW_COUNT_CACHE > 0 and (current_time - _RAW_COUNT_TIME) < CACHE_TTL:
        return _RAW_COUNT_CACHE

    try:
        # Ask Postgres to just count the rows (very fast) instead of downloading them
        count_df = pd.read_sql("SELECT COUNT(*) FROM raw_logs", engine)
        total = int(count_df.iloc[0, 0])
        
        _RAW_COUNT_CACHE = total
        _RAW_COUNT_TIME = current_time
        return total
    except Exception as e:
        print(f"Count error: {e}")
        return 0

def _safe_str(val):
    if pd.isna(val):
        return ""
    return str(val)

# =====================================================
# AUTHENTICATION MIDDLEWARE
# =====================================================
@app.before_request
def check_authentication():
    """Intercept every request. Redirect to login if not authenticated."""
    # ADDED 'login_github' to the whitelist!
    open_routes = ['login', 'login_github', 'authorize', 'static']
    
    # Don't block the background Windows agents uploading logs!
    if request.path.startswith('/api/upload-logs'):
        return
        
    if request.endpoint not in open_routes and 'user_email' not in session:
        return redirect(url_for('login'))

# =====================================================
# OAUTH ROUTES
# =====================================================
@app.route('/login')
def login():
    if 'user_email' in session:
        return redirect(url_for('index'))
    # Optional: You can render a custom HTML login page here instead of redirecting instantly
    return render_template('login.html')

@app.route('/login/github')
def login_github():
    redirect_uri = url_for('authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    try:
        token = github.authorize_access_token()
        resp = github.get('user')
        user_info = resp.json()
        
        # GitHub often hides primary emails, so fetch them explicitly
        email = user_info.get('email')
        if not email:
            emails_resp = github.get('user/emails')
            emails = emails_resp.json()
            for e in emails:
                if e.get('primary') and e.get('verified'):
                    email = e.get('email')
                    break

        # Verify against the SOC Admin whitelist
        if email in AUTHORIZED_ADMINS:
            session['user_email'] = email
            session['user_name'] = user_info.get('login', 'Analyst')
            session['avatar_url'] = user_info.get('avatar_url', '')
            return redirect(url_for('index'))
        else:
            abort(403, f"Unauthorized SOC Access. Email {email} is not whitelisted.")
            
    except Exception as e:
        print(f"[-] GitHub OAuth Error: {e}")
        return "Authentication Failed", 400

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    session.pop('user_name', None)
    session.pop('avatar_url', None)
    return redirect(url_for('login'))


# =====================================================
# API & DASHBOARD ROUTES
# =====================================================
@app.route("/")
def index():
    # Pass session info so we can display the user's name/avatar on the dashboard later
    return render_template("dashboard.html", user_name=session.get('user_name'))

@app.route("/api/summary")
def api_summary():
    df = _load_analysis()
    if df is None:
        return jsonify({"no_data": True})

    for col in ["is_anomaly", "final_risk_level", "total_threat_score", "username", "source_ip", "mitre_techniques"]:
        if col not in df.columns:
            df[col] = None

    true_total_events = _get_raw_total_events()
    total_analyzed = int(len(df)) 
    
    anomalies = df[df["is_anomaly"] == 1]
    total_anomalies = int(len(anomalies))
    anomaly_rate = round((total_anomalies / total_analyzed) * 100, 2) if total_analyzed else 0

    risk_distribution = df["final_risk_level"].value_counts().to_dict()
    avg_threat_score = round(float(df["total_threat_score"].mean()), 2) if total_analyzed else 0

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
        "total_events": true_total_events,
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

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    if "final_risk_level" in df.columns:
        for level, cnt in df["final_risk_level"].value_counts().items():
            if level in counts:
                counts[level] = int(cnt)
    return jsonify(counts)

@app.route("/api/top-incidents")
def api_top_incidents():
    df = _load_analysis()
    if df is None:
        return jsonify({"no_data": True, "incidents": []})

    top = (
        df.sort_values("total_threat_score", ascending=False)
        .head(20)
        .copy()
    )

    records = []
    for _, row in top.iterrows():
        records.append({
            "username": _safe_str(row.get("username")),
            "source_ip": _safe_str(row.get("source_ip")),
            "machine": _safe_str(row.get("machine", "N/A")),
            "risk_level": _safe_str(row.get("final_risk_level")),
            "threat_score": float(row.get("total_threat_score", 0)),
            "mitre_techniques": _safe_str(row.get("mitre_techniques")),
        })
    return jsonify({"incidents": records})

@app.route("/api/mitre-techniques")
def api_mitre_techniques():
    df = _load_analysis()
    if df is None or "mitre_techniques" not in df.columns:
        return jsonify({"no_data": True, "techniques": {}})

    technique_counts = defaultdict(int)
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
    if df is None or "timestamp" not in df.columns:
        return jsonify({"no_data": True, "timeline": []})

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
            for _, row in timeline.iterrows() if pd.notna(row["hour_bucket"])
        ]
    })

@app.route("/api/user-risk")
def api_user_risk():
    df = _load_analysis()
    if df is None or "username" not in df.columns:
        return jsonify({"no_data": True, "users": []})

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
    if df is None or "source_ip" not in df.columns:
        return jsonify({"no_data": True, "ips": []})

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

@app.route("/api/sentinel-report")
def api_sentinel_report():
    try:
        sys.path.insert(0, BASE_DIR)
        from testollama import load_and_analyze, generate_report, sanitize_output

        summary = load_and_analyze()
        
        if not summary or summary.get("total_events", 0) == 0:
            return jsonify({"error": "No analysis data available in the database."}), 404

        if summary.get("total_anomalies", 0) == 0:
            return jsonify({"error": "No anomalies detected. Everything is secure!"}), 200

        raw_output, rejection_reasons = generate_report(summary)
        allowed = summary.get("allowed_mitre_techniques", []) or []

        if rejection_reasons:
            final_report = sanitize_output(raw_output, allowed)
        else:
            final_report = raw_output

        return jsonify({"report": final_report})

    except Exception as exc:
        import traceback
        print("[-] API 500 Error in Sentinel Report:")
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error. Check the terminal for details."}), 500

if __name__ == "__main__":
    cert_path = "cert.pem"
    key_path = "key.pem"
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        print("🛡️ ThreatWeaver SOC Dashboard starting securely on https://0.0.0.0:5001")
        app.run(host="0.0.0.0", port=5001, debug=False, ssl_context=(cert_path, key_path))
    else:
        print("🛡️ ThreatWeaver SOC Dashboard starting on http://0.0.0.0:5001")
        app.run(host="0.0.0.0", port=5001, debug=False)
