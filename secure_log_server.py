from flask import Flask, request, jsonify, abort
import psycopg2
from psycopg2 import extras
import os
import dotenv

dotenv.load_dotenv()

app = Flask(__name__)

# ====================================================
# CONFIGURATION
# ====================================================
API_KEY = os.getenv("API_KEY")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "threatweaver_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS")
DB_PORT = os.getenv("DB_PORT", "5432")

# ====================================================
# SECURE JSON UPLOAD ENDPOINT
# ====================================================
@app.route('/api/upload-logs', methods=['POST'])
def upload_logs():
    # 1. Authenticate
    if request.headers.get("X-API-KEY") != API_KEY:
        abort(401, "Unauthorized")

    # 2. Get the JSON payload
    logs = request.get_json()
    if not logs or not isinstance(logs, list):
        return jsonify({"error": "Invalid payload format. Expected JSON array."}), 400

    # 3. Format data for database insertion
    values_to_insert = [
        (
            log.get("timestamp"), log.get("event_id"), log.get("username"),
            log.get("source_ip"), log.get("process_name"),
            log.get("command_line"), log.get("source_machine")
        )
        for log in logs
    ]

    # 4. Insert into PostgreSQL
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS, port=DB_PORT)
        cursor = conn.cursor()
        
        insert_query = """
            INSERT INTO raw_logs (timestamp, event_id, username, source_ip, process_name, command_line, source_machine)
            VALUES %s
        """
        
        extras.execute_values(cursor, insert_query, values_to_insert)
        conn.commit()
        
        cursor.close()
        conn.close()
        
        print(f"[+] Received and stored {len(logs)} client logs over secure tunnel.")
        return jsonify({"message": "Logs successfully ingested"}), 200

    except Exception as e:
        print(f"[-] Database Error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    cert_path = os.getenv("CERT_PATH", "cert.pem")
    key_path = os.getenv("KEY_PATH", "key.pem")
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        print(f"🛡️ Secure Log Server starting on HTTPS (Port 5000)...")
        app.run(host='0.0.0.0', port=5000, ssl_context=(cert_path, key_path))
    else:
        print(f"[!] WARNING: SSL Certificates not found. Running in vulnerable HTTP mode.")
        app.run(host='0.0.0.0', port=5000)
