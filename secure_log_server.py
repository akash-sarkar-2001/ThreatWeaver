from flask import Flask, request, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import uuid

# ====================================================
# CONFIGURATION
# ====================================================

UPLOAD_FOLDER = r"C:\Users\Server-PC\Desktop\log-collector"
ALLOWED_EXTENSIONS = {"csv"}
API_KEY = "ThreatWeaverSecureKey123"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

# Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute"]
)

# ====================================================
# HELPERS
# ====================================================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ====================================================
# SECURE FILE UPLOAD ENDPOINT
# ====================================================

@app.route('/upload', methods=['POST'])
@limiter.limit("20 per minute")  # prevent DoS
def upload_log():

    # ----------------------------
    # API KEY AUTHENTICATION
    # ----------------------------
    client_key = request.headers.get("X-API-KEY")

    if client_key != API_KEY:
        abort(401, "Unauthorized")

    # ----------------------------
    # CHECK FILE EXISTENCE
    # ----------------------------
    if 'file' not in request.files:
        return "No file sent", 400

    file = request.files['file']

    if file.filename == "":
        return "Empty filename", 400

    # ----------------------------
    # FILE TYPE VALIDATION
    # ----------------------------
    if not allowed_file(file.filename):
        return "Invalid file type", 400

    # ----------------------------
    # SECURE FILE NAME
    # ----------------------------
    filename = secure_filename(file.filename)

    save_path = os.path.join(UPLOAD_FOLDER, filename)

    file.save(save_path)

    print(f"[+] Received {filename} at {datetime.now()}")
    return "Upload successful", 200


# ====================================================
# SERVER START
# ====================================================

if __name__ == '__main__':
    app.run(
        host="0.0.0.0",
        port=8443,
        ssl_context=(
            "C:\\https_cert\\cert.pem",
            "C:\\https_cert\\key.pem"
        )
    )
