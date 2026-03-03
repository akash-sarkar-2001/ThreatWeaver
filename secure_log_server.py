from flask import Flask, request
import os
from datetime import datetime

UPLOAD_FOLDER = r"C:\Users\Server-PC\Desktop\log-collector"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_log():
    if 'file' not in request.files:
        return "No file sent", 400
    
    file = request.files['file']
    save_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(save_path)

    print(f"[+] Received {file.filename} at {datetime.now()}")
    return "Upload successful", 200


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8443, ssl_context=("C:\\https_cert\\cert.pem",
                                                     "C:\\https_cert\\key.pem"))
