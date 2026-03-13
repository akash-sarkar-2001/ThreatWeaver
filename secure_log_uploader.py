import requests
import time
import os

SERVER_URL = "https://192.168.40.10:8443/upload"
FILE_TO_SEND = "client_logs.csv"

# TLS certificate to trust
CERT_PATH = "C:\\https_cert\\cert.pem"

# API authentication
API_KEY = "ThreatWeaverSecureKey123"

def send_file():

    if not os.path.exists(FILE_TO_SEND):
        print("[!] client_logs.csv not found")
        return

    try:

        with open(FILE_TO_SEND, 'rb') as f:

            files = {'file': (FILE_TO_SEND, f)}

            headers = {
                "X-API-KEY": API_KEY
            }

            r = requests.post(
                SERVER_URL,
                files=files,
                headers=headers,
                verify=CERT_PATH
            )

        if r.status_code == 200:
            print("[+] Secure upload successful")

        else:
            print("[-] Upload failed:", r.text)

    except requests.exceptions.SSLError:
        print("[-] TLS verification failed. Certificate not trusted.")

    except Exception as e:
        print("[-] Error:", e)


while True:
    send_file()
    time.sleep(60)
