import requests
import time
import os

SERVER_URL = "https://192.168.40.10:8443/upload"
FILE_TO_SEND = "client_logs.csv"

# Ignore self-signed certificate warnings
requests.packages.urllib3.disable_warnings()

def send_file():
    if not os.path.exists(FILE_TO_SEND):
        print("[!] client_logs.csv not found")
        return
    
    try:
        with open(FILE_TO_SEND, 'rb') as f:
            files = {'file': (FILE_TO_SEND, f)}
            r = requests.post(SERVER_URL, files=files, verify=False)
        
        if r.status_code == 200:
            print("[+] Secure upload successful")
        else:
            print("[-] Upload failed:", r.text)

    except Exception as e:
        print("[-] Error:", e)


while True:
    send_file()
    time.sleep(60)
