import os
import requests
from dotenv import load_dotenv

load_dotenv()  # Loads .env

SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")

def send_to_splunk(event_data):
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"
    }
    payload = {
        "event": event_data,
        "sourcetype": "nmap_scan"
    }
    response = requests.post(
        SPLUNK_HEC_URL,
        json=payload,
        headers=headers,
        verify=False  # <---- THIS MUST BE PRESENT!
    )
    if response.status_code != 200:
        print(f"Splunk HEC Error: {response.status_code} {response.text}")
    return response.status_code, response.text
