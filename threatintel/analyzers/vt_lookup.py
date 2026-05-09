import requests

import os
from dotenv import load_dotenv
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

def vt_lookup(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VT_API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return {
            "malicious": data["data"]["attributes"]["last_analysis_stats"]["malicious"],
            "suspicious": data["data"]["attributes"]["last_analysis_stats"]["suspicious"],
        }
    return {} 

    