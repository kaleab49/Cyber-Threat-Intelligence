import requests

import os
from dotenv import load_dotenv
load_dotenv()
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY", "")

def fetch_pastebin():
    url = "https://threatfox-api.abuse.ch/api/v1/"
    try:
        res = requests.post(url,
            json={"query": "get_iocs", "days": 1},
            headers={"API-KEY": THREATFOX_API_KEY},
            timeout=15
        )
        data = res.json()
        results = []
        for item in data.get("data", [])[:50]:
            ioc_value = item.get("ioc_value", "").strip()
            ioc_type  = item.get("ioc_type", "").strip()
            type_map  = {
                "ip:port": "ip", "domain": "domain",
                "url": "url", "md5_hash": "md5", "sha256_hash": "sha256",
            }
            mapped_type = type_map.get(ioc_type, "url")
            if ioc_value:
                results.append({
                    "type":   mapped_type,
                    "value":  ioc_value.split(":")[0] if ioc_type == "ip:port" else ioc_value,
                    "source": "threatfox",
                })
        return results
    except Exception as e:
        print("threatfox error:", e)
        return []
