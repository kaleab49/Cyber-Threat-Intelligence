import requests
from threatintel.services.ingestion_service import ingest_event


def fetch_threat_feed():
    url = "https://pastebin.com/raw/your-test-link"

    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.text

            ingest_event("threat_feed", data)

            print("✔ Data ingested successfully")
            return "success"

        print(f"Failed: {response.status_code}")
        return "failed"

    except Exception as e:
        print(f"Error: {e}")
        return "error"