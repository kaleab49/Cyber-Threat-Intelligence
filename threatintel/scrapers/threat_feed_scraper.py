import requests
from threatintel.services.ingestion_service import ingest_event


def fetch_threat_feed():
    

    url = "https://pastebin.com/raw/your-test-link"  # temporary test source

    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.text

            # Send to pipeline
            ingest_event("threat_feed", data)

            print("Data ingested successfully")

        else:
            print(f"Failed: {response.status_code}")

    except Exception as e:
        print(f"Error: {e}")