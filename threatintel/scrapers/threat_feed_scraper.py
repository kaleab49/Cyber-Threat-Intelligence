import requests

def fetch_threat_feed():
    url = "https://pastebin.com/raw/your-test-link"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        text = response.text

        # TEMP: convert raw text → IOC format (placeholder logic)
        iocs = []

        for word in text.split():
            if word.count(".") == 3:  # naive IP detection
                iocs.append({"type": "ip", "value": word})

        return iocs

    except Exception as e:
        print(f"Failed threat_feed: {e}")
        return []