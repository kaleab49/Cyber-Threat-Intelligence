import requests

BEARER_TOKEN = "YOUR_TOKEN"

def fetch_twitter():
    url = "https://api.twitter.com/2/tweets/search/recent"

    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}"
    }

    params = {
        "query": "malware OR CVE OR breach",
        "max_results": 10
    }

    try:
        res = requests.get(url, headers=headers, params=params)
        res.raise_for_status()

        data = res.json()

        results = []

        for tweet in data.get("data", []):
            results.append({
                "type": "text",
                "value": tweet["text"],
                "source": "twitter"
            })

        return results

    except Exception as e:
        print("twitter error:", e)
        return []