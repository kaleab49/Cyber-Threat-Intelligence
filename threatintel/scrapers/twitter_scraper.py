import os
import re

import requests

TWITTER_API_URL = "https://api.twitter.com/2/tweets/search/recent"


def _extract_iocs_from_text(text):
    patterns = {
        "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b",
        "url": r"\bhttps?://[^\s\"'<>]+",
        "md5": r"\b[a-fA-F0-9]{32}\b",
        "sha1": r"\b[a-fA-F0-9]{40}\b",
        "sha256": r"\b[a-fA-F0-9]{64}\b",
        "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    }
    extracted = []
    for ioc_type, pattern in patterns.items():
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            extracted.append((ioc_type, match.group(0)))
    return extracted

def fetch_twitter():
    bearer_token = os.getenv("TWITTER_BEARER_TOKEN", "").strip()
    if not bearer_token:
        return []

    headers = {
        "Authorization": f"Bearer {bearer_token}"
    }

    params = {
        "query": "malware OR CVE OR breach",
        "max_results": 10
    }

    try:
        res = requests.get(TWITTER_API_URL, headers=headers, params=params, timeout=15)
        res.raise_for_status()

        data = res.json()

        results = []

        for tweet in data.get("data", []):
            for ioc_type, value in _extract_iocs_from_text(tweet.get("text", "")):
                results.append({
                    "type": ioc_type,
                    "value": value,
                    "source": "twitter"
                })

        return results

    except requests.RequestException:
        return []