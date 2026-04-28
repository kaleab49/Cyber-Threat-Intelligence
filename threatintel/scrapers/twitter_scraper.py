# twitter_scraper.py
import requests
from bs4 import BeautifulSoup


def fetch_twitter():
    usernames = ["elonmusk"]  # extend later

    iocs = []

    for user in usernames:
        try:
            url = f"https://nitter.net/{user}"
            res = requests.get(url, timeout=10)

            if res.status_code != 200:
                continue

            soup = BeautifulSoup(res.text, "html.parser")
            tweets = soup.find_all("div", class_="timeline-item")[:10]

            for t in tweets:
                text = t.get_text()

                # simple IOC extraction
                if "http" in text:
                    iocs.append({"value": text, "type": "url", "source": "twitter"})

                if "CVE-" in text:
                    iocs.append({"value": text, "type": "cve", "source": "twitter"})

        except Exception:
            continue

    return iocs