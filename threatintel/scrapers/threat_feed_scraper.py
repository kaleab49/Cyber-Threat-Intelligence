import feedparser

def fetch_threat_feed():
    feeds = [
        "https://www.cert.ssi.gouv.fr/feed/",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://otx.alienvault.com/api/v1/indicators/export"
    ]

    results = []

    for url in feeds:
        try:
            data = feedparser.parse(url)

            for entry in data.entries[:20]:
                results.append({
                    "type": "url",
                    "value": entry.get("title", ""),
                    "source": "threat_feed",
                })

        except Exception as e:
            print("feed error:", e)

    return results