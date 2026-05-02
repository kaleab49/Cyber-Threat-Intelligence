import feedparser

def fetch_threat_feed():
    feeds = [
        "https://www.cert.ssi.gouv.fr/feed/",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    ]
    results = []
    for url in feeds:
        try:
            data = feedparser.parse(url)
            for entry in data.entries[:20]:
                link = entry.get("link", "").strip()
                if link and link.startswith("http"):
                    results.append({
                        "type": "url",
                        "value": link,
                        "source": "threat_feed",
                    })
        except Exception as e:
            print("feed error:", e)
    return results
