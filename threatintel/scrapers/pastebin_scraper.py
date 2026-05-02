import requests
from bs4 import BeautifulSoup

def fetch_pastebin():
    url = "https://pastebin.com/archive"

    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")

        results = []

        for link in soup.select(".maintable a")[:10]:
            try:
                paste_url = "https://pastebin.com" + link.get("href")
                raw_url = paste_url.replace("/","/raw/")

                raw = requests.get(raw_url, timeout=10).text

                results.append({
                    "type": "text",
                    "value": raw[:200],
                    "source": "pastebin"
                })

            except:
                continue

        return results

    except Exception as e:
        print("pastebin error:", e)
        return []