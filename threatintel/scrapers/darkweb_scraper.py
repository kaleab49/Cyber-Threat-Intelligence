import re

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"


def fetch_darkweb():
    text = "Leak contains 185.199.110.153 and admin panel access"

    iocs = []

    for ip in re.findall(IP_REGEX, text):
        iocs.append({
            "type": "ip",
            "value": ip,
            "source": "darkweb"
        })

    return iocs