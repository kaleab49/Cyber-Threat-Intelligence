import re

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
CVE_REGEX = r"\bCVE-\d{4}-\d{4,7}\b"


def fetch_pastebin():
    text = "Attack from 8.8.8.8 using CVE-2024-1234"

    iocs = []

    for ip in re.findall(IP_REGEX, text):
        iocs.append({
            "type": "ip",
            "value": ip,
            "source": "pastebin"
        })

    for cve in re.findall(CVE_REGEX, text):
        iocs.append({
            "type": "cve",
            "value": cve,
            "source": "pastebin"
        })

    return iocs