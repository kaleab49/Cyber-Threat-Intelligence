import re

PATTERNS = {
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "url": r"https?://[^\s]+",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"CVE-\d{4}-\d{4,7}",
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
}

def extract_iocs(text):
    results = []

    for ioc_type, pattern in PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            results.append({
                "type": ioc_type,
                "value": match
            })

    return results