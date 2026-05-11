def enrich_ioc(ioc):
    if not isinstance(ioc, dict):
        return {"error": "invalid ioc"}

    ioc_type = ioc.get("type")
    score = 50

    if ioc_type == "ip":
        score = 70
    elif ioc_type == "cve":
        score = 90

    # Keep backward compatibility (`score`) while standardizing on `threat_score`.
    ioc["score"] = score
    ioc["threat_score"] = score
    return ioc


def enrich_iocs(iocs):
    if not isinstance(iocs, list):
        return []

    return [enrich_ioc(ioc) for ioc in iocs if isinstance(ioc, dict)]