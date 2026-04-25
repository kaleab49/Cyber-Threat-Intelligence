# threatintel/services/enrichment.py

def enrich_ioc(ioc):
    if not isinstance(ioc, dict):
        return {"error": "invalid ioc"}

    ioc_type = ioc.get("type")

    if ioc_type == "ip":
        ioc["score"] = 70
    elif ioc_type == "cve":
        ioc["score"] = 90
    else:
        ioc["score"] = 50

    return ioc