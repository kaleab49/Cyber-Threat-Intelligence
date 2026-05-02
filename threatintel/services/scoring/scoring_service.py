# services/scoring/scoring_service.py
def get_source_score(source):
    if source == "CISA":
        return 40
    elif source == "URLhaus":
        return 30
    else:
        return 10
def score_ioc(ioc):
    score = 0

    # Frequency
    if ioc.times_seen >= 5:
        score += 40
    elif ioc.times_seen >= 2:
        score += 20

    # Source reliability
    if hasattr(ioc, "source"):
        if ioc.source == "CISA":
            score += 40
        elif ioc.source == "URLhaus":
            score += 30

    # Type-based
    if ioc.type == "ip":
        score += 10
    elif ioc.type == "domain":
        score += 15

    return min(score, 100)


def get_severity(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def score_iocs(iocs):
    for ioc in iocs:
        ioc.score = score_ioc(ioc)
        ioc.severity = get_severity(ioc.score)
        ioc.save()
    return iocs