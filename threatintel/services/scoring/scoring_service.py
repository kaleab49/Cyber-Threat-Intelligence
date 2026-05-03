# services/scoring/scoring_service.py
def get_source_score(source):
    key = str(source or "").strip().lower()
    if key in ("cisa", "cisa-kev"):
        return 40
    if key == "urlhaus":
        return 30
    if key == "twitter":
        return 25
    return 10


def score_ioc(ioc):
    score = 0

    # Frequency
    if ioc.times_seen >= 5:
        score += 40
    elif ioc.times_seen >= 2:
        score += 20

    # Source reliability
    src = str(getattr(ioc, "source", "") or "").strip().lower()
    if src in ("cisa", "cisa-kev"):
        score += 40
    elif src == "urlhaus":
        score += 30
    elif src == "twitter":
        score += 25

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
        computed = score_ioc(ioc)
        new_score = max(ioc.threat_score or 0, computed)
        if new_score != ioc.threat_score:
            ioc.threat_score = new_score
            ioc.save(update_fields=["threat_score"])
    return iocs


def calculate_scores(iocs):
    """Backward-compatible alias used by older call sites."""
    return score_iocs(iocs)