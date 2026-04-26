SOURCE_SCORES = {
    "cisa-kev": 95,
    "urlhaus": 80,
    "web-scrape": 60,
    "twitter": 70,
}


def get_source_score(source, default=50):
    normalized_source = str(source).strip().lower()
    return SOURCE_SCORES.get(normalized_source, default)
