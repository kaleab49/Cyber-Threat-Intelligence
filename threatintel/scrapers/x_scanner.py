"""Twitter/X scraper helpers for IOC ingestion."""

from threatintel.services.feed_ingest import ingest_twitter_user


def scrape_twitter_user(username, limit=50):
    """
    Scrape recent tweets from a single account and ingest discovered IOCs.

    Args:
        username: Twitter/X username (with or without leading '@').
        limit: Maximum number of tweets to scan.

    Returns:
        dict: Ingestion summary (tweets scanned, IOCs processed, etc).
    """
    return ingest_twitter_user(username=username, limit=limit)


def scrape_twitter_users(usernames, limit=50):
    """
    Scrape multiple Twitter/X accounts and return per-user summaries.

    Args:
        usernames: Iterable of Twitter/X usernames.
        limit: Maximum tweets per user.

    Returns:
        list[dict]: Per-user ingestion results.
    """
    results = []
    for username in usernames:
        results.append(scrape_twitter_user(username=username, limit=limit))
    return results
