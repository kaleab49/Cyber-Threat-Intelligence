import ipaddress
import re
from datetime import datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from django.utils import timezone

from threatintel.models import Event, IOC
from threatintel.services.scoring import get_source_score

try:
    import snscrape.modules.twitter as sntwitter
except ImportError:  # pragma: no cover - optional dependency
    sntwitter = None


URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
CIRCL_CVE_URL = "https://cve.circl.lu/api/cve/"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_timestamp(value):
    if not value:
        return timezone.now()

    if isinstance(value, datetime):
        return value

    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt)
            return timezone.make_aware(dt, timezone.get_current_timezone()) if timezone.is_naive(dt) else dt
        except ValueError:
            continue

    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return timezone.make_aware(dt, timezone.get_current_timezone()) if timezone.is_naive(dt) else dt
    except ValueError:
        return timezone.now()


def _is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _upsert_ioc(value, ioc_type, source, threat_score=0, tags=None):
    normalized_value = IOC.normalize_for_type(ioc_type, value)
    normalized_source = str(source).strip().lower()
    ioc, created = IOC.objects.get_or_create(
        value=normalized_value,
        type=ioc_type,
        source=normalized_source,
        defaults={"threat_score": threat_score, "tags": tags or []},
    )
    if not created:
        updated = False
        if threat_score > ioc.threat_score:
            ioc.threat_score = threat_score
            updated = True
        if tags:
            existing = ioc.tags if isinstance(ioc.tags, list) else []
            merged = sorted(set(existing + tags))
            if merged != existing:
                ioc.tags = merged
                updated = True
        if updated:
            ioc.save(update_fields=["threat_score", "tags", "last_seen"])
    return ioc


def _extract_iocs_from_text(text):
    if not text:
        return []

    patterns = {
        "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b",
        "url": r"\bhttps?://[^\s\"'<>]+",
        "md5": r"\b[a-fA-F0-9]{32}\b",
        "sha1": r"\b[a-fA-F0-9]{40}\b",
        "sha256": r"\b[a-fA-F0-9]{64}\b",
        "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    }
    extracted = []
    for ioc_type, pattern in patterns.items():
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            extracted.append((ioc_type, match.group(0)))
    return extracted


def ingest_urlhaus_recent(limit=100):
    response = requests.post(URLHAUS_RECENT_URL, timeout=20)
    response.raise_for_status()
    payload = response.json()
    urls = payload.get("urls", [])[: max(1, min(int(limit), 1000))]

    created_events = 0
    created_iocs = 0

    base_score = get_source_score("urlhaus")

    for item in urls:
        url_value = (item.get("url") or "").strip()
        if not url_value:
            continue

        timestamp = _parse_timestamp(item.get("date_added"))
        Event.objects.create(
            source="urlhaus",
            raw_data=url_value,
            parsed_data=item,
            timestamp=timestamp,
        )
        created_events += 1

        ioc = _upsert_ioc(
            value=url_value,
            ioc_type="url",
            source="urlhaus",
            threat_score=base_score,
            tags=["malicious", "urlhaus"],
        )
        if ioc:
            created_iocs += 1

        host = urlparse(url_value).hostname
        if host:
            if _is_ip_address(host):
                _upsert_ioc(
                    value=host,
                    ioc_type="ip",
                    source="urlhaus",
                    threat_score=base_score,
                    tags=["urlhost", "urlhaus"],
                )
            else:
                _upsert_ioc(
                    value=host,
                    ioc_type="domain",
                    source="urlhaus",
                    threat_score=base_score,
                    tags=["urlhost", "urlhaus"],
                )

    return {
        "source": "urlhaus",
        "requested": min(int(limit), 1000),
        "events_created": created_events,
        "ioc_processed": created_iocs,
    }


def ingest_cisa_kev(limit=100):
    response = requests.get(CISA_KEV_URL, timeout=20)
    response.raise_for_status()
    payload = response.json()
    vulnerabilities = payload.get("vulnerabilities", [])[: max(1, min(int(limit), 2000))]

    created_events = 0
    ioc_processed = 0

    base_score = get_source_score("cisa-kev")

    for item in vulnerabilities:
        cve = (item.get("cveID") or "").strip()
        if not cve:
            continue

        Event.objects.create(
            source="cisa-kev",
            raw_data=cve,
            parsed_data=item,
            timestamp=timezone.now(),
        )
        created_events += 1

        _upsert_ioc(
            value=cve,
            ioc_type="cve",
            source="cisa-kev",
            threat_score=base_score,
            tags=["kev", "cisa"],
        )
        ioc_processed += 1

    return {
        "source": "cisa-kev",
        "requested": min(int(limit), 2000),
        "events_created": created_events,
        "ioc_processed": ioc_processed,
    }


def scrape_ioc_page(url, source="web-scrape", limit=500):
    response = requests.get(url, timeout=20)
    response.raise_for_status()
    html = response.text

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator=" ", strip=True)
    extracted = _extract_iocs_from_text(text)[: max(1, min(int(limit), 5000))]

    Event.objects.create(
        source=source,
        raw_data=url,
        parsed_data={"url": url, "matched_count": len(extracted)},
        timestamp=timezone.now(),
    )

    base_score = get_source_score(source)

    ioc_processed = 0
    for ioc_type, value in extracted:
        _upsert_ioc(
            value=value,
            ioc_type=ioc_type,
            source=source,
            threat_score=base_score,
            tags=["scraped"],
        )
        ioc_processed += 1

    return {
        "source": source,
        "url": url,
        "ioc_processed": ioc_processed,
    }


def ingest_twitter_user(username, limit=50):
    if sntwitter is None:
        raise RuntimeError("Twitter scraping requires snscrape. Install with: pip install snscrape")

    normalized_user = str(username).strip().lstrip("@")
    if not normalized_user:
        return {"source": "twitter", "username": username, "tweets_scanned": 0, "ioc_processed": 0}

    max_items = max(1, min(int(limit), 500))
    query = f"from:{normalized_user}"

    ioc_processed = 0
    tweets_scanned = 0
    base_score = get_source_score("twitter")

    for tweet in sntwitter.TwitterSearchScraper(query).get_items():
        if tweets_scanned >= max_items:
            break

        tweet_text = (getattr(tweet, "rawContent", "") or "").strip()
        if not tweet_text:
            tweets_scanned += 1
            continue

        Event.objects.create(
            source="twitter",
            raw_data=f"https://x.com/{normalized_user}/status/{tweet.id}",
            parsed_data={
                "id": str(tweet.id),
                "username": normalized_user,
                "date": tweet.date.isoformat() if getattr(tweet, "date", None) else None,
                "text": tweet_text,
            },
            timestamp=_parse_timestamp(getattr(tweet, "date", None)),
        )

        for ioc_type, value in _extract_iocs_from_text(tweet_text):
            _upsert_ioc(
                value=value,
                ioc_type=ioc_type,
                source="twitter",
                threat_score=base_score,
                tags=["tweet", "osint"],
            )
            ioc_processed += 1

        tweets_scanned += 1

    return {
        "source": "twitter",
        "username": normalized_user,
        "tweets_scanned": tweets_scanned,
        "ioc_processed": ioc_processed,
    }


def enrich_cves_from_circl(limit=50):
    cves = IOC.objects.filter(type="cve").order_by("-last_seen")[: max(1, min(int(limit), 500))]
    enriched = 0
    failures = []

    for ioc in cves:
        cve_id = ioc.value.upper()
        try:
            response = requests.get(f"{CIRCL_CVE_URL}{cve_id}", timeout=20)
            if response.status_code != 200:
                failures.append({"cve": cve_id, "status_code": response.status_code})
                continue
            details = response.json()

            cvss = details.get("cvss") or 0
            try:
                score = min(100, int(float(cvss) * 10))
            except (ValueError, TypeError):
                score = ioc.threat_score

            tags = ["circl"]
            if details.get("cisaKnownExploited"):
                tags.append("kev")

            _upsert_ioc(
                value=ioc.value,
                ioc_type="cve",
                source=ioc.source,
                threat_score=max(ioc.threat_score, score),
                tags=tags,
            )
            Event.objects.create(
                source="circl",
                raw_data=cve_id,
                parsed_data=details,
                timestamp=timezone.now(),
            )
            enriched += 1
        except requests.RequestException as exc:
            failures.append({"cve": cve_id, "error": str(exc)})

    return {
        "source": "circl",
        "requested": min(int(limit), 500),
        "enriched": enriched,
        "failed": failures[:20],
    }
