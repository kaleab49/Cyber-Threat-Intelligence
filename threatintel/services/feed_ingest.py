import ipaddress
from datetime import datetime
from urllib.parse import urlparse

import requests
from django.utils import timezone

from threatintel.models import Event, IOC


URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
CIRCL_CVE_URL = "https://cve.circl.lu/api/cve/"


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
    ioc, created = IOC.objects.get_or_create(
        value=value,
        type=ioc_type,
        source=source,
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


def ingest_urlhaus_recent(limit=100):
    response = requests.post(URLHAUS_RECENT_URL, timeout=20)
    response.raise_for_status()
    payload = response.json()
    urls = payload.get("urls", [])[: max(1, min(int(limit), 1000))]

    created_events = 0
    created_iocs = 0

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
            threat_score=80,
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
                    threat_score=70,
                    tags=["urlhost", "urlhaus"],
                )
            else:
                _upsert_ioc(
                    value=host,
                    ioc_type="domain",
                    source="urlhaus",
                    threat_score=70,
                    tags=["urlhost", "urlhaus"],
                )

    return {
        "source": "urlhaus",
        "requested": min(int(limit), 1000),
        "events_created": created_events,
        "ioc_processed": created_iocs,
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
