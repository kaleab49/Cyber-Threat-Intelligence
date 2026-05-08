from celery import shared_task
from threatintel.scrapers.feed_registry import FEEDS
from threatintel.services.enrichment.enrichment_service import enrich_ioc
from threatintel.models import IOC, Event
from django.utils import timezone


def _process_feed(name, feed_fn):
    """Shared logic: run a feed, enrich IOCs, save to DB."""
    raw_data = feed_fn()

    if not isinstance(raw_data, list):
        raw_data = []

    saved = 0
    errors = []

    for ioc in raw_data:
        if not isinstance(ioc, dict):
            continue

        value  = ioc.get("value", "").strip()
        itype  = ioc.get("type", "").strip()
        source = ioc.get("source", name).strip()

        if not value or not itype:
            continue

        try:
            enriched = enrich_ioc(ioc)
            threat_score = enriched.get("threat_score", 0) if isinstance(enriched, dict) else 0

            IOC.objects.upsert_ioc(
                value=value,
                ioc_type=itype,
                source=source,
                threat_score=threat_score,
            )

            Event.objects.create(
                source=source,
                raw_data=value,
                parsed_data=enriched if isinstance(enriched, dict) else ioc,
                timestamp=timezone.now(),
            )
            saved += 1

        except Exception as e:
            errors.append({"value": value, "error": str(e)})

    return {
        "feed":   name,
        "status": "success",
        "saved":  saved,
        "errors": errors[:10],
    }


# ── Individual tasks (can be triggered via API) ────────────────────────────

@shared_task
def run_feed_threat():
    return _process_feed("threat_feed", FEEDS["threat_feed"])


@shared_task
def run_feed_pastebin():
    return _process_feed("pastebin", FEEDS["pastebin"])


@shared_task
def run_feed_darkweb():
    return _process_feed("darkweb", FEEDS["darkweb"])


@shared_task
def run_feed_malwarebazaar():
    return _process_feed("malwarebazaar", FEEDS["malwarebazaar"])


@shared_task
def run_feed_twitter():
    return _process_feed("twitter", FEEDS["twitter"])


# ── Master task: run all feeds ─────────────────────────────────────────────

@shared_task
def run_all_feeds():
    results = {}
    for name, feed_fn in FEEDS.items():
        try:
            results[name] = _process_feed(name, feed_fn)
        except Exception as e:
            results[name] = {
                "feed":   name,
                "status": "failed",
                "error":  str(e),
            }
    return results
@shared_task
def run_feed_virustotal():
    return _process_feed("virustotal", FEEDS["virustotal"])
