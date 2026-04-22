from celery import shared_task
from threatintel.analyzers.correlation_engine import correlate_iocs
from threatintel.services.feed_ingest import ingest_cisa_kev, ingest_urlhaus_recent

@shared_task
def run_correlation():
    correlate_iocs()


@shared_task
def run_daily_feed_ingest():
    return {
        "urlhaus": ingest_urlhaus_recent(limit=100),
        "cisa_kev": ingest_cisa_kev(limit=100),
    }