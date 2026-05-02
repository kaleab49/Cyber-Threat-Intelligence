from celery import shared_task
from threatintel.scrapers.feed_registry import FEEDS
from threatintel.services.enrichment.enrichment_service import enrich_ioc


@shared_task
def run_all_feeds():
    results = {}

    for name, feed in FEEDS.items():
        try:
            raw_data = feed()

            # 1. FORCE LIST
            if not isinstance(raw_data, list):
                raw_data = []

            enriched = []

            # 2. PROCESS IOC BY IOC (CRITICAL FIX)
            for ioc in raw_data:
                if not isinstance(ioc, dict):
                    continue

                try:
                    enriched_ioc = enrich_ioc(ioc)
                    enriched.append(enriched_ioc)

                except Exception as e:
                    enriched.append({
                        "ioc": ioc,
                        "error": str(e)
                    })

            results[name] = {
                "status": "success",
                "count": len(enriched),
                "data": enriched[:10]
            }

        except Exception as e:
            results[name] = {
                "status": "failed",
                "error": str(e),
            }

    return results