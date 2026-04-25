from celery import shared_task
from threatintel.scrapers.feed_registry import FEEDS
from threatintel.services.enrichment import enrich_ioc


@shared_task
def run_all_feeds():
    results = {}

    for name, feed in FEEDS.items():
        try:
            raw_data = feed()

        
            if not raw_data:
                raw_data = []

            if isinstance(raw_data, dict):
                raw_data = [raw_data]

            if not isinstance(raw_data, list):
                raise ValueError(f"{name} returned invalid data type")

            enriched = []
            for ioc in raw_data:
                try:
                    enriched.append(enrich_ioc(ioc))
                except Exception as e:
                    enriched.append({
                        "ioc": ioc,
                        "error": str(e)
                    })

            results[name] = {
                "status": "success",
                "count": len(enriched),
                "data": enriched[:10]  # optional preview
            }

        except Exception as e:
            results[name] = {
                "status": "failed",
                "error": str(e),
            }

    return results