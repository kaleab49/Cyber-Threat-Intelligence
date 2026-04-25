from celery import shared_task
from threatintel.scrapers.threat_feed_scraper import fetch_threat_feed


@shared_task
def run_threat_feed_ingestion():
 
    fetch_threat_feed()
    return "Threat feed ingestion completed"



