from celery import shared_task
from threatintel.analyzers.correlation_engine import correlate_iocs

@shared_task
def run_correlation():
    correlate_iocs()