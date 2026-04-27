"""Shared helpers for the threatintel app (keep Celery tasks in tasks.py)."""


def run_correlation_sync():
    from threatintel.analyzers.correlation_engine import correlate_iocs

    correlate_iocs()
