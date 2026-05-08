from rest_framework.decorators import api_view
from rest_framework.response import Response
from threatintel.tasks import (
    run_all_feeds, run_feed_threat, run_feed_pastebin,
    run_feed_darkweb, run_feed_malwarebazaar, run_feed_twitter,
)

def _trigger(task_fn, async_mode):
    if async_mode:
        job = task_fn.delay()
        return Response({"task_id": job.id, "status": "queued"})
    return Response(task_fn())

@api_view(["POST"])
def run_all_feeds_api(request):
    return _trigger(run_all_feeds, request.data.get("async", False))

@api_view(["POST"])
def run_feed_threat_api(request):
    return _trigger(run_feed_threat, request.data.get("async", False))

@api_view(["POST"])
def run_feed_pastebin_api(request):
    return _trigger(run_feed_pastebin, request.data.get("async", False))

@api_view(["POST"])
def run_feed_darkweb_api(request):
    return _trigger(run_feed_darkweb, request.data.get("async", False))

@api_view(["POST"])
def run_feed_malwarebazaar_api(request):
    return _trigger(run_feed_malwarebazaar, request.data.get("async", False))

@api_view(["POST"])
def run_feed_twitter_api(request):
    return _trigger(run_feed_twitter, request.data.get("async", False))

@api_view(["GET"])
def scraper_status(request):
    return Response({
        "scrapers": [
            {"name": "threat_feed",   "endpoint": "/api/scrapers/threat-feed/",   "requires_key": False},
            {"name": "pastebin",      "endpoint": "/api/scrapers/pastebin/",      "requires_key": False},
            {"name": "darkweb",       "endpoint": "/api/scrapers/darkweb/",       "requires_key": False},
            {"name": "malwarebazaar", "endpoint": "/api/scrapers/malwarebazaar/", "requires_key": True},
            {"name": "twitter",       "endpoint": "/api/scrapers/twitter/",       "requires_key": True},
        ],
        "run_all": "/api/scrapers/run-all/",
    })

from threatintel.tasks import run_feed_virustotal

@api_view(["POST"])
def run_feed_virustotal_api(request):
    """POST /api/scrapers/virustotal/"""
    return _trigger(run_feed_virustotal, request.data.get("async", False))
