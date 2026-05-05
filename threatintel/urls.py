from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .view import *
from threatintel.api.graph_api import graph_data
from threatintel.api.analytics_api import dashboard_stats
from threatintel.api.ioc_api import extract_iocs_from_text
from threatintel.api.auth_api import register, login, refresh_token, logout, me
from threatintel.api.feed_ingest_api import (
    enrich_cves_circl_api,
    ingest_cisa_kev_api,
    ingest_urlhaus_recent_api,
    scrape_ioc_page_api,
)
from threatintel.api.scraper_api import (
    scraper_status, run_all_feeds_api,
    run_feed_threat_api, run_feed_pastebin_api,
    run_feed_darkweb_api, run_feed_malwarebazaar_api,
    run_feed_twitter_api,
)

router = DefaultRouter()
router.register(r'iocs', IOCViewSet)
router.register(r'events', EventViewSet)
router.register(r'feeds', ThreatFeedViewSet)
router.register(r'malware', MalwareViewSet)
router.register(r'actors', ThreatActorViewSet)
router.register(r'campaigns', CampaignViewSet)
router.register(r'relationships', RelationshipViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('analytics/dashboard/', dashboard_stats, name='dashboard-stats'),
    path('ioc/extract/', extract_iocs_from_text, name='extract-iocs'),
    path('feeds/ingest/urlhaus/recent/', ingest_urlhaus_recent_api, name='ingest-urlhaus-recent'),
    path('feeds/ingest/cisa/kev/', ingest_cisa_kev_api, name='ingest-cisa-kev'),
    path('feeds/ingest/scrape/', scrape_ioc_page_api, name='ingest-scrape-ioc-page'),
    path('feeds/enrich/circl/cves/', enrich_cves_circl_api, name='enrich-cves-circl'),
    path('graph/', graph_data, name='graph-data'),
    path('scrapers/', scraper_status, name='scraper-status'),
    path('scrapers/run-all/', run_all_feeds_api, name='scraper-run-all'),
    path('scrapers/threat-feed/', run_feed_threat_api, name='scraper-threat'),
    path('scrapers/pastebin/', run_feed_pastebin_api, name='scraper-pastebin'),
    path('scrapers/darkweb/', run_feed_darkweb_api, name='scraper-darkweb'),
    path('scrapers/malwarebazaar/', run_feed_malwarebazaar_api, name='scraper-malwarebazaar'),
    path('scrapers/twitter/', run_feed_twitter_api, name='scraper-twitter'),
    path('auth/register/', register,       name='auth-register'),
    path('auth/login/',    login,          name='auth-login'),
    path('auth/refresh/',  refresh_token,  name='auth-refresh'),
    path('auth/logout/',   logout,         name='auth-logout'),
    path('auth/me/',       me,             name='auth-me'),
]


# Add to urlpatterns:
