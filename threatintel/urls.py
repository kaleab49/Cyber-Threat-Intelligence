from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .view import *
from threatintel.api.analytics_api import dashboard_stats
from threatintel.api.ioc_api import extract_iocs_from_text
from threatintel.api.feed_ingest_api import enrich_cves_circl_api, ingest_urlhaus_recent_api

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
    path('feeds/enrich/circl/cves/', enrich_cves_circl_api, name='enrich-cves-circl'),
]