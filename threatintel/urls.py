from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .view import *

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
]