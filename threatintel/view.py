from rest_framework import viewsets
from .models import *
from .serializer import *

class IOCViewSet(viewsets.ModelViewSet):
    queryset = IOC.objects.all().order_by('-last_seen')
    serializer_class = IOCSerializer


class EventViewSet(viewsets.ModelViewSet):
    queryset = Event.objects.all().order_by('-timestamp')
    serializer_class = EventSerializer


class ThreatFeedViewSet(viewsets.ModelViewSet):
    queryset = ThreatFeed.objects.all()
    serializer_class = ThreatFeedSerializer


class MalwareViewSet(viewsets.ModelViewSet):
    queryset = Malware.objects.all()
    serializer_class = MalwareSerializer


class ThreatActorViewSet(viewsets.ModelViewSet):
    queryset = ThreatActor.objects.all()
    serializer_class = ThreatActorSerializer


class CampaignViewSet(viewsets.ModelViewSet):
    queryset = Campaign.objects.all()
    serializer_class = CampaignSerializer


class RelationshipViewSet(viewsets.ModelViewSet):
    queryset = Relationship.objects.all()
    serializer_class = RelationshipSerializer
