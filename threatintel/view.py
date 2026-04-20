from rest_framework import viewsets
from .models import *
from .serializer import *

class IOCViewSet(viewsets.ModelViewSet):
    queryset = IOC.objects.all().order_by('-last_seen')
    serializer_class = IOCSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params

        ioc_type = params.get('type')
        source = params.get('source')
        min_threat_score = params.get('min_threat_score')
        search_value = params.get('search')
        ordering = params.get('ordering')

        if ioc_type:
            queryset = queryset.filter(type=ioc_type)
        if source:
            queryset = queryset.filter(source__iexact=source)
        if min_threat_score:
            try:
                queryset = queryset.filter(threat_score__gte=int(min_threat_score))
            except (TypeError, ValueError):
                pass
        if search_value:
            queryset = queryset.filter(value__icontains=search_value)

        if ordering in {'last_seen', '-last_seen', 'threat_score', '-threat_score', 'value', '-value'}:
            queryset = queryset.order_by(ordering)

        return queryset


class EventViewSet(viewsets.ModelViewSet):
    queryset = Event.objects.all().order_by('-timestamp')
    serializer_class = EventSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params

        source = params.get('source')
        ordering = params.get('ordering')

        if source:
            queryset = queryset.filter(source__iexact=source)
        if ordering in {'timestamp', '-timestamp', 'created_at', '-created_at'}:
            queryset = queryset.order_by(ordering)

        return queryset


class ThreatFeedViewSet(viewsets.ModelViewSet):
    queryset = ThreatFeed.objects.all()
    serializer_class = ThreatFeedSerializer


class MalwareViewSet(viewsets.ModelViewSet):
    queryset = Malware.objects.all()
    serializer_class = MalwareSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params

        hash_type = params.get('hash_type')
        source = params.get('source')
        search_value = params.get('search')
        ordering = params.get('ordering')

        if hash_type:
            queryset = queryset.filter(hash_type__iexact=hash_type)
        if source:
            queryset = queryset.filter(source__iexact=source)
        if search_value:
            queryset = queryset.filter(hash_value__icontains=search_value)
        if ordering in {'first_seen', '-first_seen', 'hash_value', '-hash_value'}:
            queryset = queryset.order_by(ordering)

        return queryset


class ThreatActorViewSet(viewsets.ModelViewSet):
    queryset = ThreatActor.objects.all()
    serializer_class = ThreatActorSerializer


class CampaignViewSet(viewsets.ModelViewSet):
    queryset = Campaign.objects.all()
    serializer_class = CampaignSerializer


class RelationshipViewSet(viewsets.ModelViewSet):
    queryset = Relationship.objects.all()
    serializer_class = RelationshipSerializer
