from datetime import datetime

from django.db.models import Q
from rest_framework import viewsets
from .models import *
from .serializer import *


def parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


class IOCViewSet(viewsets.ModelViewSet):
    queryset = IOC.objects.all().order_by('-last_seen')
    serializer_class = IOCSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params

        ioc_type = params.get('type')
        source = params.get('source')
        min_threat_score = params.get('min_threat_score')
        max_threat_score = params.get('max_threat_score')
        search_value = params.get('search') or params.get('q')
        value_exact = params.get('value')
        tags = params.getlist('tags') or params.get('tag')
        first_seen_from = parse_iso_datetime(params.get('first_seen_from'))
        first_seen_to = parse_iso_datetime(params.get('first_seen_to'))
        last_seen_from = parse_iso_datetime(params.get('last_seen_from'))
        last_seen_to = parse_iso_datetime(params.get('last_seen_to'))
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
        if max_threat_score:
            try:
                queryset = queryset.filter(threat_score__lte=int(max_threat_score))
            except (TypeError, ValueError):
                pass
        if value_exact:
            queryset = queryset.filter(value__iexact=value_exact)
        if search_value:
            queryset = queryset.filter(
                Q(value__icontains=search_value) | Q(source__icontains=search_value)
            )
        if tags:
            parsed_tags = []
            if isinstance(tags, str):
                parsed_tags = [tag.strip() for tag in tags.split(',') if tag.strip()]
            else:
                for tag_value in tags:
                    parsed_tags.extend(
                        [tag.strip() for tag in tag_value.split(',') if tag.strip()]
                    )
            for tag in parsed_tags:
                queryset = queryset.filter(tags__icontains=f'"{tag}"')
        if first_seen_from:
            queryset = queryset.filter(first_seen__gte=first_seen_from)
        if first_seen_to:
            queryset = queryset.filter(first_seen__lte=first_seen_to)
        if last_seen_from:
            queryset = queryset.filter(last_seen__gte=last_seen_from)
        if last_seen_to:
            queryset = queryset.filter(last_seen__lte=last_seen_to)

        if ordering in {
            'last_seen', '-last_seen', 'threat_score', '-threat_score',
            'value', '-value', 'first_seen', '-first_seen'
        }:
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
