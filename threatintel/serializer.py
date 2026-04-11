from rest_framework import serializers
from .models import *

class IOCSerializer(serializers.ModelSerializer):
    class Meta:
        model = IOC
        fields = '__all__'


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = '__all__'


class ThreatFeedSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatFeed
        fields = '__all__'


class MalwareSerializer(serializers.ModelSerializer):
    class Meta:
        model = Malware
        fields = '__all__'


class ThreatActorSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatActor
        fields = '__all__'


class CampaignSerializer(serializers.ModelSerializer):
    class Meta:
        model = Campaign
        fields = '__all__'


class RelationshipSerializer(serializers.ModelSerializer):
    class Meta:
        model = Relationship
        fields = '__all__'