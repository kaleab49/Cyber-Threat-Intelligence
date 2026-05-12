from django.contrib import admin
from .models import IOC, Event, ThreatFeed, Malware, ThreatActor, Campaign, Relationship


@admin.register(IOC)
class IOCAdmin(admin.ModelAdmin):
    list_display  = ('value', 'type', 'source', 'threat_score', 'first_seen', 'last_seen')
    list_filter   = ('type', 'source')
    search_fields = ('value', 'source', 'tags')
    ordering      = ('-threat_score', '-last_seen')
    readonly_fields = ('id', 'first_seen', 'last_seen')


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display  = ('source', 'raw_data', 'timestamp', 'created_at')
    list_filter   = ('source',)
    search_fields = ('source', 'raw_data')
    ordering      = ('-timestamp',)
    readonly_fields = ('id', 'created_at')


@admin.register(ThreatFeed)
class ThreatFeedAdmin(admin.ModelAdmin):
    list_display  = ('name', 'url', 'last_fetched')
    search_fields = ('name', 'url')


@admin.register(Malware)
class MalwareAdmin(admin.ModelAdmin):
    list_display  = ('name', 'hash_value', 'hash_type', 'source', 'first_seen')
    list_filter   = ('hash_type', 'source')
    search_fields = ('name', 'hash_value', 'source')
    ordering      = ('-first_seen',)
    readonly_fields = ('id', 'first_seen')


@admin.register(ThreatActor)
class ThreatActorAdmin(admin.ModelAdmin):
    list_display  = ('name', 'country')
    search_fields = ('name', 'country', 'aliases')


@admin.register(Campaign)
class CampaignAdmin(admin.ModelAdmin):
    list_display  = ('name', 'start_date', 'end_date')
    search_fields = ('name',)


@admin.register(Relationship)
class RelationshipAdmin(admin.ModelAdmin):
    list_display  = ('source_ioc', 'relation_type', 'target_ioc', 'created_at')
    list_filter   = ('relation_type',)
    readonly_fields = ('id', 'created_at')
