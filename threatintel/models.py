from django.db import models
import uuid


class IOC(models.Model):
    IOC_TYPES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('url', 'URL'),
        ('hash', 'Hash'),
        ('cve', 'CVE'),
        ('email', 'Email'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    value = models.CharField(max_length=255, db_index=True)
    type = models.CharField(max_length=20, choices=IOC_TYPES)
    source = models.CharField(max_length=100)
    threat_score = models.IntegerField(default=0)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    tags = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"{self.value} ({self.type})"



class Event(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.CharField(max_length=100)
    raw_data = models.TextField()
    parsed_data = models.JSONField(blank=True, null=True)
    timestamp = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Event from {self.source}"

class ThreatFeed(models.Model):
    name = models.CharField(max_length=255)
    url = models.URLField()
    last_fetched = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.name


class Malware(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, blank=True, null=True)
    hash_value = models.CharField(max_length=255, unique=True)
    hash_type = models.CharField(max_length=20, default='sha256')
    first_seen = models.DateTimeField(auto_now_add=True)
    source = models.CharField(max_length=100)
    metadata = models.JSONField(blank=True, null=True)

    def __str__(self):
        return self.hash_value


#class ThreatActor(models.Model):
class ThreatActor(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    aliases = models.JSONField(blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


        
class Campaign(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    start_date = models.DateTimeField(blank=True, null=True)
    end_date = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.name

class Relationship(models.Model):
    RELATION_TYPES = [
        ('uses', 'USES'),
        ('targets', 'TARGETS'),
        ('related', 'RELATED_TO'),
        ('drops', 'DROPS'),
        ('communicates', 'COMMUNICATES_WITH'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source_ioc = models.ForeignKey(IOC, on_delete=models.CASCADE, related_name='source_rel')
    target_ioc = models.ForeignKey(IOC, on_delete=models.CASCADE, related_name='target_rel')
    relation_type = models.CharField(max_length=50, choices=RELATION_TYPES)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.source_ioc} -> {self.target_ioc} ({self.relation_type})"