from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
import ipaddress
import re
from urllib.parse import urlparse, urlunparse
import uuid



# IOC MANAGER

class IOCManager(models.Manager):

    def upsert_ioc(self, value, ioc_type, source, threat_score=0, tags=None):

        value = IOC.normalize_for_type(ioc_type, value)

        obj, created = self.get_or_create(
            value=value,
            type=ioc_type,
            source=source,
            defaults={
                "threat_score": threat_score,
                "tags": tags or {},
            }
        )

        if not created:
            obj.threat_score = max(obj.threat_score, threat_score)
            obj.last_seen = timezone.now()
            obj.save()

        return obj


# IOC MODEL


class IOC(models.Model):

    IOC_TYPES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('url', 'URL'),
        ('hash', 'Hash'),
        ('md5', 'MD5'),
        ('sha1', 'SHA1'),
        ('sha256', 'SHA256'),
        ('cve', 'CVE'),
        ('email', 'Email'),
    ]

    HASH_TYPES = {"hash", "md5", "sha1", "sha256"}

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    value = models.CharField(max_length=255, db_index=True)
    type = models.CharField(max_length=20, choices=IOC_TYPES)
    source = models.CharField(max_length=100)

    threat_score = models.IntegerField(default=0)

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    tags = models.JSONField(blank=True, null=True)

    objects = IOCManager()

    def __str__(self):
        return f"{self.value} ({self.type})"

    # =========================
    # NORMALIZATION ENGINE
    # =========================
    @staticmethod
    def normalize_for_type(ioc_type, value):
        normalized = str(value).strip()

        if ioc_type == "domain":
            return normalized.rstrip(".").lower()

        if ioc_type == "url":
            parsed = urlparse(normalized)
            scheme = parsed.scheme.lower()
            hostname = (parsed.hostname or "").lower()
            port = parsed.port

            if port and not (
                (scheme == "http" and port == 80) or
                (scheme == "https" and port == 443)
            ):
                netloc = f"{hostname}:{port}"
            else:
                netloc = hostname

            path = parsed.path or "/"

            return urlunparse((scheme, netloc, path, "", parsed.query, "")).strip()

        if ioc_type in IOC.HASH_TYPES:
            return normalized.lower()

        if ioc_type == "cve":
            return normalized.upper()

        if ioc_type == "email":
            return normalized.lower()

        return normalized

    # VALIDATION ENGINE
    def clean(self):

        if not self.value:
            raise ValidationError({"value": "IOC value cannot be empty."})

        self.value = self.normalize_for_type(self.type, self.value)
        self.source = str(self.source).strip().lower()

        value = self.value

        if self.type == "ip":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ValidationError({"value": "Invalid IP address format."})

        elif self.type == "domain":
            domain_regex = re.compile(
                r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
            )
            if not domain_regex.match(value):
                raise ValidationError({"value": "Invalid domain format."})

        elif self.type == "url":
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValidationError({"value": "Invalid URL format."})

        elif self.type in self.HASH_TYPES:
            hash_patterns = {
                "md5": r"(?i)[a-f0-9]{32}",
                "sha1": r"(?i)[a-f0-9]{40}",
                "sha256": r"(?i)[a-f0-9]{64}",
                "hash": r"(?i)[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}",
            }

            if not re.fullmatch(hash_patterns[self.type], value):
                raise ValidationError({"value": f"Invalid {self.type} hash format."})

        elif self.type == "cve":
            if not re.fullmatch(r"(?i)CVE-\d{4}-\d{4,7}", value):
                raise ValidationError({"value": "Invalid CVE format."})

        elif self.type == "email":
            email_regex = re.compile(
                r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
            )
            if not email_regex.match(value):
                raise ValidationError({"value": "Invalid email format."})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)



# EVENT LOGGING

class Event(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.CharField(max_length=100)
    raw_data = models.TextField()
    parsed_data = models.JSONField(blank=True, null=True)
    timestamp = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Event from {self.source}"


# =========================
# THREAT FEEDS
# =========================
class ThreatFeed(models.Model):
    name = models.CharField(max_length=255)
    url = models.URLField()
    last_fetched = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.name



# MALWARE

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


# THREAT ACTOR

class ThreatActor(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    aliases = models.JSONField(blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


# =========================
# CAMPAIGN

class Campaign(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    start_date = models.DateTimeField(blank=True, null=True)
    end_date = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.name


# =========================
# RELATIONSHIP GRAPH
# =========================
class Relationship(models.Model):

    RELATION_TYPES = [
        ('uses', 'USES'),
        ('targets', 'TARGETS'),
        ('related', 'RELATED_TO'),
        ('drops', 'DROPS'),
        ('communicates', 'COMMUNICATES_WITH'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    source_ioc = models.ForeignKey(
        IOC,
        on_delete=models.CASCADE,
        related_name='source_rel'
    )

    target_ioc = models.ForeignKey(
        IOC,
        on_delete=models.CASCADE,
        related_name='target_rel'
    )

    relation_type = models.CharField(max_length=50, choices=RELATION_TYPES)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.source_ioc} -> {self.target_ioc} ({self.relation_type})"