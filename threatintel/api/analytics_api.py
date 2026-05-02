from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.db.models import Count, Avg, Max
from django.utils import timezone
from datetime import timedelta

from threatintel.models import IOC, Event, Malware, ThreatActor, Campaign


@api_view(["GET"])
def dashboard_stats(request):
    """
    GET /api/analytics/dashboard/
    Returns aggregated stats for the CTI dashboard.
    """
    now        = timezone.now()
    last_24h   = now - timedelta(hours=24)
    last_7d    = now - timedelta(days=7)
    last_30d   = now - timedelta(days=30)

    # ── IOC Stats ──────────────────────────────────────────
    total_iocs      = IOC.objects.count()
    iocs_24h        = IOC.objects.filter(first_seen__gte=last_24h).count()
    iocs_7d         = IOC.objects.filter(first_seen__gte=last_7d).count()
    high_risk_iocs  = IOC.objects.filter(threat_score__gte=75).count()

    iocs_by_type    = list(
        IOC.objects.values("type")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    iocs_by_source  = list(
        IOC.objects.values("source")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )

    avg_threat_score = IOC.objects.aggregate(avg=Avg("threat_score"))["avg"] or 0
    max_threat_score = IOC.objects.aggregate(max=Max("threat_score"))["max"] or 0

    # ── Event Stats ────────────────────────────────────────
    total_events    = Event.objects.count()
    events_24h      = Event.objects.filter(timestamp__gte=last_24h).count()
    events_7d       = Event.objects.filter(timestamp__gte=last_7d).count()

    events_by_source = list(
        Event.objects.values("source")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )

    # ── Daily IOC trend (last 30 days) ─────────────────────
    daily_iocs = list(
        IOC.objects.filter(first_seen__gte=last_30d)
        .extra(select={"day": "date(first_seen)"})
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )

    # ── Top threats ────────────────────────────────────────
    top_threats = list(
        IOC.objects.order_by("-threat_score", "-times_seen")
        .values("id", "value", "type", "source", "threat_score", "tags")[:10]
    )

    # ── Other model counts ─────────────────────────────────
    total_malware      = Malware.objects.count()
    total_actors       = ThreatActor.objects.count()
    total_campaigns    = Campaign.objects.count()

    return Response({
        "generated_at": now,
        "iocs": {
            "total":            total_iocs,
            "last_24h":         iocs_24h,
            "last_7d":          iocs_7d,
            "high_risk":        high_risk_iocs,
            "avg_threat_score": round(avg_threat_score, 2),
            "max_threat_score": max_threat_score,
            "by_type":          iocs_by_type,
            "by_source":        iocs_by_source,
            "daily_trend":      daily_iocs,
            "top_threats":      top_threats,
        },
        "events": {
            "total":      total_events,
            "last_24h":   events_24h,
            "last_7d":    events_7d,
            "by_source":  events_by_source,
        },
        "threat_actors": total_actors,
        "malware":        total_malware,
        "campaigns":      total_campaigns,
    })