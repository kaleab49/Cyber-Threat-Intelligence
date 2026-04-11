from rest_framework.decorators import api_view
from rest_framework.response import Response
from threatintel.models import IOC, Event
from django.db.models import Count

@api_view(['GET'])
def dashboard_stats(request):
    total_iocs = IOC.objects.count()
    total_events = Event.objects.count()

    top_iocs = (
        IOC.objects.values('value')
        .annotate(count=Count('value'))
        .order_by('-count')[:10]
    )

    return Response({
        "total_iocs": total_iocs,
        "total_events": total_events,
        "top_iocs": list(top_iocs)
    })