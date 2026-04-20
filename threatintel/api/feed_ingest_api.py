from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from threatintel.services.feed_ingest import enrich_cves_from_circl, ingest_urlhaus_recent


@api_view(["POST"])
def ingest_urlhaus_recent_api(request):
    limit = request.data.get("limit", 100)
    try:
        result = ingest_urlhaus_recent(limit=limit)
    except Exception as exc:
        return Response(
            {"detail": "URLhaus ingestion failed.", "error": str(exc)},
            status=status.HTTP_502_BAD_GATEWAY,
        )
    return Response(result, status=status.HTTP_200_OK)


@api_view(["POST"])
def enrich_cves_circl_api(request):
    limit = request.data.get("limit", 50)
    try:
        result = enrich_cves_from_circl(limit=limit)
    except Exception as exc:
        return Response(
            {"detail": "CIRCL CVE enrichment failed.", "error": str(exc)},
            status=status.HTTP_502_BAD_GATEWAY,
        )
    return Response(result, status=status.HTTP_200_OK)
