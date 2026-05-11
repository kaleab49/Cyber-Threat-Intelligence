from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from threatintel.ioc.extractor import extract_iocs


@api_view(["POST"])
def extract_iocs_from_text(request):

    text = request.data.get("text", "").strip()

    if not text:
        return Response(
            {"error": "Field 'text' is required."},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        extracted = extract_iocs(text)
    except Exception as e:
        return Response(
            {"error": f"Extraction failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    results = [{"type": ioc_type, "value": value} for ioc_type, value in extracted]
    return Response({"count": len(results), "results": results})