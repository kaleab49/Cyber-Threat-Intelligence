from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from threatintel.ioc.extractor import extract_iocs


@api_view(['POST'])
def extract_iocs_from_text(request):
    text = request.data.get('text', '')
    if not text:
        return Response(
            {"detail": "Request body must include non-empty 'text'."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    return Response({"results": extract_iocs(text)}, status=status.HTTP_200_OK)
