from rest_framework.decorators import api_view
from rest_framework.response import Response
from threatintel.models import IOC, Relationship


@api_view(['GET'])
def graph_data(request):

    nodes = []
    edges = []

    # Nodes
    for ioc in IOC.objects.all():
        nodes.append({
            "id": ioc.value,
            "type": ioc.type,
            "score": ioc.threat_score
        })

    # Edges
    for rel in Relationship.objects.all():
        edges.append({
            "source": rel.source_ioc.value,
            "target": rel.target_ioc.value,
            "type": rel.relation_type
        })

    return Response({
        "nodes": nodes,
        "edges": edges
    })