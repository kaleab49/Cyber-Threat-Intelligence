from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from threatintel.models import Relationship, IOC


@api_view(["GET"])
def graph_data(request):
    """
    GET /api/graph/
    Query params:
      - ioc_id   : filter relationships by a specific IOC (source or target)
      - limit    : max number of relationships to return (default 100)
    Returns nodes and edges for relationship graph visualization.
    """
    ioc_id = request.query_params.get("ioc_id")
    limit  = request.query_params.get("limit", 100)

    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        return Response(
            {"error": "Invalid limit value."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # ── Build queryset ─────────────────────────────────────
    qs = Relationship.objects.select_related("source_ioc", "target_ioc")

    if ioc_id:
        qs = qs.filter(source_ioc__id=ioc_id) | qs.filter(target_ioc__id=ioc_id)

    relationships = qs[:limit]

    # ── Build nodes + edges ────────────────────────────────
    nodes = {}
    edges = []

    for rel in relationships:
        src = rel.source_ioc
        tgt = rel.target_ioc

        # Add source node
        if str(src.id) not in nodes:
            nodes[str(src.id)] = {
                "id":           str(src.id),
                "label":        src.value,
                "type":         src.type,
                "threat_score": src.threat_score,
                "source":       src.source,
            }

        # Add target node
        if str(tgt.id) not in nodes:
            nodes[str(tgt.id)] = {
                "id":           str(tgt.id),
                "label":        tgt.value,
                "type":         tgt.type,
                "threat_score": tgt.threat_score,
                "source":       tgt.source,
            }

        # Add edge
        edges.append({
            "id":            str(rel.id),
            "source":        str(src.id),
            "target":        str(tgt.id),
            "relation_type": rel.relation_type,
            "created_at":    rel.created_at,
        })

    return Response({
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes":      list(nodes.values()),
        "edges":      edges,
    })