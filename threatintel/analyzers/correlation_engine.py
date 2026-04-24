# threatintel/analyzers/correlation_engine.py

from threatintel.models import Relationship


def correlate_event(event, iocs):
    """
    Create relationships between IOCs that appear in the same event.
    """

    created_links = []

    iocs = list(iocs)

    for i in range(len(iocs)):
        for j in range(i + 1, len(iocs)):

            ioc_a = iocs[i]
            ioc_b = iocs[j]

            if ioc_a.id == ioc_b.id:
                continue

            rel, created = Relationship.objects.get_or_create(
                source_ioc=ioc_a,
                target_ioc=ioc_b,
                relation_type="related"
            )

            created_links.append(rel)

    return created_links