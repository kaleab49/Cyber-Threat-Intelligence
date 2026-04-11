from threatintel.models import IOC, Relationship

def correlate_iocs():
    iocs = IOC.objects.all()

    for ioc in iocs:
        # Find same-value IOCs from different sources
        related_iocs = IOC.objects.filter(value=ioc.value).exclude(id=ioc.id)

        for target in related_iocs:
            Relationship.objects.get_or_create(
                source_ioc=ioc,
                target_ioc=target,
                relation_type="related"
            )