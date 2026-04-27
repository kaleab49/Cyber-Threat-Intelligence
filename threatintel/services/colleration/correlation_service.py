def correlate_event(event, iocs):

    relationships = []

    for ioc in iocs:
        existing = IOC.objects.filter(value=ioc.value).exclude(id=ioc.id)

        for match in existing:
            rel = Relationship.objects.create(
                source_ioc=ioc,
                target_ioc=match,
                relation_type="duplicate",
                confidence=0.9
            )
            relationships.append(rel)

    return relationships