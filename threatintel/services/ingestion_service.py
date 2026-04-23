from threatintel.models import Event, IOC
from threatintel.ioc.extractor import extract_iocs


def ingest_event(source, raw_data):
    event = Event.objects.create(
        source=source,
        raw_data=raw_data
    )

    iocs = extract_iocs(raw_data)

    for ioc_type, value in iocs:
        IOC.objects.create(
            value=value,
            type=ioc_type,
            event=event
        )

    return event