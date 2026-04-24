from threatintel.models import Event, IOC
from threatintel.ioc.extractor import extract_iocs
from threatintel.ioc.classifier import classify_ioc


def ingest_event(source, raw_data):
    event = Event.objects.create(
        source=source,
        raw_data=raw_data
    )

    iocs = extract_iocs(raw_data)

    for ioc_type, value in iocs:

        print("DEBUG:", ioc_type, value)  # IMPORTANT DEBUG LINE

        score = classify_ioc(ioc_type, value)

        IOC.objects.create(
            value=value,
            type=ioc_type,   # MUST BE: ip, cve, hash, etc
            threat_score=score,
            source=source
        )

    return event