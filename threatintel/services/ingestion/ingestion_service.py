from django.db import transaction

from threatintel.ioc.classifier import classify_ioc
from threatintel.ioc.extractor import extract_iocs
from threatintel.models import Event, IOC


def ingest_event(source, raw_data):
    ioc_objects = []
    with transaction.atomic():
        event = Event.objects.create(
            source=source,
            raw_data=raw_data,
        )
        normalized_source = str(source).strip().lower()

        for ioc_type, value in extract_iocs(raw_data):
            score = classify_ioc(ioc_type, value)
            normalized_value = IOC.normalize_for_type(ioc_type, value)
            obj, created = IOC.objects.get_or_create(
                value=normalized_value,
                type=ioc_type,
                defaults={
                    "source": normalized_source,
                    "threat_score": score,
                },
            )
            if not created:
                if score > obj.threat_score:
                    obj.threat_score = score
                if normalized_source and obj.source != normalized_source:
                    obj.source = normalized_source
                obj.save(update_fields=["threat_score", "source", "last_seen"])
            ioc_objects.append(obj)

    return event, ioc_objects