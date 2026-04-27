from django.db import transaction
from threatintel.models import Event, IOC
from threatintel.ioc.extractor import extract_iocs
from threatintel.ioc.classifier import classify_ioc
from threatintel.analyzers.correlation_engine import correlate_event
from threatintel.models import IOC

def ingest_event(source, raw_data):
    with transaction.atomic():

    
        event = Event.objects.create(
            source=source,
            raw_data=raw_data
        )

    
        iocs = extract_iocs(raw_data)

        for ioc_type, value in iocs:

            score = classify_ioc(ioc_type, value)

        
            obj, created = IOC.objects.get_or_create(
                value=value,
                type=ioc_type,
                source=source,
                defaults={
                    "threat_score": score
                }
            )

            if not created:
                obj.last_seen = obj.last_seen  # auto updated anyway
                obj.threat_score = max(obj.threat_score, score)
                obj.save()

            print("IOC:", value, ioc_type, "CREATED:", created)

        return event