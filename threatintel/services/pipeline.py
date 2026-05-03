# services/intelligence/pipeline.py

from threatintel.analyzers.correlation_engine import correlate_event
from threatintel.services.ingestion.ingestion_service import ingest_event
from threatintel.services.scoring.scoring_service import score_iocs


def process_raw_event(source, raw_data):
    event, iocs = ingest_event(source, raw_data)
    relationships = correlate_event(event, iocs)
    scored_iocs = score_iocs(iocs)
    return {
        "event": event,
        "iocs": scored_iocs,
        "relationships": relationships,
    }