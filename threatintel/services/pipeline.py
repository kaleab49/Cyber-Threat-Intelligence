# services/intelligence/pipeline.py

from threatintel.services.ingestion.ingestion_service import ingest_event
from services.enrichment_service import enrich_iocs
from threatintel.services.colleration.correlation_service import correlate_event
from threatintel.services.scoring.scoring_service import calculate_scores


def process_raw_event(source, raw_data):

    
    event, iocs = ingest_event(source, raw_data)

    
    enriched_iocs = enrich_iocs(iocs)

   
    relationships = correlate_event(event, enriched_iocs)

    
    scored_iocs = calculate_scores(enriched_iocs)

    return {
        "event": event,
        "iocs": scored_iocs,
        "relationships": relationships
    }