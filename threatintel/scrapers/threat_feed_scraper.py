from threatintel.services.ingestion_service import ingest_event


def fetch_threat_feed():
    data = "Attack from 45.33.12.9 using CVE-2024-1234 and hash abcdef1234567890"

    ingest_event("test_feed", data)

    print("Test data ingested successfully")