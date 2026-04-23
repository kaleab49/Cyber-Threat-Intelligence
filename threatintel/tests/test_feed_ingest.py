from unittest.mock import Mock, patch

from django.test import TestCase

from threatintel.models import IOC
from threatintel.services.feed_ingest import (
    _extract_iocs_from_text,
    ingest_cisa_kev,
    ingest_urlhaus_recent,
)
from threatintel.services.scoring import get_source_score


class FeedIngestTests(TestCase):
    def test_extract_iocs_from_text(self):
        text = "Visit http://evil.test and report CVE-2024-12345 from 1.2.3.4 hash a" + ("b" * 63)
        extracted = _extract_iocs_from_text(text)
        extracted_values = {value for _, value in extracted}

        self.assertIn("http://evil.test", extracted_values)
        self.assertIn("CVE-2024-12345", extracted_values)
        self.assertIn("1.2.3.4", extracted_values)

    @patch("threatintel.services.feed_ingest.requests.get")
    def test_ingest_cisa_kev_creates_cve_iocs(self, mocked_get):
        mocked_response = Mock()
        mocked_response.json.return_value = {
            "vulnerabilities": [
                {"cveID": "CVE-2023-1111"},
                {"cveID": "CVE-2023-2222"},
            ]
        }
        mocked_response.raise_for_status.return_value = None
        mocked_get.return_value = mocked_response

        result = ingest_cisa_kev(limit=10)

        self.assertEqual(result["ioc_processed"], 2)
        self.assertEqual(IOC.objects.filter(type="cve", source="cisa-kev").count(), 2)
        self.assertTrue(
            IOC.objects.filter(
                type="cve", source="cisa-kev", threat_score=get_source_score("cisa-kev")
            ).exists()
        )

    @patch("threatintel.services.feed_ingest.requests.post")
    def test_ingest_urlhaus_uses_source_score(self, mocked_post):
        mocked_response = Mock()
        mocked_response.json.return_value = {
            "urls": [{"url": "http://bad.example/path", "date_added": "2026-01-01 00:00:00 UTC"}]
        }
        mocked_response.raise_for_status.return_value = None
        mocked_post.return_value = mocked_response

        result = ingest_urlhaus_recent(limit=1)

        self.assertEqual(result["ioc_processed"], 1)
        self.assertTrue(
            IOC.objects.filter(
                value="http://bad.example/path",
                type="url",
                source="urlhaus",
                threat_score=get_source_score("urlhaus"),
            ).exists()
        )
