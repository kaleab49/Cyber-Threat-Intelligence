from django.test import TestCase
from unittest.mock import patch, MagicMock
from threatintel.scrapers.darkweb_scraper import fetch_darkweb
from threatintel.scrapers.threat_feed_scraper import fetch_threat_feed
from threatintel.scrapers.malwarebazaar_api import fetch_malwarebazaar


class DarkwebScraperTest(TestCase):

    def test_fetch_darkweb_returns_list(self):
        result = fetch_darkweb()
        self.assertIsInstance(result, list)

    def test_fetch_darkweb_returns_ioc_dicts(self):
        result = fetch_darkweb()
        if result:
            self.assertIn("type", result[0])
            self.assertIn("value", result[0])
            self.assertIn("source", result[0])

    def test_fetch_darkweb_source_is_darkweb(self):
        result = fetch_darkweb()
        for item in result:
            self.assertEqual(item["source"], "darkweb")

    def test_fetch_darkweb_returns_ip_type(self):
        result = fetch_darkweb()
        if result:
            self.assertEqual(result[0]["type"], "ip")


class ThreatFeedScraperTest(TestCase):

    @patch("threatintel.scrapers.threat_feed_scraper.feedparser.parse")
    def test_fetch_threat_feed_returns_list(self, mock_parse):
        mock_parse.return_value = MagicMock(entries=[])
        result = fetch_threat_feed()
        self.assertIsInstance(result, list)

    @patch("threatintel.scrapers.threat_feed_scraper.feedparser.parse")
    def test_fetch_threat_feed_handles_entries(self, mock_parse):
        mock_entry = MagicMock()
        mock_entry.get = lambda key, default="": "https://example.com/advisory" if key == "link" else default
        mock_parse.return_value = MagicMock(entries=[mock_entry] * 3)
        result = fetch_threat_feed()
        self.assertIsInstance(result, list)

    @patch("threatintel.scrapers.threat_feed_scraper.feedparser.parse")
    def test_fetch_threat_feed_handles_errors(self, mock_parse):
        mock_parse.side_effect = Exception("Network error")
        result = fetch_threat_feed()
        self.assertEqual(result, [])


class MalwareBazaarScraperTest(TestCase):

    @patch("threatintel.scrapers.malwarebazaar_api.requests.post")
    def test_fetch_malwarebazaar_returns_list(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "query_status": "ok",
                "data": [
                    {
                        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                        "file_name": "malware.exe",
                        "tags": ["ransomware"],
                        "signature": "Emotet",
                        "file_type": "exe",
                        "first_seen": "2024-01-01",
                    }
                ]
            }
        )
        mock_post.return_value.raise_for_status = MagicMock()
        result = fetch_malwarebazaar(limit=1)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    @patch("threatintel.scrapers.malwarebazaar_api.requests.post")
    def test_fetch_malwarebazaar_handles_error_status(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"query_status": "error"}
        )
        result = fetch_malwarebazaar()
        self.assertEqual(result, [])

    @patch("threatintel.scrapers.malwarebazaar_api.requests.post")
    def test_fetch_malwarebazaar_handles_network_error(self, mock_post):
        mock_post.side_effect = Exception("Connection error")
        result = fetch_malwarebazaar()
        self.assertEqual(result, [])

    @patch("threatintel.scrapers.malwarebazaar_api.requests.post")
    def test_fetch_malwarebazaar_ioc_structure(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "query_status": "ok",
                "data": [{
                    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                    "file_name": "test.exe",
                    "tags": ["trojan"],
                    "signature": "Emotet",
                    "file_type": "exe",
                    "first_seen": "2024-01-01",
                }]
            }
        )
        result = fetch_malwarebazaar(limit=1)
        sha256_iocs = [r for r in result if r["type"] == "sha256"]
        self.assertTrue(len(sha256_iocs) > 0)
        self.assertIn("malware", sha256_iocs[0]["tags"])
        self.assertIn("bazaar", sha256_iocs[0]["tags"])