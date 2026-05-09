from django.test import TestCase
from threatintel.ioc.extractor import extract_iocs


class IOCExtractionTest(TestCase):

    def test_extract_ip(self):
        results = extract_iocs("Malicious IP: 192.168.1.1 detected")
        types = [r[0] for r in results]
        values = [r[1] for r in results]
        self.assertIn("ip", types)
        self.assertIn("192.168.1.1", values)

    def test_extract_domain(self):
        results = extract_iocs("Connected to evil.com via DNS")
        values = [r[1] for r in results]
        self.assertIn("evil.com", values)

    def test_extract_url(self):
        results = extract_iocs("Downloaded from http://malware.com/payload.exe")
        types = [r[0] for r in results]
        self.assertIn("url", types)

    def test_extract_md5(self):
        results = extract_iocs("Hash: d41d8cd98f00b204e9800998ecf8427e")
        types = [r[0] for r in results]
        self.assertIn("md5", types)

    def test_extract_sha256(self):
        results = extract_iocs(
            "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        types = [r[0] for r in results]
        self.assertIn("sha256", types)

    def test_extract_cve(self):
        results = extract_iocs("Exploiting CVE-2024-1234 in the wild")
        types = [r[0] for r in results]
        values = [r[1] for r in results]
        self.assertIn("cve", types)
        self.assertIn("CVE-2024-1234", values)

    def test_extract_multiple_iocs(self):
        text = "IP 8.8.8.8 used domain evil.com and hash d41d8cd98f00b204e9800998ecf8427e"
        results = extract_iocs(text)
        self.assertGreaterEqual(len(results), 3)

    def test_extract_empty_text(self):
        results = extract_iocs("")
        self.assertEqual(results, [])

    def test_extract_no_iocs(self):
        results = extract_iocs("This text has no threat indicators at all.")
        self.assertEqual(len(results), 0)

    def test_extract_https_url(self):
        results = extract_iocs("Visit https://evil.com/malware for payload")
        types = [r[0] for r in results]
        self.assertIn("url", types)