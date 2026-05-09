from django.test import TestCase
from django.core.exceptions import ValidationError
from threatintel.models import IOC, Event, ThreatFeed, Malware, ThreatActor, Campaign, Relationship


class IOCModelTest(TestCase):

    def test_create_valid_ip(self):
        ioc = IOC.objects.create(value="8.8.8.8", type="ip", source="test")
        self.assertEqual(ioc.value, "8.8.8.8")
        self.assertEqual(ioc.type, "ip")

    def test_create_valid_domain(self):
        ioc = IOC.objects.create(value="example.com", type="domain", source="test")
        self.assertEqual(ioc.value, "example.com")

    def test_create_valid_cve(self):
        ioc = IOC.objects.create(value="CVE-2024-1234", type="cve", source="test")
        self.assertEqual(ioc.value, "CVE-2024-1234")

    def test_create_valid_md5(self):
        ioc = IOC.objects.create(value="d41d8cd98f00b204e9800998ecf8427e", type="md5", source="test")
        self.assertEqual(ioc.value, "d41d8cd98f00b204e9800998ecf8427e")

    def test_create_valid_sha256(self):
        ioc = IOC.objects.create(
            value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            type="sha256",
            source="test"
        )
        self.assertIsNotNone(ioc.id)

    def test_invalid_ip_raises_validation_error(self):
        ioc = IOC(value="999.999.999.999", type="ip", source="test")
        with self.assertRaises(ValidationError):
            ioc.full_clean()

    def test_invalid_domain_raises_validation_error(self):
        ioc = IOC(value="not_a_domain", type="domain", source="test")
        with self.assertRaises(ValidationError):
            ioc.full_clean()

    def test_invalid_cve_raises_validation_error(self):
        ioc = IOC(value="NOTACVE", type="cve", source="test")
        with self.assertRaises(ValidationError):
            ioc.full_clean()

    def test_domain_normalized_to_lowercase(self):
        ioc = IOC.objects.create(value="EXAMPLE.COM", type="domain", source="test")
        self.assertEqual(ioc.value, "example.com")

    def test_cve_normalized_to_uppercase(self):
        ioc = IOC.objects.create(value="cve-2024-1234", type="cve", source="test")
        self.assertEqual(ioc.value, "CVE-2024-1234")

    def test_unique_constraint_value_type(self):
        IOC.objects.create(value="8.8.8.8", type="ip", source="source1")
        with self.assertRaises(Exception):
            IOC.objects.create(value="8.8.8.8", type="ip", source="source2")

    def test_upsert_ioc_creates_new(self):
        ioc = IOC.objects.upsert_ioc("1.1.1.1", "ip", "test", threat_score=50)
        self.assertEqual(ioc.value, "1.1.1.1")
        self.assertEqual(ioc.threat_score, 50)

    def test_upsert_ioc_updates_score(self):
        IOC.objects.upsert_ioc("1.1.1.1", "ip", "test", threat_score=30)
        ioc = IOC.objects.upsert_ioc("1.1.1.1", "ip", "test", threat_score=80)
        self.assertEqual(ioc.threat_score, 80)

    def test_str_representation(self):
        ioc = IOC.objects.create(value="8.8.8.8", type="ip", source="test")
        self.assertIn("8.8.8.8", str(ioc))


class EventModelTest(TestCase):

    def test_create_event(self):
        event = Event.objects.create(source="test", raw_data="test data")
        self.assertEqual(event.source, "test")
        self.assertEqual(event.raw_data, "test data")

    def test_event_with_parsed_data(self):
        event = Event.objects.create(
            source="cisa-kev",
            raw_data="CVE-2024-1234",
            parsed_data={"cveID": "CVE-2024-1234"}
        )
        self.assertEqual(event.parsed_data["cveID"], "CVE-2024-1234")

    def test_str_representation(self):
        event = Event.objects.create(source="test", raw_data="data")
        self.assertIn("test", str(event))


class RelationshipModelTest(TestCase):

    def test_create_relationship(self):
        src = IOC.objects.create(value="8.8.8.8", type="ip", source="test")
        tgt = IOC.objects.create(value="evil.com", type="domain", source="test")
        rel = Relationship.objects.create(
            source_ioc=src,
            target_ioc=tgt,
            relation_type="communicates"
        )
        self.assertEqual(rel.source_ioc, src)
        self.assertEqual(rel.target_ioc, tgt)