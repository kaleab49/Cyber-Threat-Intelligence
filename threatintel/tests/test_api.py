from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from threatintel.view import IOCViewSet
from threatintel.models import IOC


class IOCViewSetFilterTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        now = timezone.now()

        IOC.objects.create(
            value="1.2.3.4",
            type="ip",
            source="feed1",
            threat_score=30,
            tags=["botnet"],
        )
        IOC.objects.create(
            value="example.com",
            type="domain",
            source="feed2",
            threat_score=80,
            tags=["malware"],
        )
        IOC.objects.create(
            value="32f7c7e5d6e46c6c89f9cf5f67b3ce66a5b7c1d7f6a8e2b3c4d5f60718293abc",
            type="sha256",
            source="feed1",
            threat_score=45,
            tags=["phishing", "malware"],
        )

    def _get_queryset(self, params):
        request = self.factory.get("/api/iocs/", params)
        view = IOCViewSet()
        view.request = Request(request)
        return view.get_queryset()

    def test_filter_by_type_and_threat_score_range(self):
        queryset = self._get_queryset({
            'type': 'domain',
            'min_threat_score': '50',
            'max_threat_score': '100',
        })

        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.first().value, 'example.com')

    def test_search_can_match_value_or_source(self):
        queryset = self._get_queryset({'search': 'feed1'})

        self.assertEqual(queryset.count(), 2)
        self.assertTrue(all(ioc.source == 'feed1' for ioc in queryset))

    def test_filter_by_tag_list_and_ordering(self):
        queryset = self._get_queryset({
            'tags': 'malware,phishing',
            'ordering': '-threat_score',
        })

        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.first().type, 'sha256')
        self.assertEqual(queryset.first().threat_score, 45)
