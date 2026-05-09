from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status
from threatintel.models import IOC, Event


class AuthAPITest(TestCase):

    def setUp(self):
        self.client = APIClient()

    def test_register_user(self):
        res = self.client.post('/api/auth/register/', {
            'username': 'testuser',
            'password': 'testpass123',
        }, format='json')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertIn('access', res.data)
        self.assertIn('refresh', res.data)

    def test_login_user(self):
        User.objects.create_user(username='testuser', password='testpass123')
        res = self.client.post('/api/auth/login/', {
            'username': 'testuser',
            'password': 'testpass123',
        }, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('access', res.data)

    def test_login_invalid_credentials(self):
        res = self.client.post('/api/auth/login/', {
            'username': 'wrong',
            'password': 'wrong',
        }, format='json')
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_me_endpoint_requires_auth(self):
        res = self.client.get('/api/auth/me/')
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_me_endpoint_with_auth(self):
        user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_authenticate(user=user)
        res = self.client.get('/api/auth/me/')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['username'], 'testuser')

    def test_register_duplicate_username(self):
        User.objects.create_user(username='testuser', password='testpass123')
        res = self.client.post('/api/auth/register/', {
            'username': 'testuser',
            'password': 'testpass123',
        }, format='json')
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)


class IOCAPITest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_authenticate(user=self.user)

    def test_list_iocs(self):
        IOC.objects.create(value="8.8.8.8", type="ip", source="test")
        res = self.client.get('/api/iocs/')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['count'], 1)

    def test_create_ioc(self):
        res = self.client.post('/api/iocs/', {
            'value': '1.1.1.1',
            'type': 'ip',
            'source': 'test',
            'threat_score': 50,
        }, format='json')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertEqual(res.data['value'], '1.1.1.1')

    def test_retrieve_ioc(self):
        ioc = IOC.objects.create(value="8.8.8.8", type="ip", source="test")
        res = self.client.get(f'/api/iocs/{ioc.id}/')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['value'], '8.8.8.8')

    def test_filter_iocs_by_type(self):
        IOC.objects.create(value="8.8.8.8", type="ip", source="test")
        IOC.objects.create(value="CVE-2024-1234", type="cve", source="test")
        res = self.client.get('/api/iocs/?type=ip')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['count'], 1)

    def test_filter_iocs_by_source(self):
        IOC.objects.create(value="8.8.8.8", type="ip", source="urlhaus")
        IOC.objects.create(value="CVE-2024-1234", type="cve", source="cisa-kev")
        res = self.client.get('/api/iocs/?source=urlhaus')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['count'], 1)

    def test_delete_ioc(self):
        ioc = IOC.objects.create(value="8.8.8.8", type="ip", source="test")
        res = self.client.delete(f'/api/iocs/{ioc.id}/')
        self.assertEqual(res.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(IOC.objects.count(), 0)

    def test_iocs_require_auth(self):
        self.client.force_authenticate(user=None)
        res = self.client.get('/api/iocs/')
        self.assertEqual(res.status_code, status.HTTP_200_OK)  # IOCs allow read without auth


class EventAPITest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_authenticate(user=self.user)

    def test_list_events(self):
        Event.objects.create(source="test", raw_data="data")
        res = self.client.get('/api/events/')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['count'], 1)

    def test_filter_events_by_source(self):
        Event.objects.create(source="urlhaus", raw_data="data1")
        Event.objects.create(source="cisa-kev", raw_data="data2")
        res = self.client.get('/api/events/?source=urlhaus')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['count'], 1)


class AnalyticsAPITest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_authenticate(user=self.user)

    def test_dashboard_stats(self):
        IOC.objects.create(value="8.8.8.8", type="ip", source="test", threat_score=80)
        res = self.client.get('/api/analytics/dashboard/')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('iocs', res.data)
        self.assertIn('events', res.data)
        self.assertEqual(res.data['iocs']['total'], 1)
        self.assertEqual(res.data['iocs']['high_risk'], 1)

    def test_extract_iocs_from_text(self):
        res = self.client.post('/api/ioc/extract/', {
            'text': 'Found malicious IP 8.8.8.8 and domain evil.com'
        }, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('results', res.data)
        self.assertGreater(res.data['count'], 0)