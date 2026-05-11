
# ⬡ CTI Platform — Cyber Threat Intelligence

A full-stack, production-grade Cyber Threat Intelligence (CTI) platform built with **Django + Django REST Framework** on the backend and **React + TypeScript + Vite** on the frontend. The platform aggregates, enriches, and visualizes threat intelligence from multiple sources — giving security teams a single place to track IOCs, CVEs, and emerging adversary activity.

---

## 🚀 Features

- **Multi-source Feed Ingestion** — URLhaus, CISA KEV, ThreatFox, Threat Feeds (CERT/CISA RSS), Darkweb Scanner
- **IOC Tracking** — IPs, domains, URLs, hashes (MD5/SHA1/SHA256), CVEs, emails with automatic normalization and deduplication
- **VirusTotal Enrichment** — Enrich existing IOCs with VT scan results and detection scores
- **MalwareBazaar Integration** — Fetch recent malware samples and hashes
- **IOC Extraction** — Extract IOCs from raw text, threat reports, or logs instantly
- **Relationship Graph** — Visualize connections between IOCs, campaigns, and threat actors
- **Automated Scheduling** — Celery (Redis by default, configurable broker) for background task execution
- **JWT Authentication** — Secure login/register with token-based auth
- **Analytics Dashboard** — Real-time stats, threat trends, top threats, and source breakdown
- **Event Timeline** — Full audit log of all ingestion and enrichment events
- **REST API** — Full DRF-powered API with filtering, pagination, and search
- **60 Tests** — Comprehensive test suite covering models, APIs, extractors, and scrapers

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, Django 5.2, Django REST Framework |
| Auth | SimpleJWT (JWT tokens) |
| Task Queue | Celery 5.6, Redis (default) / RabbitMQ (optional) |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Frontend | React 18, TypeScript, Vite |
| Styling | Custom CSS (dark theme) |
| Scrapers | Requests, BeautifulSoup, Feedparser |
| Enrichment | VirusTotal API v3, CIRCL CVE API |
| Testing | Django TestCase, unittest.mock |

---

## 📁 Project Structure

```
Cyber-Threat-Intelligence/
├── CTI/                          # Django project settings
│   ├── settings.py
│   ├── urls.py
│   ├── celery.py
│   └── wsgi.py / asgi.py
├── threatintel/                  # Main Django app
│   ├── api/                      # API endpoint handlers
│   │   ├── auth_api.py           # JWT auth (login, register, refresh)
│   │   ├── ioc_api.py            # IOC extraction endpoint
│   │   ├── feed_ingest_api.py    # Feed ingestion endpoints
│   │   ├── analytics_api.py      # Dashboard statistics
│   │   ├── graph_api.py          # Relationship graph data
│   │   └── scraper_api.py        # Scraper trigger endpoints
│   ├── analyzers/                # VT lookup, correlation, DNS, Whois
│   ├── ioc/                      # IOC extractor and classifier
│   ├── scrapers/                 # Feed scrapers
│   │   ├── virustotal_scraper.py
│   │   ├── malwarebazaar_api.py
│   │   ├── threat_feed_scraper.py
│   │   ├── pastebin_scraper.py   # ThreatFox integration
│   │   ├── darkweb_scraper.py
│   │   └── feed_registry.py
│   ├── services/                 # Business logic
│   │   ├── ingestion/            # Feed ingestion services
│   │   ├── enrichment/           # IOC enrichment
│   │   ├── scoring/              # Threat scoring
│   │   └── correlation/          # IOC correlation
│   ├── tests/                    # Test suite (60 tests)
│   ├── models.py                 # IOC, Event, ThreatFeed, Malware, ThreatActor, Campaign, Relationship
│   ├── serializer.py
│   ├── view.py                   # ViewSets
│   ├── tasks.py                  # Celery tasks
│   └── urls.py
├── frontend/                     # React + TypeScript frontend
│   ├── src/
│   │   ├── App.tsx               # Main dashboard
│   │   ├── Landing.tsx           # Landing page
│   │   ├── Login.tsx             # Auth modal
│   │   ├── api.ts                # API client
│   │   ├── App.css               # Dashboard styles
│   │   └── landing.css           # Landing page styles
│   ├── vite.config.ts
│   └── package.json
├── .env                          # Environment variables (not in git)
├── .gitignore
├── requirements.txt
└── manage.py
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.11+
- Node.js 20+
- Redis (default broker) or RabbitMQ

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/Cyber-Threat-Intelligence.git
cd Cyber-Threat-Intelligence
```

### 2. Set up Python environment
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment variables
```bash
cp .env.example .env
```

Edit `.env` with your values:
```env
SECRET_KEY=your-django-secret-key
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1
VIRUSTOTAL_API_KEY=your-virustotal-api-key
THREATFOX_API_KEY=your-threatfox-api-key
TWITTER_BEARER_TOKEN=your-twitter-bearer-token
CELERY_BROKER_URL=redis://localhost:6379/0
THROTTLE_ANON=60/hour
THROTTLE_USER=600/hour
```

### 4. Run database migrations
```bash
python manage.py migrate
```

### 5. Create a superuser
```bash
python manage.py createsuperuser
```

### 6. Set up the frontend
```bash
cd frontend
npm install
cd ..
```

---

## 🚦 Running the Platform

You need **4 terminals** running simultaneously:

**Terminal 1 — Django backend:**
```bash
source .venv/bin/activate
python manage.py runserver
```

**Terminal 2 — Celery worker:**
```bash
source .venv/bin/activate
celery -A CTI worker -l info
```

**Terminal 3 — Celery beat (scheduler):**
```bash
source .venv/bin/activate
celery -A CTI beat -l info
```

**Terminal 4 — React frontend:**
```bash
cd frontend
npm run dev
```

Then open **http://localhost:5173** in your browser.

---

## 🔌 API Endpoints

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register/` | Create a new account |
| POST | `/api/auth/login/` | Login and get JWT tokens |
| POST | `/api/auth/refresh/` | Refresh access token |
| POST | `/api/auth/logout/` | Logout and blacklist token |
| GET  | `/api/auth/me/` | Get current user info |

### IOCs
| Method | Endpoint | Description |
|---|---|---|
| GET/POST | `/api/iocs/` | List / Create IOCs |
| GET/PUT/DELETE | `/api/iocs/<id>/` | Retrieve / Update / Delete IOC |

### Events
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/events/` | List all events |

### Feed Ingestion
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/feeds/ingest/urlhaus/recent/` | Ingest URLhaus feed |
| POST | `/api/feeds/ingest/cisa/kev/` | Ingest CISA KEV feed |
| POST | `/api/feeds/ingest/scrape/` | Scrape IOCs from a URL |
| POST | `/api/feeds/enrich/circl/cves/` | Enrich CVEs with CIRCL |

### Scrapers
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/scrapers/` | List all scrapers |
| POST | `/api/scrapers/run-all/` | Run all scrapers |
| POST | `/api/scrapers/threat-feed/` | Run threat feed scraper |
| POST | `/api/scrapers/virustotal/` | Run VirusTotal enrichment |
| POST | `/api/scrapers/malwarebazaar/` | Run MalwareBazaar scraper |
| POST | `/api/scrapers/darkweb/` | Run darkweb scanner |
| POST | `/api/scrapers/pastebin/` | Run ThreatFox scraper |

### Analytics
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/analytics/dashboard/` | Dashboard statistics |
| POST | `/api/ioc/extract/` | Extract IOCs from text |
| GET | `/api/graph/` | Relationship graph data |

---

## 🧪 Running Tests

```bash
python manage.py test threatintel --verbosity=2
```

**Test coverage:**
- `test_models.py` — IOC validation, normalization, upsert logic
- `test_api.py` — Auth, IOC, Event, and Analytics API endpoints
- `test_extractions.py` — IOC extraction from raw text
- `test_scraper.py` — Scraper unit tests with mocked HTTP calls
- `test_feed_ingest.py` — Feed ingestion service tests

---

## 🔒 Security

- JWT authentication with token blacklisting on logout
- Environment-driven secrets and host configuration (`SECRET_KEY`, `ALLOWED_HOSTS`, `DEBUG`)
- Input validation and normalization on all IOC types
- API throttling enabled for auth and ingestion endpoints
- SSRF protections on URL scrape ingestion (private/loopback targets blocked)
- `.env` excluded from version control via `.gitignore`

---

## 📊 Data Sources

| Source | Type | Update Frequency |
|---|---|---|
| CISA KEV | CVEs | Daily |
| URLhaus | Malicious URLs | Hourly |
| ThreatFox | Multi-type IOCs | Hourly |
| CERT/CISA RSS Feeds | URLs | Hourly |
| Darkweb Scanner | IPs | Hourly |
| VirusTotal | Enrichment | On demand |
| MalwareBazaar | Malware hashes | Hourly |

---

## 🗺 Roadmap

- [ ] PostgreSQL support for production
- [ ] STIX/TAXII export format
- [ ] Email alerts for high-risk IOCs
- [ ] User roles and permissions
- [ ] Docker deployment
- [ ] MITRE ATT&CK mapping

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

Built by **Nathan and kaleab** as a production-grade CTI platform for security teams.
