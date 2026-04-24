# CyberIntell

## Overview

CyberIntell is an open-source project designed for cyber intelligence analysis and automated data gathering. It enables security professionals, researchers, and organizations to collect, analyze, and visualize data from various cyber sources to identify threats, trends, and insights in real-time.

The project aims to streamline the process of cyber threat intelligence by providing tools for data ingestion, processing, and reporting, making it easier to stay ahead of emerging cyber risks.

## Key Features

- **Automated Data Collection**: Integrates with multiple cyber intelligence feeds, APIs, and sources to gather data automatically.
- **Real-Time Analysis**: Processes incoming data in real-time using advanced algorithms for anomaly detection and pattern recognition.
- **Visualization Tools**: Provides interactive dashboards and charts for visualizing insights, trends, and threat maps.
- **Modular Architecture**: Built with extensibility in mind, allowing users to add custom data sources and analysis modules.
- **Reporting**: Generates detailed reports on cyber threats, including summaries, alerts, and recommendations.

## Architecture

This repo is a **Django + Django REST Framework backend** and a **Vite + React frontend**:

- Backend: `CTI/` (project) + `threatintel/` (app)
- Frontend: `frontend/`

The architecture consists of:
- Data Ingestion Module: Handles collection from sources.
- Analysis Engine: Applies machine learning models for threat detection.
- Visualization Layer: Web-based interface for displaying results.

## Installation

### Prerequisites
- Python 3.10+ (Debian/Ubuntu typically use `python3`)
- Node.js 18+ (for the React frontend)

### Steps
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/cyberintell.git
   ```
2. Navigate to the project directory:
   ```
   cd cyberintell
   ```
3. Install backend dependencies:
   ```
   python3 -m pip install -r requirements.txt
   ```
4. Run migrations:
   ```
   python3 manage.py migrate
   ```

## Usage

### Run the backend API (Django)

Start the API server on port 8000:

```
python3 manage.py runserver 8000
```

API base is at `http://localhost:8000/api/`.

### Ingest data (backend)

You can ingest from URLhaus + CISA KEV using the management command:

```
python3 manage.py run_feed_ingest --urlhaus-limit 100 --kev-limit 100
```

Or via API endpoints:

- `POST /api/feeds/ingest/urlhaus/recent/`
- `POST /api/feeds/ingest/cisa/kev/`
- `POST /api/feeds/ingest/scrape/`

### Run the frontend (React)

In a separate terminal:

```
cd frontend
npm install
npm run dev
```

The Vite dev server proxies `/api` to `http://localhost:8000`, so the UI can call the backend without extra CORS config.

### Command-Line Options
- `--config`: Specify a custom config file.
- `--verbose`: Enable verbose logging.

## API

CyberIntell provides a REST API for programmatic access:
- `GET /api/iocs/`: List stored IOCs (supports `search` and `source` query params)
- `GET /api/events/`: List ingested events
- `GET /api/analytics/dashboard/`: High-level dashboard stats

Refer to the API documentation in `docs/api.md` for details.

## Contributing

We welcome contributions! Please follow these steps:
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-name`.
3. Commit your changes: `git commit -m "Add feature"`.
4. Push to the branch: `git push origin feature-name`.
5. Submit a pull request.

Please ensure your code follows the project's coding standards and includes tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, please open an issue on GitHub or contact the maintainers at [your-email@example.com].

## Disclaimer

CyberIntell is intended for educational and research purposes. Users are responsible for complying with applicable laws and regulations when using this tool.