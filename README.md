# ThreatHawk 🦅

ThreatHawk is a comprehensive Cyber Threat Intelligence & Investigation Platform. It provides tools for investigating Indicators of Compromise (IOCs), monitoring live threat feeds, analyzing dark web activity, managing investigation cases, and generating intelligence reports.

## Architecture

ThreatHawk is built with a modern, decoupled architecture:

- **Backend**: Python-based REST API powered by **FastAPI**. It handles threat data ingestion, database operations (SQLAlchemy/SQLite), scheduling, and integration with Tor for dark web monitoring.
- **Frontend**: A reactive, component-driven user interface built with **Next.js** (React 19), styled with **Material UI (MUI)**, and featuring interactive data visualizations using **D3.js**, **Recharts**, and **React Simple Maps**.

## Key Features

- 🔍 **IOC Investigator**: Deep-dive analysis of IP addresses, domains, URLs, and file hashes.
- 🌐 **Live Threat Feed**: Real-time streaming of global cyber threat indicators and events.
- 🧅 **Dark Web Monitor**: Automated scanning and monitoring of hidden services via integrated Tor routing.
- 📁 **Case Management**: Organize investigations, link IOCs, and track threat actor attribution.
- 📊 **Interactive Dashboard**: High-level overview of threat landscapes with dynamic charts and geographic maps.
- 📑 **Reporting Engine**: Generate comprehensive, exportable intelligence reports from investigations.

## Getting Started

### Prerequisites

- **Python 3.8+**
- **Node.js 18+** (with npm)
- **Tor** (for Dark Web Monitor features)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd threathawk
   ```

2. **Set up the Backend:**
   ```bash
   cd backend
   python -m venv venv
   # Activate virtual environment
   # Windows:
   venv\Scripts\activate
   # Linux/Mac:
   # source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Set up the Frontend:**
   ```bash
   cd ../frontend
   npm install
   ```

### Running the Application

ThreatHawk includes a convenient startup script that launches both the backend and frontend simultaneously.

1. From the project root directory, run:
   ```bash
   python start.py
   ```

2. The script will automatically:
   - Start the FastAPI backend on `http://localhost:8000`
   - Start the Next.js development server on `http://localhost:3000`
   - Open your default web browser to the ThreatHawk dashboard

Press `Ctrl+C` in the terminal to stop all services.

## Project Structure

```text
threathawk/
├── backend/            # FastAPI Python backend
│   ├── routers/        # API endpoints (cases, dashboard, darkweb, etc.)
│   ├── engines/        # Core processing logic
│   ├── integrations/   # Third-party API connectors
│   ├── scrapers/       # Data collection scripts
│   ├── utils/          # Helpers (including Tor controller)
│   ├── models.py       # SQLAlchemy database models
│   ├── database.py     # DB connection setup
│   └── main.py         # FastAPI application entry point
├── frontend/           # Next.js React frontend
│   ├── src/            # Components, pages, hooks, etc.
│   ├── public/         # Static assets
│   └── package.json    # Node dependencies and scripts
└── start.py            # Unified startup script
```

## Environment Variables

Check the `.env` file in the `backend/` directory for configuration options, including API keys for external intelligence sources and database settings.

## Author

Kaivalya Parihar
