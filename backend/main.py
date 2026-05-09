#backend\main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from database import engine, Base
import uvicorn
import os
from contextlib import asynccontextmanager

# Load environment variables
load_dotenv()

# Create all database tables
Base.metadata.create_all(bind=engine)

# Import routers
from routers import investigate
from routers import feed
from routers import darkweb
from routers import dashboard
from routers import cases
from routers import reports


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Start Tor in a background thread so it doesn't block server startup
    import threading
    from utils.tor_controller import start_tor
    threading.Thread(target=start_tor, daemon=True).start()
    # Start scheduler
    from scheduler import start_scheduler
    start_scheduler()
    yield
    # Stop scheduler
    from scheduler import stop_scheduler
    stop_scheduler()


# Initialise FastAPI app
app = FastAPI(
    title="ThreatHawk API",
    description="Cyber Threat Intelligence & Investigation Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allows Next.js frontend to talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create reports directory if it doesn't exist
os.makedirs(os.path.join(os.path.dirname(__file__), "reports_out"), exist_ok=True)

# Serve generated reports as static files
app.mount("/reports_files", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "reports_out")), name="reports_files")

# Register routers
app.include_router(investigate.router, prefix="/api/investigate", tags=["IOC Investigator"])
app.include_router(feed.router, prefix="/api/feed", tags=["Live Threat Feed"])
app.include_router(darkweb.router, prefix="/api/darkweb", tags=["Dark Web Monitor"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(cases.router, prefix="/api/cases", tags=["Cases"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])

@app.get("/")
def root():
    return {
        "platform": "ThreatHawk",
        "version": "1.0.0",
        "status": "running",
        "engines": ["IOC Investigator", "Live Threat Feed", "Dark Web Monitor"]
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=os.getenv("APP_HOST", "0.0.0.0"),
        port=int(os.getenv("APP_PORT", 8000)),
        reload=True
    )