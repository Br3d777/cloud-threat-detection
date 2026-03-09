"""
Dashboard API server.
Serves the dashboard and exposes alert and incident data.
"""

import os
import json
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Cloud Threat Detection Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ALERTS_DIR = Path(os.getenv("ALERTS_DIR", "/tmp/alerts"))
INCIDENTS_DIR = Path(os.getenv("INCIDENTS_DIR", "/tmp/incidents"))


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    html_path = Path(__file__).parent / "index.html"
    return HTMLResponse(html_path.read_text())


@app.get("/api/alerts")
async def get_alerts(limit: int = 100):
    alerts = []
    try:
        for path in sorted(ALERTS_DIR.glob("alert-*.json"), reverse=True)[:limit]:
            try:
                alerts.append(json.loads(path.read_text()))
            except Exception:
                continue
    except Exception:
        pass
    return JSONResponse({"alerts": alerts, "count": len(alerts)})


@app.get("/api/incidents")
async def get_incidents(limit: int = 50):
    incidents = []
    try:
        for path in sorted(INCIDENTS_DIR.glob("incident-*.json"), reverse=True)[:limit]:
            try:
                incidents.append(json.loads(path.read_text()))
            except Exception:
                continue
    except Exception:
        pass
    return JSONResponse({"incidents": incidents, "count": len(incidents)})


@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")