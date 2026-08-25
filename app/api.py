from fastapi import FastAPI, HTTPException

from app.storage.database import (
    initialize_database,
    get_alerts,
)

app = FastAPI(
    title="SentinelSOC API",
    version="1.0.0",
    description="Security monitoring and alert API",
)


@app.on_event("startup")
def startup():
    initialize_database()


@app.get("/")
def root():
    return {
        "name": "SentinelSOC",
        "status": "online",
        "version": "1.0.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }


@app.get("/alerts")
def alerts():
    rows = get_alerts()

    return {
        "count": len(rows),
        "alerts": [dict(row) for row in rows],
    }


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    rows = get_alerts()

    for row in rows:
        if row["id"] == alert_id:
            return dict(row)

    raise HTTPException(
        status_code=404,
        detail="Alert not found",
    )