"""
dashboard/api.py
────────────────
FastAPI server exposing:
    GET  /alerts          — recent alerts (JSON)
    GET  /stats           — live metrics
    GET  /blocked         — current block list
    POST /unblock/{ip}    — manual unblock
    WS   /ws/alerts       — live WebSocket feed for the dashboard

Run with:
    uvicorn dashboard.api:app --host 0.0.0.0 --port 8000
"""

import asyncio
import json
import time
import logging
from collections import deque
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from response.auto_block import blocked_ips, manual_unblock

logger = logging.getLogger(__name__)

app = FastAPI(title="SHIELD IDS API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── shared state (written by pipeline, read by API) ───────────────────────────

_recent_alerts: deque = deque(maxlen=200)   # Alert.to_dict() entries
_stats: dict[str, Any] = {
    "flows_total":    0,
    "alerts_total":   0,
    "flows_per_sec":  0,
    "start_time":     time.time(),
    "last_update":    time.time(),
}
_ws_clients: list[WebSocket] = []


# ── called by the main pipeline ───────────────────────────────────────────────

def ingest_alert(alert_dict: dict):
    """Thread-safe: push a new alert into the API layer."""
    _recent_alerts.appendleft(alert_dict)
    _stats["alerts_total"] += 1
    _stats["last_update"] = time.time()

def increment_flow_counter():
    _stats["flows_total"] += 1


async def broadcast_alert(alert_dict: dict):
    """Push a new alert to all connected WebSocket clients."""
    dead = []
    payload = json.dumps({"type": "alert", "data": alert_dict})
    for ws in _ws_clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)


# ── HTTP endpoints ────────────────────────────────────────────────────────────

@app.get("/alerts")
async def get_alerts(limit: int = 50, severity: str = ""):
    alerts = list(_recent_alerts)
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    return {"alerts": alerts[:limit], "total": _stats["alerts_total"]}


@app.get("/stats")
async def get_stats():
    uptime = int(time.time() - _stats["start_time"])
    return {
        **_stats,
        "uptime_seconds": uptime,
        "blocked_count":  len(blocked_ips()),
    }


@app.get("/blocked")
async def get_blocked():
    return {"blocked": blocked_ips()}


@app.post("/unblock/{ip}")
async def unblock(ip: str):
    ok = manual_unblock(ip)
    return {"success": ok, "ip": ip}


# ── WebSocket feed ────────────────────────────────────────────────────────────

@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.append(websocket)
    logger.info("Dashboard client connected (%d total)", len(_ws_clients))
    try:
        # send recent alerts on connect
        for alert in list(_recent_alerts)[:20]:
            await websocket.send_text(
                json.dumps({"type": "history", "data": alert})
            )
        # keep alive
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        _ws_clients.remove(websocket)
        logger.info("Dashboard client disconnected")


# ── health check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "time": time.time()}
