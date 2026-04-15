"""HTTP client for LAN Monitor backend API."""
import os
import httpx

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")
_TIMEOUT = 10.0


def _get(path: str, params: dict | None = None) -> dict | list:
    with httpx.Client(base_url=BACKEND_URL, timeout=_TIMEOUT) as client:
        r = client.get(path, params=params or {})
        r.raise_for_status()
        return r.json()


def _patch(path: str, data: dict) -> dict:
    with httpx.Client(base_url=BACKEND_URL, timeout=_TIMEOUT) as client:
        r = client.patch(path, json=data)
        r.raise_for_status()
        return r.json()


def _put(path: str, data: dict) -> dict:
    with httpx.Client(base_url=BACKEND_URL, timeout=_TIMEOUT) as client:
        r = client.put(path, json=data)
        r.raise_for_status()
        return r.json()


def _post(path: str, data: dict | None = None) -> dict:
    with httpx.Client(base_url=BACKEND_URL, timeout=_TIMEOUT) as client:
        r = client.post(path, json=data or {})
        r.raise_for_status()
        return r.json()


# ---- Devices ----

def get_devices() -> list[dict]:
    return _get("/api/devices")  # type: ignore


def get_device(device_id: int) -> dict:
    return _get(f"/api/devices/{device_id}")  # type: ignore


def update_device(device_id: int, **kwargs) -> dict:
    return _patch(f"/api/devices/{device_id}", kwargs)


# ---- Alerts ----

def get_alerts(severity: str | None = None, ack: bool | None = None, device_id: int | None = None) -> list[dict]:
    params = {}
    if severity:
        params["severity"] = severity
    if ack is not None:
        params["ack"] = str(ack).lower()
    if device_id is not None:
        params["device_id"] = device_id
    return _get("/api/alerts", params)  # type: ignore


def acknowledge_alert(alert_id: int) -> dict:
    return _patch(f"/api/alerts/{alert_id}/acknowledge", {})


# ---- Evidence ----

def get_evidence(device_id: int, limit: int = 100, event_type: str | None = None) -> list[dict]:
    params: dict = {"limit": limit}
    if event_type:
        params["event_type"] = event_type
    return _get(f"/api/evidence/{device_id}", params)  # type: ignore


# ---- Config ----

def get_config() -> list[dict]:
    return _get("/api/config")  # type: ignore


def update_config(values: dict) -> dict:
    return _put("/api/config", {"values": values})


# ---- Stats ----

def get_stats() -> dict:
    return _get("/api/stats")  # type: ignore


# ---- Ingest / Scan ----

def trigger_nmap_scan() -> dict:
    return _post("/api/scan/nmap")


def get_scan_status() -> dict:
    return _get("/api/scan/status")  # type: ignore


def trigger_ingest(source: str) -> dict:
    return _post(f"/api/ingest/{source}")


# ---- LLM ----

def analyze_device_llm(device_id: int) -> dict:
    return _post(f"/api/llm/analyze/{device_id}")


def get_llm_health() -> dict:
    return _get("/api/llm/health")  # type: ignore
