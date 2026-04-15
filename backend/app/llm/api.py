"""API endpoints for LLM-based device analysis."""
import logging
import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app.llm.analyzer import analyze_device

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/llm", tags=["llm"])


@router.post("/analyze/{device_id}")
def analyze_device_endpoint(device_id: int, db: Session = Depends(get_db)):
    """Run LLM analysis on a device and return plain-English assessment."""
    if not settings.llm_enabled:
        raise HTTPException(status_code=503, detail="LLM analysis is disabled. Set LLM_ENABLED=true in .env.")

    from app.models.device import Device
    from app.schemas.device import DeviceDetail

    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Build a plain dict from the ORM object (reuse existing schema)
    device_data = {
        "ip": device.ip,
        "hostname": device.hostname,
        "mac": device.mac,
        "vendor": device.vendor,
        "category": device.category.value if hasattr(device.category, "value") else device.category,
        "suspicion_score": device.suspicion_score,
        "score_reasons": device.score_reasons or [],
        "ports": [
            {
                "port": p.port,
                "protocol": p.protocol,
                "service": p.service,
                "banner": p.banner,
            }
            for p in (device.ports or [])
        ],
    }

    result = analyze_device(
        device=device_data,
        provider=settings.llm_provider,
        base_url=settings.llm_base_url,
        model=settings.llm_model,
    )

    if not result["ok"]:
        raise HTTPException(status_code=502, detail=result["error"])

    return result


@router.get("/health")
def llm_health():
    """Check whether the configured LLM provider is reachable."""
    if not settings.llm_enabled:
        return {"status": "disabled", "provider": settings.llm_provider}

    try:
        if settings.llm_provider == "lmstudio":
            url = settings.llm_base_url.rstrip("/") + "/v1/models"
        else:
            url = settings.llm_base_url.rstrip("/") + "/api/tags"

        with httpx.Client(timeout=5.0) as client:
            r = client.get(url)
            r.raise_for_status()
        return {"status": "ok", "provider": settings.llm_provider, "base_url": settings.llm_base_url, "model": settings.llm_model}
    except Exception as e:
        return {"status": "unreachable", "provider": settings.llm_provider, "error": str(e)}
