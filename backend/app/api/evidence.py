from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.event import NetworkEvent

router = APIRouter(tags=["evidence"])


@router.get("/evidence/{device_id}")
def get_evidence(
    device_id: int,
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    event_type: str | None = Query(None),
    since: datetime | None = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(NetworkEvent).filter(NetworkEvent.device_id == device_id)
    if event_type:
        q = q.filter(NetworkEvent.event_type == event_type)
    if since:
        q = q.filter(NetworkEvent.ts >= since)
    events = q.order_by(NetworkEvent.ts.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id": e.id,
            "source_ip": e.source_ip,
            "dest_ip": e.dest_ip,
            "event_type": e.event_type,
            "source": e.source,
            "ts": e.ts.isoformat(),
            "raw": e.raw,
        }
        for e in events
    ]
