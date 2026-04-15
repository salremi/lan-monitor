from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import Alert, AlertSeverity
from app.schemas.alert import AlertOut

router = APIRouter(tags=["alerts"])


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    severity: AlertSeverity | None = Query(None),
    ack: bool | None = Query(None),
    device_id: int | None = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(Alert)
    if severity is not None:
        q = q.filter(Alert.severity == severity)
    if ack is not None:
        q = q.filter(Alert.acknowledged == ack)
    if device_id is not None:
        q = q.filter(Alert.device_id == device_id)
    return q.order_by(Alert.created_at.desc()).all()


@router.patch("/alerts/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = True
    alert.ack_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert
