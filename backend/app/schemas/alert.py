from datetime import datetime
from typing import Any
from pydantic import BaseModel
from app.models.alert import AlertSeverity


class AlertOut(BaseModel):
    id: int
    device_id: int
    severity: AlertSeverity
    title: str
    reason: str
    evidence: list[Any]
    created_at: datetime
    acknowledged: bool
    ack_at: datetime | None

    model_config = {"from_attributes": True}
