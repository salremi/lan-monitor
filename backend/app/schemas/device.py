from datetime import datetime
from typing import Any
from pydantic import BaseModel
from app.models.device import DeviceCategory


class DevicePortOut(BaseModel):
    id: int
    device_id: int
    port: int
    protocol: str
    service: str | None
    banner: str | None
    discovered_at: datetime

    model_config = {"from_attributes": True}


class DeviceOut(BaseModel):
    id: int
    ip: str
    mac: str | None
    hostname: str | None
    vendor: str | None
    category: DeviceCategory
    tags: list[str]
    first_seen: datetime
    last_seen: datetime
    suppressed: bool
    suspicion_score: float
    score_reasons: list[dict[str, Any]]

    model_config = {"from_attributes": True}


class DeviceDetail(DeviceOut):
    ports: list[DevicePortOut] = []


class DevicePatch(BaseModel):
    category: DeviceCategory | None = None
    tags: list[str] | None = None
    suppressed: bool | None = None
