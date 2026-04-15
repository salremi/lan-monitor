from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.device import Device
from app.models.event import NetworkEvent
from app.schemas.device import DeviceOut, DeviceDetail, DevicePatch

router = APIRouter(tags=["devices"])


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db)):
    return db.query(Device).order_by(Device.suspicion_score.desc()).all()


@router.get("/devices/{device_id}", response_model=DeviceDetail)
def get_device(device_id: int, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.patch("/devices/{device_id}", response_model=DeviceOut)
def update_device(device_id: int, patch: DevicePatch, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if patch.category is not None:
        device.category = patch.category
    if patch.tags is not None:
        device.tags = patch.tags
    if patch.suppressed is not None:
        device.suppressed = patch.suppressed
    db.commit()
    db.refresh(device)
    return device
