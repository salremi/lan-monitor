from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.app_config import AppConfig
from app.schemas.config import ConfigEntry, ConfigUpdate

router = APIRouter(tags=["config"])


@router.get("/config", response_model=list[ConfigEntry])
def get_config(db: Session = Depends(get_db)):
    return db.query(AppConfig).all()


@router.put("/config")
def update_config(update: ConfigUpdate, db: Session = Depends(get_db)):
    updated = []
    for key, value in update.values.items():
        entry = db.query(AppConfig).filter(AppConfig.key == key).first()
        if entry:
            entry.value = value
            updated.append(key)
    db.commit()
    return {"updated": updated}
