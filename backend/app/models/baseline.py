from datetime import datetime
from sqlalchemy import String, Integer, Float, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class Baseline(Base):
    __tablename__ = "baselines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    metric: Mapped[str] = mapped_column(String, nullable=False)
    mean: Mapped[float] = mapped_column(Float, nullable=False)
    stddev: Mapped[float] = mapped_column(Float, nullable=False)
    window_hours: Mapped[int] = mapped_column(Integer, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    device: Mapped["Device"] = relationship("Device", back_populates="baselines")

    __table_args__ = (
        Index("ix_baselines_device_id_metric", "device_id", "metric"),
    )
