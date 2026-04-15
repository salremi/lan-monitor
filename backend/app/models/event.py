from datetime import datetime
from sqlalchemy import String, Integer, DateTime, JSON, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    source_ip: Mapped[str] = mapped_column(String, nullable=False)
    dest_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    device: Mapped["Device | None"] = relationship("Device", back_populates="events")

    __table_args__ = (
        Index("ix_network_events_device_id", "device_id"),
        Index("ix_network_events_source_ip", "source_ip"),
    )
