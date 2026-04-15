import enum
from datetime import datetime
from sqlalchemy import String, Integer, Float, Boolean, DateTime, JSON, Enum, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class DeviceCategory(str, enum.Enum):
    PC = "PC"
    phone = "phone"
    TV = "TV"
    IoT = "IoT"
    NAS = "NAS"
    router = "router"
    unknown = "unknown"


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip: Mapped[str] = mapped_column(String, nullable=False, index=True)
    mac: Mapped[str | None] = mapped_column(String, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    category: Mapped[DeviceCategory] = mapped_column(
        Enum(DeviceCategory), default=DeviceCategory.unknown, nullable=False
    )
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    suspicion_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    score_reasons: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    ports: Mapped[list["DevicePort"]] = relationship("DevicePort", back_populates="device", cascade="all, delete-orphan")
    events: Mapped[list["NetworkEvent"]] = relationship("NetworkEvent", back_populates="device")
    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="device", cascade="all, delete-orphan")
    baselines: Mapped[list["Baseline"]] = relationship("Baseline", back_populates="device", cascade="all, delete-orphan")


class DevicePort(Base):
    __tablename__ = "device_ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String, nullable=False)
    service: Mapped[str | None] = mapped_column(String, nullable=True)
    banner: Mapped[str | None] = mapped_column(String, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    device: Mapped["Device"] = relationship("Device", back_populates="ports")

    __table_args__ = (
        Index("ix_device_ports_device_id", "device_id"),
    )
