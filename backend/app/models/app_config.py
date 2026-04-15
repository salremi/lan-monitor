from sqlalchemy import String, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class AppConfig(Base):
    __tablename__ = "app_config"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[dict | list | str | int | float | bool | None] = mapped_column(JSON, nullable=True)
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
