from typing import Any
from pydantic import BaseModel


class ConfigEntry(BaseModel):
    key: str
    value: Any
    description: str

    model_config = {"from_attributes": True}


class ConfigUpdate(BaseModel):
    values: dict[str, Any]
