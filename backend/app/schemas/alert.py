from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class AlertCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    source: str


class AlertUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None
    status: Optional[str] = None


class AlertResponse(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    severity: str
    source: str
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)