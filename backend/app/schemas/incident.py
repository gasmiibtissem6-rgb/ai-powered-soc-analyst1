from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None

    severity: str = "medium"
    status: str = "open"

    source: Optional[str] = None

    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None

    assigned_to: Optional[str] = None

    correlation_id: Optional[str] = None

    event_timestamp: Optional[datetime] = None


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None

    severity: Optional[str] = None
    status: Optional[str] = None

    source: Optional[str] = None

    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None

    assigned_to: Optional[str] = None

    correlation_id: Optional[str] = None
    event_timestamp: Optional[datetime] = None


class IncidentResponse(IncidentBase):
    id: int

    detected_at: datetime
    resolved_at: Optional[datetime] = None
    created_at: datetime

    workflow_status: str
    workflow_error: Optional[str] = None

    model_config = ConfigDict(
        from_attributes=True
    )