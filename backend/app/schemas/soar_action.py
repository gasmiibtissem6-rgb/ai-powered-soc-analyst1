from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class SOARActionCreate(BaseModel):
    incident_id: int
    action_type: str
    target: str
    requires_approval: bool = True


class SOARActionResponse(BaseModel):
    id: int
    incident_id: int
    action_type: str
    target: str
    status: str
    requires_approval: bool
    approved: Optional[bool] = None
    result: Optional[Any] = None
    executed_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)