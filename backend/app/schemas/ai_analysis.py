from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class AIAnalysisBase(BaseModel):
    incident_id: int
    summary: str
    risk_level: str
    explanation: Optional[str] = None
    recommendation: Optional[str] = None
    mitre_technique: Optional[str] = None
    model_used: Optional[str] = None


class AIAnalysisCreate(AIAnalysisBase):
    pass


class AIAnalysisUpdate(BaseModel):
    summary: Optional[str] = None
    risk_level: Optional[str] = None
    explanation: Optional[str] = None
    recommendation: Optional[str] = None
    mitre_technique: Optional[str] = None
    model_used: Optional[str] = None


class AIAnalysisResponse(AIAnalysisBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)