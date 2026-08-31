from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class SOCReportBase(BaseModel):
    incident_id: int
    ai_analysis_id: Optional[int] = None
    thread_id: Optional[str] = None

    title: str
    summary: str
    risk_level: str

    # Machine Learning
    ml_status: Optional[str] = None
    ml_prediction: Optional[str] = None
    ml_probabilities: Optional[Dict[str, Optional[float]]] = None
    ml_engine: Optional[str] = None
    ml_is_anomaly: Optional[bool] = None
    ml_anomaly_score: Optional[float] = None
    # MITRE ATT&CK
    mitre_technique: Optional[str] = None
    mitre_name: Optional[str] = None

    # Response
    recommendation: Optional[str] = None
    response_status: Optional[str] = None

    # Human Review
    human_review_status: Optional[str] = None
    human_comment: Optional[str] = None

    # RAG + Agents
    rag_sources: Optional[List[str]] = None
    agent_trace: Optional[List[str]] = None


class SOCReportCreate(SOCReportBase):
    pass


class SOCReportResponse(SOCReportBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )
