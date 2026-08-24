from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class AIAnalysisBase(BaseModel):
    incident_id: int
    summary: str
    risk_level: str

    explanation: Optional[str] = None
    recommendation: Optional[str] = None

    # =====================================================
    # MITRE ATT&CK
    # =====================================================

    mitre_technique: Optional[str] = None
    mitre_name: Optional[str] = None
    mitre_valid: bool = False

    # =====================================================
    # RAG
    # =====================================================

    rag_sources: Optional[List[str]] = None

    # =====================================================
    # HUMAN REVIEW
    # =====================================================

    human_approval_required: bool = False
    human_approved: Optional[bool] = None
    human_review_status: Optional[str] = None
    human_comment: Optional[str] = None

    # =====================================================
    # RESPONSE
    # =====================================================

    response_status: Optional[str] = None

    # =====================================================
    # LANGGRAPH
    # =====================================================

    thread_id: Optional[str] = None
    agent_trace: Optional[List[str]] = None

    # =====================================================
    # LLM
    # =====================================================

    model_used: Optional[str] = None


class AIAnalysisCreate(AIAnalysisBase):
    pass


class AIAnalysisUpdate(BaseModel):

    summary: Optional[str] = None
    risk_level: Optional[str] = None

    explanation: Optional[str] = None
    recommendation: Optional[str] = None

    # MITRE ATT&CK
    mitre_technique: Optional[str] = None
    mitre_name: Optional[str] = None
    mitre_valid: Optional[bool] = None

    # RAG
    rag_sources: Optional[List[str]] = None

    # Human review
    human_approval_required: Optional[bool] = None
    human_approved: Optional[bool] = None
    human_review_status: Optional[str] = None
    human_comment: Optional[str] = None

    # Response
    response_status: Optional[str] = None

    # LangGraph
    thread_id: Optional[str] = None
    agent_trace: Optional[List[str]] = None

    # LLM
    model_used: Optional[str] = None


class AIAnalysisResponse(AIAnalysisBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )