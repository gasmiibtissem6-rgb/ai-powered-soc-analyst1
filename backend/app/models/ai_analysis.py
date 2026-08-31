from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)

from sqlalchemy.dialects.postgresql import JSONB

from app.database.session import Base


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    incident_id = Column(
        Integer,
        ForeignKey(
            "incidents.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # =====================================================
    # AI INVESTIGATION
    # =====================================================

    summary = Column(
        Text,
        nullable=False,
    )

    risk_level = Column(
        String(20),
        nullable=False,
    )

    explanation = Column(
        Text,
        nullable=True,
    )

    recommendation = Column(
        Text,
        nullable=True,
    )

    # =====================================================
    # MITRE ATT&CK
    # =====================================================

    mitre_technique = Column(
        String(100),
        nullable=True,
    )

    mitre_name = Column(
        String(150),
        nullable=True,
    )

    mitre_valid = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    # =====================================================
    # RAG
    # =====================================================

    rag_sources = Column(
        JSONB,
        nullable=True,
    )

    # =====================================================
    # HUMAN REVIEW
    # =====================================================

    human_approval_required = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    human_approved = Column(
        Boolean,
        nullable=True,
    )

    human_review_status = Column(
        String(50),
        nullable=True,
    )

    human_comment = Column(
        Text,
        nullable=True,
    )

    # =====================================================
    # RESPONSE
    # =====================================================

    response_status = Column(
        String(50),
        nullable=True,
    )

    # =====================================================
    # MULTI-SOURCE CORRELATION
    # =====================================================

    correlation_id = Column(
        String(100),
        nullable=True,
        index=True,
    )

    correlation_confidence = Column(
        String(50),
        nullable=True,
    )

    correlated_incident_count = Column(
        Integer,
        default=0,
        nullable=False,
    )

    correlated_sources = Column(
        JSONB,
        nullable=True,
    )

    # =====================================================
    # LANGGRAPH
    # =====================================================

    thread_id = Column(
        String(100),
        nullable=True,
        index=True,
    )

    agent_trace = Column(
        JSONB,
        nullable=True,
    )

    # =====================================================
    # MODEL
    # =====================================================

    model_used = Column(
        String(100),
        nullable=True,
    )

    # =====================================================
    # TIMESTAMP
    # =====================================================

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )