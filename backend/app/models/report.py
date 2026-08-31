from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB

from app.database.session import Base


class SOCReport(Base):
    __tablename__ = "soc_reports"

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

    ai_analysis_id = Column(
        Integer,
        ForeignKey(
            "ai_analyses.id",
            ondelete="CASCADE",
        ),
        nullable=True,
        index=True,
    )

    thread_id = Column(
        String(100),
        nullable=True,
        index=True,
    )

    # =====================================================
    # REPORT
    # =====================================================

    title = Column(
        String(255),
        nullable=False,
    )

    summary = Column(
        Text,
        nullable=False,
    )

    risk_level = Column(
        String(20),
        nullable=False,
    )

    # =====================================================
    # MACHINE LEARNING
    # =====================================================

    ml_status = Column(
        String(50),
        nullable=True,
    )

    ml_prediction = Column(
        String(50),
        nullable=True,
    )

    ml_probabilities = Column(
        JSONB,
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

    # =====================================================
    # RESPONSE
    # =====================================================

    recommendation = Column(
        Text,
        nullable=True,
    )

    response_status = Column(
        String(50),
        nullable=True,
    )

    # =====================================================
    # HUMAN REVIEW
    # =====================================================

    human_review_status = Column(
        String(50),
        nullable=True,
    )

    human_comment = Column(
        Text,
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
    # RAG + AGENTS
    # =====================================================

    rag_sources = Column(
        JSONB,
        nullable=True,
    )

    agent_trace = Column(
        JSONB,
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