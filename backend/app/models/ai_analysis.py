from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from app.database.session import Base


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id = Column(Integer, primary_key=True, index=True)

    incident_id = Column(
        Integer,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    summary = Column(Text, nullable=False)

    risk_level = Column(
        String(20),
        nullable=False,
    )

    explanation = Column(Text, nullable=True)

    recommendation = Column(Text, nullable=True)

    mitre_technique = Column(
        String(100),
        nullable=True,
    )

    model_used = Column(
        String(100),
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )