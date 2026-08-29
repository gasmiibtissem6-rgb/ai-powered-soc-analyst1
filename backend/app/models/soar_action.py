from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB

from app.database.session import Base


class SOARAction(Base):
    __tablename__ = "soar_actions"

    id = Column(Integer, primary_key=True, index=True)

    incident_id = Column(
        Integer,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    action_type = Column(String(50), nullable=False)

    target = Column(String(255), nullable=False)

    status = Column(String(50), default="pending", nullable=False)

    requires_approval = Column(Boolean, default=True, nullable=False)

    approved = Column(Boolean, nullable=True)

    result = Column(JSONB, nullable=True)

    executed_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)