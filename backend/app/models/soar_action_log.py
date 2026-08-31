from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB

from app.database.session import Base


class SOARActionLog(Base):
    __tablename__ = "soar_action_logs"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    action_id = Column(
        Integer,
        ForeignKey(
            "soar_actions.id",
            ondelete="CASCADE",
        ),
        nullable=False,
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

    event_type = Column(
        String(50),
        nullable=False,
    )

    previous_status = Column(
        String(50),
        nullable=True,
    )

    new_status = Column(
        String(50),
        nullable=False,
    )

    details = Column(
        JSONB,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )