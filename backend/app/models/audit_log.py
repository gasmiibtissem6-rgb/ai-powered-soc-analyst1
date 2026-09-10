from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB

from app.database.session import Base
from app.utils.datetime_utils import utc_now


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    event_type = Column(
        String(100),
        nullable=False,
        index=True,
    )

    outcome = Column(
        String(50),
        nullable=False,
    )

    actor_subject = Column(
        String(255),
        nullable=True,
        index=True,
    )

    actor_source = Column(
        String(50),
        nullable=True,
    )

    actor_email = Column(
        String(255),
        nullable=True,
    )

    resource_type = Column(
        String(100),
        nullable=True,
    )

    resource_id = Column(
        String(255),
        nullable=True,
    )

    request_method = Column(
        String(20),
        nullable=True,
    )

    request_path = Column(
        String(500),
        nullable=True,
    )

    client_ip = Column(
        String(100),
        nullable=True,
    )

    details = Column(
        JSONB,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=utc_now,
        nullable=False,
        index=True,
    )
