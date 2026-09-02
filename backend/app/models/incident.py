from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    severity: Mapped[str] = mapped_column(
        String(50),
        default="medium",
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="open",
        nullable=False,
    )

    # --------------------------------------------------
    # SOC analyst disposition
    # --------------------------------------------------

    disposition: Mapped[str] = mapped_column(
        String(50),
        default="unknown",
        nullable=False,
    )

    source: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    # Machine / endpoint concerné
    hostname: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # IP source observée dans l'incident
    source_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )

    # IP destination éventuelle
    destination_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )

    # Utilisateur concerné
    username: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    assigned_to: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # --------------------------------------------------
    # SOC workflow state
    # --------------------------------------------------

    workflow_status: Mapped[str] = mapped_column(
        String(50),
        default="pending",
        nullable=False,
    )

    workflow_error: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # --------------------------------------------------
    # Correlation
    # --------------------------------------------------

    correlation_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )

    # --------------------------------------------------
    # SOC operational metrics
    # --------------------------------------------------

    event_timestamp: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )