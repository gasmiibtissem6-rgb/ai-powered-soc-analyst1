from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(
        Integer,
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

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        default="medium",
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="new",
        nullable=False,
    )

    attack_type: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    mitre_technique: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    source_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )

    destination_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )