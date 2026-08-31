from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.incident import Incident


class CorrelationService:
    """
    Correlate SOC incidents coming from different sources
    such as Wazuh and Suricata.
    """

    @staticmethod
    def generate_correlation_id() -> str:
        """
        Generate a unique correlation identifier.
        """

        return f"SOC-{uuid4().hex}"

    @staticmethod
    def find_related_incident(
        db: Session,
        source: str,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        hostname: Optional[str] = None,
        window_minutes: int = 5,
    ) -> Optional[Incident]:
        """
        Look for a recent incident from another source
        that may belong to the same security activity.
        """

        created_after = datetime.utcnow() - timedelta(
            minutes=window_minutes
        )

        query = (
            db.query(Incident)
            .filter(
                Incident.created_at >= created_after,
                Incident.source != source,
            )
        )

        conditions = []

        if source_ip:
            conditions.append(
                Incident.source_ip == source_ip
            )

            conditions.append(
                Incident.destination_ip == source_ip
            )

        if destination_ip:
            conditions.append(
                Incident.source_ip == destination_ip
            )

            conditions.append(
                Incident.destination_ip == destination_ip
            )

        if hostname:
            conditions.append(
                Incident.hostname == hostname
            )

        if not conditions:
            return None

        from sqlalchemy import or_

        query = query.filter(
            or_(*conditions)
        )

        return (
            query.order_by(
                Incident.created_at.desc()
            )
            .first()
        )

    @staticmethod
    def correlate_incident(
        db: Session,
        incident: Incident,
        window_minutes: int = 5,
    ) -> str:
        """
        Assign a correlation_id to an incident.

        If a related recent incident already exists,
        both incidents receive the same correlation_id.

        Otherwise a new correlation_id is generated.
        """

        if incident.correlation_id:
            return incident.correlation_id

        related = (
            CorrelationService.find_related_incident(
                db=db,
                source=incident.source,
                source_ip=incident.source_ip,
                destination_ip=incident.destination_ip,
                hostname=incident.hostname,
                window_minutes=window_minutes,
            )
        )

        if related:

            correlation_id = (
                related.correlation_id
                or CorrelationService.generate_correlation_id()
            )

            if not related.correlation_id:
                related.correlation_id = correlation_id

            incident.correlation_id = correlation_id

            db.commit()

            db.refresh(related)
            db.refresh(incident)

            return correlation_id

        correlation_id = (
            CorrelationService.generate_correlation_id()
        )

        incident.correlation_id = correlation_id

        db.commit()
        db.refresh(incident)

        return correlation_id
