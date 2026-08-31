from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.models.incident import Incident


class CorrelationService:
    """
    Correlate SOC incidents coming from different sources
    such as Wazuh and Suricata.

    The oldest incident in a correlation group is considered
    the primary incident and is responsible for running the
    complete SOC workflow.
    """

    # =====================================================
    # GENERATE CORRELATION ID
    # =====================================================

    @staticmethod
    def generate_correlation_id() -> str:
        """
        Generate a unique correlation identifier.
        """

        return f"SOC-{uuid4().hex}"

    # =====================================================
    # FIND RELATED INCIDENT
    # =====================================================

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

        Correlation rules:

        1. Preferred:
           exact same source/destination pair.

        2. Also accepted:
           reverse source/destination pair.

        3. Hostname is used only as a fallback when
           network IP information is incomplete.
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

        # -------------------------------------------------
        # Strong network correlation
        # -------------------------------------------------

        if source_ip and destination_ip:

            same_direction = and_(
                Incident.source_ip == source_ip,
                Incident.destination_ip == destination_ip,
            )

            reverse_direction = and_(
                Incident.source_ip == destination_ip,
                Incident.destination_ip == source_ip,
            )

            query = query.filter(
                or_(
                    same_direction,
                    reverse_direction,
                )
            )

        # -------------------------------------------------
        # Source IP only
        # -------------------------------------------------

        elif source_ip:

            query = query.filter(
                Incident.source_ip == source_ip
            )

        # -------------------------------------------------
        # Destination IP only
        # -------------------------------------------------

        elif destination_ip:

            query = query.filter(
                Incident.destination_ip == destination_ip
            )

        # -------------------------------------------------
        # Hostname fallback
        # -------------------------------------------------

        elif hostname:

            query = query.filter(
                Incident.hostname == hostname
            )

        else:
            return None

        return (
            query.order_by(
                Incident.created_at.desc(),
                Incident.id.desc(),
            )
            .first()
        )

    # =====================================================
    # CORRELATE INCIDENT
    # =====================================================

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

        related = CorrelationService.find_related_incident(
            db=db,
            source=incident.source,
            source_ip=incident.source_ip,
            destination_ip=incident.destination_ip,
            hostname=incident.hostname,
            window_minutes=window_minutes,
        )

        # -------------------------------------------------
        # Related incident found
        # -------------------------------------------------

        if related:

            correlation_id = (
                related.correlation_id
                or CorrelationService.generate_correlation_id()
            )

            if not related.correlation_id:
                related.correlation_id = correlation_id

            incident.correlation_id = correlation_id

            try:
                db.commit()
                db.refresh(related)
                db.refresh(incident)

            except Exception:
                db.rollback()
                raise

            return correlation_id

        # -------------------------------------------------
        # No related incident
        # -------------------------------------------------

        correlation_id = (
            CorrelationService.generate_correlation_id()
        )

        incident.correlation_id = correlation_id

        try:
            db.commit()
            db.refresh(incident)

        except Exception:
            db.rollback()
            raise

        return correlation_id

    # =====================================================
    # GET PRIMARY INCIDENT
    # =====================================================

    @staticmethod
    def get_primary_incident(
        db: Session,
        correlation_id: str,
    ) -> Optional[Incident]:
        """
        Return the oldest incident in a correlation group.
        """

        if not correlation_id:
            return None

        return (
            db.query(Incident)
            .filter(
                Incident.correlation_id == correlation_id
            )
            .order_by(
                Incident.created_at.asc(),
                Incident.id.asc(),
            )
            .first()
        )

    # =====================================================
    # CHECK IF INCIDENT IS PRIMARY
    # =====================================================

    @staticmethod
    def is_primary_incident(
        db: Session,
        incident: Incident,
    ) -> bool:
        """
        Return True only if this incident is the primary
        incident of its correlation group.
        """

        if not incident.correlation_id:
            return True

        primary = CorrelationService.get_primary_incident(
            db=db,
            correlation_id=incident.correlation_id,
        )

        if not primary:
            return True

        return primary.id == incident.id

    # =====================================================
    # SHOULD RUN SOC WORKFLOW
    # =====================================================

    @staticmethod
    def should_run_workflow(
        db: Session,
        incident: Incident,
    ) -> bool:
        """
        Only the primary incident in a correlation group
        runs the complete SOC workflow.
        """

        return CorrelationService.is_primary_incident(
            db=db,
            incident=incident,
        )

    # =====================================================
    # MARK AS CORRELATED
    # =====================================================

    @staticmethod
    def mark_as_correlated(
        db: Session,
        incident: Incident,
    ) -> None:
        """
        Mark a secondary incident as correlated.
        """

        incident.workflow_status = "correlated"
        incident.workflow_error = None

        try:
            db.commit()
            db.refresh(incident)

        except Exception:
            db.rollback()
            raise