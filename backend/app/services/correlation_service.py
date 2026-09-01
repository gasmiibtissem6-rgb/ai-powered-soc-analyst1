from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.models.incident import Incident


class CorrelationService:
    """
    Correlate SOC incidents coming from different sources.

    Correlation uses:
    - time window
    - source/destination IP pair
    - activity category
    - source diversity

    The oldest incident in a correlation group is the
    primary incident and runs the complete SOC workflow.
    """

    # =====================================================
    # GENERATE CORRELATION ID
    # =====================================================

    @staticmethod
    def generate_correlation_id() -> str:
        return f"SOC-{uuid4().hex}"

    # =====================================================
    # CLASSIFY INCIDENT ACTIVITY
    # =====================================================

    @staticmethod
    def classify_activity(
        title: Optional[str],
        description: Optional[str] = None,
    ) -> str:
        """
        Infer a broad activity category from incident text.

        This avoids correlating unrelated alerts that only
        happen to share the same IP pair.
        """

        text = (
            f"{title or ''} "
            f"{description or ''}"
        ).lower()

        # -------------------------------------------------
        # Network scan / discovery
        # -------------------------------------------------

        scan_keywords = (
            "nmap",
            "port scan",
            "network scan",
            "tcp syn port scan",
            "network service discovery",
            "reconnaissance",
        )

        if any(
            keyword in text
            for keyword in scan_keywords
        ):
            return "network_scan"

        # -------------------------------------------------
        # Authentication
        # -------------------------------------------------

        auth_keywords = (
            "authentication",
            "login",
            "failed password",
            "invalid user",
            "brute force",
            "sshd",
            "pam",
        )

        if any(
            keyword in text
            for keyword in auth_keywords
        ):
            return "authentication"

        # -------------------------------------------------
        # HTTP / web
        # -------------------------------------------------

        http_keywords = (
            "http",
            "cleartext",
            "client body",
            "web",
            "request",
        )

        if (
            any(
                keyword in text
                for keyword in http_keywords
            )
            or " uri " in f" {text} "
        ):
            return "http"

        # -------------------------------------------------
        # Malware
        # -------------------------------------------------

        malware_keywords = (
            "malware",
            "trojan",
            "ransomware",
            "virus",
            "backdoor",
        )

        if any(
            keyword in text
            for keyword in malware_keywords
        ):
            return "malware"

        return "generic"

    # =====================================================
    # ACTIVITY COMPATIBILITY
    # =====================================================

    @staticmethod
    def activities_are_compatible(
        first: Incident,
        second: Incident,
    ) -> bool:
        """
        Return True when two incidents are similar enough
        to belong to the same security activity.
        """

        first_category = (
            CorrelationService.classify_activity(
                first.title,
                first.description,
            )
        )

        second_category = (
            CorrelationService.classify_activity(
                second.title,
                second.description,
            )
        )

        # Exact activity category is preferred
        if first_category == second_category:
            return True

        # Generic incidents are not strong enough to merge
        # with a clearly classified security activity.
        if (
            first_category == "generic"
            or second_category == "generic"
        ):
            return False

        return False

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
        title: Optional[str] = None,
        description: Optional[str] = None,
        window_minutes: int = 5,
    ) -> Optional[Incident]:
        """
        Look for a recent incident from another source that
        belongs to the same security activity.
        """

        created_after = (
            datetime.utcnow()
            - timedelta(
                minutes=window_minutes
            )
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
        # Partial network correlation
        # -------------------------------------------------

        elif source_ip:

            query = query.filter(
                Incident.source_ip == source_ip
            )

        elif destination_ip:

            query = query.filter(
                Incident.destination_ip == destination_ip
            )

        elif hostname:

            query = query.filter(
                Incident.hostname == hostname
            )

        else:
            return None

        candidates = (
            query.order_by(
                Incident.created_at.desc(),
                Incident.id.desc(),
            )
            .limit(20)
            .all()
        )

        # -------------------------------------------------
        # Activity-aware filtering
        # -------------------------------------------------

        current_activity = (
            CorrelationService.classify_activity(
                title,
                description,
            )
        )

        for candidate in candidates:

            candidate_activity = (
                CorrelationService.classify_activity(
                    candidate.title,
                    candidate.description,
                )
            )

            if (
                current_activity
                == candidate_activity
            ):
                return candidate

        return None

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

        Related incidents must match both:
        - network identity
        - activity category
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
                title=incident.title,
                description=incident.description,
                window_minutes=window_minutes,
            )
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
                related.correlation_id = (
                    correlation_id
                )

            incident.correlation_id = (
                correlation_id
            )

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

        incident.correlation_id = (
            correlation_id
        )

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

        if not correlation_id:
            return None

        return (
            db.query(Incident)
            .filter(
                Incident.correlation_id
                == correlation_id
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

        if not incident.correlation_id:
            return True

        primary = (
            CorrelationService.get_primary_incident(
                db=db,
                correlation_id=(
                    incident.correlation_id
                ),
            )
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

        return (
            CorrelationService.is_primary_incident(
                db=db,
                incident=incident,
            )
        )

        # =====================================================
    # BUILD CORRELATION SUMMARY
    # =====================================================

    @staticmethod
    def build_correlation_summary(
        incident: dict,
        correlated_incidents: list[dict],
    ) -> dict:
        """
        Build a normalized multi-source correlation summary.

        Confidence is based on the number of independent
        sensor sources contributing to the same activity.
        """

        detected_sources = set()

        primary_source = incident.get(
            "source"
        )

        if primary_source:
            detected_sources.add(
                str(primary_source)
            )

        for correlated in correlated_incidents:

            if not isinstance(
                correlated,
                dict,
            ):
                continue

            correlated_source = (
                correlated.get(
                    "source"
                )
            )

            if correlated_source:
                detected_sources.add(
                    str(correlated_source)
                )

        source_count = len(
            detected_sources
        )

        if source_count >= 3:
            confidence = "high"

        elif source_count == 2:
            confidence = "medium"

        else:
            confidence = "single_source"

        return {
            "source": "multi_source_correlation",

            "correlation_id": (
                incident.get(
                    "correlation_id"
                )
            ),

            "source_count": (
                source_count
            ),

            "sources": sorted(
                detected_sources
            ),

            "confidence": (
                confidence
            ),

            "correlated_incident_count": (
                len(
                    correlated_incidents
                )
            ),
        }
    # =====================================================
    # MARK AS CORRELATED
    # =====================================================

    @staticmethod
    def mark_as_correlated(
        db: Session,
        incident: Incident,
    ) -> None:

        incident.workflow_status = "correlated"
        incident.workflow_error = None

        try:
            db.commit()
            db.refresh(incident)

        except Exception:
            db.rollback()
            raise