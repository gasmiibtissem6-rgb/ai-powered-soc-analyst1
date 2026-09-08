from typing import Dict, Optional

from sqlalchemy.orm import Session

from app.models.incident import Incident


class MetricsService:

    @staticmethod
    def calculate_incident_metrics(
        incident: Incident,
    ) -> Dict[str, Optional[float]]:
        """
        Calculate operational SOC metrics
        for a single incident.

        MTTD:
            detected_at - event_timestamp

        MTTR:
            resolved_at - detected_at

        Values are returned in seconds.

        Invalid negative MTTD/MTTR values are ignored.
        """

        mttd_seconds = None
        mttr_seconds = None

        # --------------------------------------------------
        # MTTD
        # --------------------------------------------------

        if (
            incident.event_timestamp
            and incident.detected_at
        ):
            delta = (
                incident.detected_at
                - incident.event_timestamp
            )

            mttd_seconds = delta.total_seconds()

            # An event cannot be detected before it occurs.
            # Ignore invalid negative values.
            if mttd_seconds < 0:
                mttd_seconds = None

        # --------------------------------------------------
        # MTTR
        # --------------------------------------------------

        if (
            incident.resolved_at
            and incident.detected_at
        ):
            delta = (
                incident.resolved_at
                - incident.detected_at
            )

            mttr_seconds = delta.total_seconds()

            # A resolution cannot happen before detection.
            # Ignore invalid negative values.
            if mttr_seconds < 0:
                mttr_seconds = None

        return {
            "mttd_seconds": mttd_seconds,
            "mttr_seconds": mttr_seconds,
        }

    @staticmethod
    def calculate_quality_metrics(
        incidents: list[Incident],
    ) -> Dict[str, Optional[float]]:
        """
        Calculate SOC analyst classification metrics.

        False Positive Rate:
            false positives / reviewed incidents * 100

        Unknown incidents are ignored because
        they were not reviewed yet.
        """

        reviewed_incidents = [
            incident
            for incident in incidents
            if incident.disposition != "unknown"
        ]

        false_positive_count = sum(
            1
            for incident in reviewed_incidents
            if incident.disposition == "false_positive"
        )

        true_positive_count = sum(
            1
            for incident in reviewed_incidents
            if incident.disposition == "true_positive"
        )

        reviewed_count = len(
            reviewed_incidents
        )

        false_positive_rate = (
            (
                false_positive_count
                / reviewed_count
            )
            * 100
            if reviewed_count
            else None
        )

        return {
            "reviewed_incidents": reviewed_count,
            "false_positive_count": false_positive_count,
            "true_positive_count": true_positive_count,
            "false_positive_rate": false_positive_rate,
        }

    @staticmethod
    def get_global_metrics(
        db: Session,
    ) -> Dict[str, Optional[float]]:
        """
        Calculate global SOC operational metrics.
        """

        incidents = db.query(
            Incident
        ).all()

        mttd_values = []
        mttr_values = []

        for incident in incidents:

            metrics = (
                MetricsService
                .calculate_incident_metrics(
                    incident
                )
            )

            if (
                metrics["mttd_seconds"]
                is not None
            ):
                mttd_values.append(
                    metrics["mttd_seconds"]
                )

            if (
                metrics["mttr_seconds"]
                is not None
            ):
                mttr_values.append(
                    metrics["mttr_seconds"]
                )

        average_mttd = (
            sum(mttd_values)
            / len(mttd_values)
            if mttd_values
            else None
        )

        average_mttr = (
            sum(mttr_values)
            / len(mttr_values)
            if mttr_values
            else None
        )

        quality_metrics = (
            MetricsService
            .calculate_quality_metrics(
                incidents
            )
        )

        return {
            "total_incidents": len(incidents),
            "incidents_with_mttd": len(mttd_values),
            "incidents_with_mttr": len(mttr_values),
            "average_mttd_seconds": average_mttd,
            "average_mttr_seconds": average_mttr,
            **quality_metrics,
        }

    @staticmethod
    def get_severity_distribution(
        db: Session,
    ) -> Dict[str, int]:
        """
        Count incidents grouped by severity.
        """

        incidents = db.query(
            Incident
        ).all()

        distribution = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for incident in incidents:
            severity = (
                incident.severity.lower()
            )

            if severity in distribution:
                distribution[severity] += 1

        return distribution