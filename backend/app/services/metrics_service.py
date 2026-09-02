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
        """

        mttd_seconds = None
        mttr_seconds = None

        if (
            incident.event_timestamp
            and incident.detected_at
        ):
            delta = (
                incident.detected_at
                - incident.event_timestamp
            )

            mttd_seconds = max(
                0.0,
                delta.total_seconds(),
            )

        if (
            incident.resolved_at
            and incident.detected_at
        ):
            delta = (
                incident.resolved_at
                - incident.detected_at
            )

            mttr_seconds = max(
                0.0,
                delta.total_seconds(),
            )

        return {
            "mttd_seconds": mttd_seconds,
            "mttr_seconds": mttr_seconds,
        }

    @staticmethod
    def get_global_metrics(
        db: Session,
    ) -> Dict[str, Optional[float]]:
        """
        Calculate average MTTD and MTTR
        across incidents with valid timestamps.
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

        return {
            "total_incidents": len(
                incidents
            ),
            "incidents_with_mttd": len(
                mttd_values
            ),
            "incidents_with_mttr": len(
                mttr_values
            ),
            "average_mttd_seconds": (
                average_mttd
            ),
            "average_mttr_seconds": (
                average_mttr
            ),
        }
