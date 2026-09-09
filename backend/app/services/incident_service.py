from typing import Optional

from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
)
from app.utils.datetime_utils import utc_now

class IncidentService:

    @staticmethod
    def get_incidents(
        db: Session,
        workflow_status: Optional[str] = None,
    ):
        query = db.query(Incident)

        if workflow_status:
            query = query.filter(
                Incident.workflow_status == workflow_status
            )

        return (
            query.order_by(
                Incident.id.desc()
            )
            .all()
        )

    @staticmethod
    def get_incident(
        db: Session,
        incident_id: int,
    ):
        return (
            db.query(Incident)
            .filter(
                Incident.id == incident_id
            )
            .first()
        )

    @staticmethod
    def create_incident(
        db: Session,
        incident_data: IncidentCreate,
    ):
        incident = Incident(
            **incident_data.model_dump()
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)

        return incident

    @staticmethod
    def update_incident(
        db: Session,
        incident_id: int,
        incident_data: IncidentUpdate,
    ):
        incident = (
            db.query(Incident)
            .filter(
                Incident.id == incident_id
            )
            .first()
        )

        if not incident:
            return None

        update_data = incident_data.model_dump(
            exclude_unset=True
        )

        new_status = update_data.get(
            "status"
        )

        if (
            new_status in {
                "resolved",
                "closed",
            }
            and incident.resolved_at is None
        ):
            incident.resolved_at = (
                utc_now()
            )

        elif (
            new_status
            and new_status not in {
                "resolved",
                "closed",
            }
        ):
            incident.resolved_at = None

        for key, value in update_data.items():
            setattr(
                incident,
                key,
                value,
            )

        db.commit()
        db.refresh(incident)

        return incident

    @staticmethod
    def delete_incident(
        db: Session,
        incident_id: int,
    ) -> bool:
        incident = (
            db.query(Incident)
            .filter(
                Incident.id == incident_id
            )
            .first()
        )

        if not incident:
            return False

        db.delete(incident)
        db.commit()

        return True
