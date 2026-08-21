from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.schemas.incident import IncidentCreate, IncidentUpdate


class IncidentService:

    @staticmethod
    def get_incidents(db: Session):
        return db.query(Incident).order_by(Incident.id.desc()).all()

    @staticmethod
    def get_incident(db: Session, incident_id: int):
        return db.query(Incident).filter(
            Incident.id == incident_id
        ).first()

    @staticmethod
    def create_incident(db: Session, incident_data: IncidentCreate):
        incident = Incident(**incident_data.model_dump())

        db.add(incident)
        db.commit()
        db.refresh(incident)

        return incident

    @staticmethod
    def update_incident(
        db: Session,
        incident_id: int,
        incident_data: IncidentUpdate
    ):
        incident = db.query(Incident).filter(
            Incident.id == incident_id
        ).first()

        if not incident:
            return None

        update_data = incident_data.model_dump(exclude_unset=True)

        for key, value in update_data.items():
            setattr(incident, key, value)

        db.commit()
        db.refresh(incident)

        return incident

    @staticmethod
    def delete_incident(db: Session, incident_id: int) -> bool:
        incident = db.query(Incident).filter(
            Incident.id == incident_id
        ).first()

        if not incident:
            return False

        db.delete(incident)
        db.commit()

        return True