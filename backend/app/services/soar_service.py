from datetime import datetime

from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.soar_action import SOARAction
from app.schemas.soar_action import SOARActionCreate


class SOARService:

    @staticmethod
    def get_actions(db: Session):
        return db.query(SOARAction).order_by(SOARAction.id.desc()).all()

    @staticmethod
    def get_action(db: Session, action_id: int):
        return (
            db.query(SOARAction)
            .filter(SOARAction.id == action_id)
            .first()
        )

    @staticmethod
    def create_action(db: Session, data: SOARActionCreate):
        incident = (
            db.query(Incident)
            .filter(Incident.id == data.incident_id)
            .first()
        )

        if not incident:
            return None

        action = SOARAction(
            incident_id=data.incident_id,
            action_type=data.action_type,
            target=data.target,
            requires_approval=data.requires_approval,
            status="pending",
        )

        db.add(action)
        db.commit()
        db.refresh(action)

        return action

    @staticmethod
    def approve_action(db: Session, action_id: int):
        action = SOARService.get_action(db, action_id)

        if not action:
            return None

        action.approved = True
        action.status = "approved"

        db.commit()
        db.refresh(action)

        return action

    @staticmethod
    def reject_action(db: Session, action_id: int):
        action = SOARService.get_action(db, action_id)

        if not action:
            return None

        action.approved = False
        action.status = "rejected"

        db.commit()
        db.refresh(action)

        return action

    @staticmethod
    def execute_action(db: Session, action_id: int):
        action = SOARService.get_action(db, action_id)

        if not action:
            return None

        if action.requires_approval and action.approved is not True:
            return "approval_required"

        # Simulation de l'action SOAR pour le prototype.
        action.status = "executed"
        action.executed_at = datetime.utcnow()

        action.result = {
            "success": True,
            "message": f"SOAR action '{action.action_type}' executed successfully.",
            "target": action.target,
        }

        db.commit()
        db.refresh(action)

        return action