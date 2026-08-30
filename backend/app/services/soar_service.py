from datetime import datetime
from ipaddress import ip_address

from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.soar_action import SOARAction
from app.schemas.soar_action import SOARActionCreate


class SOARService:

    @staticmethod
    def get_actions(db: Session):
        return (
            db.query(SOARAction)
            .order_by(SOARAction.id.desc())
            .all()
        )

    @staticmethod
    def get_action(db: Session, action_id: int):
        return (
            db.query(SOARAction)
            .filter(SOARAction.id == action_id)
            .first()
        )

    @staticmethod
    def create_action(
        db: Session,
        data: SOARActionCreate,
    ):
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
    def approve_action(
        db: Session,
        action_id: int,
    ):
        action = SOARService.get_action(
            db,
            action_id,
        )

        if not action:
            return None

        action.approved = True
        action.status = "approved"

        db.commit()
        db.refresh(action)

        return action

    @staticmethod
    def reject_action(
        db: Session,
        action_id: int,
    ):
        action = SOARService.get_action(
            db,
            action_id,
        )

        if not action:
            return None

        action.approved = False
        action.status = "rejected"

        db.commit()
        db.refresh(action)

        return action

    @staticmethod
    def is_safe_ip_target(target: str) -> bool:
        """
        Return False when the IP must not be blocked.

        Protected examples:
        - 127.0.0.1
        - localhost/loopback addresses
        - unspecified addresses such as 0.0.0.0
        - multicast addresses
        """

        if not target:
            return False

        try:
            ip = ip_address(target)
        except ValueError:
            return False

        if ip.is_loopback:
            return False

        if ip.is_unspecified:
            return False

        if ip.is_multicast:
            return False

        return True

    @staticmethod
    def execute_action(
        db: Session,
        action_id: int,
    ):
        action = SOARService.get_action(
            db,
            action_id,
        )

        if not action:
            return None

        if (
            action.requires_approval
            and action.approved is not True
        ):
            return "approval_required"

        # --------------------------------------------------
        # Safety check for IP blocking
        # --------------------------------------------------
        if action.action_type == "block_ip":

            if not SOARService.is_safe_ip_target(
                action.target
            ):
                action.status = "blocked_by_safety"

                action.result = {
                    "success": False,
                    "message": (
                        "SOAR safety policy prevented "
                        "blocking a protected or invalid IP."
                    ),
                    "target": action.target,
                }

                db.commit()
                db.refresh(action)

                return action

        # --------------------------------------------------
        # Prototype SOAR execution
        # --------------------------------------------------
        action.status = "executed"
        action.executed_at = datetime.utcnow()

        action.result = {
            "success": True,
            "message": (
                f"SOAR action "
                f"'{action.action_type}' "
                f"executed successfully."
            ),
            "target": action.target,
        }

        db.commit()
        db.refresh(action)

        return action