from datetime import datetime
from ipaddress import ip_address

from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.soar_action import SOARAction
from app.schemas.soar_action import SOARActionCreate


class SOARService:

    # =====================================================
    # GET ALL ACTIONS
    # =====================================================

    @staticmethod
    def get_actions(
        db: Session,
    ):
        return (
            db.query(SOARAction)
            .order_by(
                SOARAction.id.desc()
            )
            .all()
        )

    # =====================================================
    # GET ONE ACTION
    # =====================================================

    @staticmethod
    def get_action(
        db: Session,
        action_id: int,
    ):
        return (
            db.query(SOARAction)
            .filter(
                SOARAction.id == action_id
            )
            .first()
        )

    # =====================================================
    # CREATE ACTION
    # =====================================================

    @staticmethod
    def create_action(
        db: Session,
        data: SOARActionCreate,
    ):
        incident = (
            db.query(Incident)
            .filter(
                Incident.id == data.incident_id
            )
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

        try:
            db.add(action)
            db.commit()
            db.refresh(action)

        except Exception:
            db.rollback()
            raise

        return action

    # =====================================================
    # APPROVE ACTION
    # =====================================================

    @staticmethod
    def approve_action(
        db: Session,
        action_id: int,
    ):
        action = SOARService.get_action(
            db=db,
            action_id=action_id,
        )

        if not action:
            return None

        # -------------------------------------------------
        # Safety: invalid endpoint cannot be approved
        # -------------------------------------------------

        if action.action_type == "isolate_endpoint":

            if not SOARService.is_safe_endpoint_target(
                action.target
            ):
                action.approved = False
                action.status = "blocked_by_safety"

                action.result = {
                    "success": False,
                    "message": (
                        "SOAR safety policy prevented "
                        "approval of an invalid endpoint "
                        "isolation target."
                    ),
                    "target": action.target,
                }

                try:
                    db.commit()
                    db.refresh(action)

                except Exception:
                    db.rollback()
                    raise

                return action

        # -------------------------------------------------
        # Safety: invalid IP cannot be approved for blocking
        # -------------------------------------------------

        if action.action_type == "block_ip":

            if not SOARService.is_safe_ip_target(
                action.target
            ):
                action.approved = False
                action.status = "blocked_by_safety"

                action.result = {
                    "success": False,
                    "message": (
                        "SOAR safety policy prevented "
                        "approval of an invalid or "
                        "protected IP target."
                    ),
                    "target": action.target,
                }

                try:
                    db.commit()
                    db.refresh(action)

                except Exception:
                    db.rollback()
                    raise

                return action

        action.approved = True
        action.status = "approved"

        try:
            db.commit()
            db.refresh(action)

        except Exception:
            db.rollback()
            raise

        return action

    # =====================================================
    # REJECT ACTION
    # =====================================================

    @staticmethod
    def reject_action(
        db: Session,
        action_id: int,
    ):
        action = SOARService.get_action(
            db=db,
            action_id=action_id,
        )

        if not action:
            return None

        action.approved = False
        action.status = "rejected"

        try:
            db.commit()
            db.refresh(action)

        except Exception:
            db.rollback()
            raise

        return action

    # =====================================================
    # IP SAFETY
    # =====================================================

    @staticmethod
    def is_safe_ip_target(
        target: str,
    ) -> bool:
        """
        Return False when an IP must not be blocked.

        Protected examples:
        - loopback addresses
        - unspecified addresses
        - multicast addresses
        - invalid strings
        """

        if not target:
            return False

        try:
            ip = ip_address(
                target.strip()
            )

        except ValueError:
            return False

        if ip.is_loopback:
            return False

        if ip.is_unspecified:
            return False

        if ip.is_multicast:
            return False

        return True

    # =====================================================
    # ENDPOINT SAFETY
    # =====================================================

    @staticmethod
    def is_safe_endpoint_target(
        target: str,
    ) -> bool:
        """
        Return False when an endpoint isolation target
        is empty, unknown, or otherwise unusable.
        """

        if not target:
            return False

        normalized = target.strip().lower()

        unsafe_values = {
            "",
            "unknown",
            "unknown-endpoint",
            "unknown_endpoint",
            "none",
            "null",
            "n/a",
            "na",
            "undefined",
        }

        if normalized in unsafe_values:
            return False

        return True

    # =====================================================
    # EXECUTE ACTION
    # =====================================================

    @staticmethod
    def execute_action(
        db: Session,
        action_id: int,
    ):
        action = SOARService.get_action(
            db=db,
            action_id=action_id,
        )

        if not action:
            return None

        # -------------------------------------------------
        # Approval requirement
        # -------------------------------------------------

        if (
            action.requires_approval
            and action.approved is not True
        ):
            return "approval_required"

        # -------------------------------------------------
        # Safety check for IP blocking
        # -------------------------------------------------

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

                try:
                    db.commit()
                    db.refresh(action)

                except Exception:
                    db.rollback()
                    raise

                return action

        # -------------------------------------------------
        # Safety check for endpoint isolation
        # -------------------------------------------------

        if action.action_type == "isolate_endpoint":

            if not SOARService.is_safe_endpoint_target(
                action.target
            ):
                action.status = "blocked_by_safety"

                action.result = {
                    "success": False,
                    "message": (
                        "SOAR safety policy prevented "
                        "isolating an unknown or invalid "
                        "endpoint."
                    ),
                    "target": action.target,
                }

                try:
                    db.commit()
                    db.refresh(action)

                except Exception:
                    db.rollback()
                    raise

                return action

        # -------------------------------------------------
        # Prototype SOAR execution
        # -------------------------------------------------

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

        try:
            db.commit()
            db.refresh(action)

        except Exception:
            db.rollback()
            raise

        return action