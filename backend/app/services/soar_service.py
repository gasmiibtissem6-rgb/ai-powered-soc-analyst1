from datetime import datetime
from ipaddress import ip_address
from typing import Optional

from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.soar_action import SOARAction
from app.models.soar_action_log import SOARActionLog
from app.schemas.soar_action import SOARActionCreate
from app.services.soar_executor_service import SOARExecutorService

class SOARService:

    # =====================================================
    # AUDIT LOG
    # =====================================================

    @staticmethod
    def log_action_event(
        db: Session,
        action: SOARAction,
        event_type: str,
        previous_status: Optional[str],
        new_status: str,
        details: Optional[dict] = None,
    ) -> SOARActionLog:
        """
        Persist one SOAR audit event.
        """

        log = SOARActionLog(
            action_id=action.id,
            incident_id=action.incident_id,
            event_type=event_type,
            previous_status=previous_status,
            new_status=new_status,
            details=details,
        )

        try:
            db.add(log)
            db.commit()
            db.refresh(log)

        except Exception:
            db.rollback()
            raise

        return log

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
    # GET ACTION AUDIT LOGS
    # =====================================================

    @staticmethod
    def get_action_logs(
        db: Session,
        action_id: int,
    ):
        """
        Return the complete audit history
        for one SOAR action.
        """

        action = SOARService.get_action(
            db=db,
            action_id=action_id,
        )

        if not action:
            return None

        return (
            db.query(SOARActionLog)
            .filter(
                SOARActionLog.action_id == action_id
            )
            .order_by(
                SOARActionLog.id.asc()
            )
            .all()
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
            approved=None,
        )

        try:
            db.add(action)
            db.commit()
            db.refresh(action)

        except Exception:
            db.rollback()
            raise

        SOARService.log_action_event(
            db=db,
            action=action,
            event_type="created",
            previous_status=None,
            new_status="pending",
            details={
                "action_type": action.action_type,
                "target": action.target,
                "requires_approval": (
                    action.requires_approval
                ),
            },
        )

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

        previous_status = action.status

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

                SOARService.log_action_event(
                    db=db,
                    action=action,
                    event_type="blocked_by_safety",
                    previous_status=previous_status,
                    new_status="blocked_by_safety",
                    details=action.result,
                )

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

                SOARService.log_action_event(
                    db=db,
                    action=action,
                    event_type="blocked_by_safety",
                    previous_status=previous_status,
                    new_status="blocked_by_safety",
                    details=action.result,
                )

                return action

        # -------------------------------------------------
        # Safety: invalid user cannot be approved
        # -------------------------------------------------

        if action.action_type == "disable_user":

            if not SOARService.is_safe_user_target(
                action.target
            ):
                action.approved = False
                action.status = "blocked_by_safety"

                action.result = {
                    "success": False,
                    "message": (
                        "SOAR safety policy prevented "
                        "approval of an invalid user target."
                    ),
                    "target": action.target,
                }

                try:
                    db.commit()
                    db.refresh(action)

                except Exception:
                    db.rollback()
                    raise

                SOARService.log_action_event(
                    db=db,
                    action=action,
                    event_type="blocked_by_safety",
                    previous_status=previous_status,
                    new_status="blocked_by_safety",
                    details=action.result,
                )

                return action

        action.approved = True
        action.status = "approved"

        try:
            db.commit()
            db.refresh(action)

        except Exception:
            db.rollback()
            raise

        SOARService.log_action_event(
            db=db,
            action=action,
            event_type="approved",
            previous_status=previous_status,
            new_status="approved",
            details={
                "target": action.target,
                "action_type": action.action_type,
            },
        )

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

        previous_status = action.status

        action.approved = False
        action.status = "rejected"

        try:
            db.commit()
            db.refresh(action)

        except Exception:
            db.rollback()
            raise

        SOARService.log_action_event(
            db=db,
            action=action,
            event_type="rejected",
            previous_status=previous_status,
            new_status="rejected",
            details={
                "target": action.target,
                "action_type": action.action_type,
            },
        )

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
    # USER SAFETY
    # =====================================================

    @staticmethod
    def is_safe_user_target(
        target: str,
    ) -> bool:
        """
        Return False when a user account target is
        empty, unknown, or otherwise unusable.
        """

        if not target:
            return False

        normalized = target.strip().lower()

        unsafe_values = {
            "",
            "unknown",
            "unknown-user",
            "unknown_user",
            "none",
            "null",
            "n/a",
            "na",
            "undefined",
        }

        return normalized not in unsafe_values

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

        previous_status = action.status

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

                SOARService.log_action_event(
                    db=db,
                    action=action,
                    event_type="blocked_by_safety",
                    previous_status=previous_status,
                    new_status="blocked_by_safety",
                    details=action.result,
                )

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

                SOARService.log_action_event(
                    db=db,
                    action=action,
                    event_type="blocked_by_safety",
                    previous_status=previous_status,
                    new_status="blocked_by_safety",
                    details=action.result,
                )

                return action

        # -------------------------------------------------
        # Safety check for user disabling
        # -------------------------------------------------



        if action.action_type == "disable_user":

            if not SOARService.is_safe_user_target(
                action.target
            ):
                action.status = "blocked_by_safety"

                action.result = {
                    "success": False,
                    "message": (
                        "SOAR safety policy prevented "
                        "disabling an invalid user target."
                    ),
                    "target": action.target,
                }

                try:
                    db.commit()
                    db.refresh(action)

                except Exception:
                    db.rollback()
                    raise

                SOARService.log_action_event(
                    db=db,
                    action=action,
                    event_type="blocked_by_safety",
                    previous_status=previous_status,
                    new_status="blocked_by_safety",
                    details=action.result,
                )

                return action

        # -------------------------------------------------
        # Execute through SOAR Executor
        # -------------------------------------------------

        execution_result = SOARExecutorService.execute(
            action_type=action.action_type,
            target=action.target,
        )

        action.result = execution_result

        # -------------------------------------------------
        # Determine resulting status
        # -------------------------------------------------

        if execution_result.get("success") is True:

            if execution_result.get("simulated") is True:
                action.status = "simulated"

            elif execution_result.get("executed") is True:
                action.status = "executed"
                action.executed_at = datetime.utcnow()

            else:
                action.status = "completed"

        else:
            action.status = "execution_failed"

        # -------------------------------------------------
        # Save result
        # -------------------------------------------------

        try:
            db.commit()
            db.refresh(action)

        except Exception:
            db.rollback()
            raise

        # -------------------------------------------------
        # Audit event
        # -------------------------------------------------

        if action.status == "simulated":
            event_type = "simulated"

        elif action.status == "executed":
            event_type = "executed"

        elif action.status == "completed":
            event_type = "completed"

        else:
            event_type = "execution_failed"

        SOARService.log_action_event(
            db=db,
            action=action,
            event_type=event_type,
            previous_status=previous_status,
            new_status=action.status,
            details=execution_result,
        )

        return action