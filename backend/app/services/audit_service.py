from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


class AuditService:

    @staticmethod
    def log_event(
        db: Session,
        *,
        event_type: str,
        outcome: str,
        actor_subject: Optional[str] = None,
        actor_source: Optional[str] = None,
        actor_email: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        request_method: Optional[str] = None,
        request_path: Optional[str] = None,
        client_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[AuditLog]:
        audit_log = AuditLog(
            event_type=event_type,
            outcome=outcome,
            actor_subject=actor_subject,
            actor_source=actor_source,
            actor_email=actor_email,
            resource_type=resource_type,
            resource_id=resource_id,
            request_method=request_method,
            request_path=request_path,
            client_ip=client_ip,
            details=details,
        )

        try:
            db.add(audit_log)
            db.commit()
            db.refresh(audit_log)
            return audit_log

        except Exception:
            db.rollback()
            return None
