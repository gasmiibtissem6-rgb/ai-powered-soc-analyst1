import traceback
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.agents import run_soc_workflow
from app.database.session import get_db
from app.models.incident import Incident
from app.services.wazuh_service import WazuhService


router = APIRouter(
    prefix="/wazuh",
    tags=["Wazuh"],
)


def find_recent_duplicate(
    db: Session,
    normalized: dict[str, Any],
    window_minutes: int = 2,
):
    """
    Look for a recently created equivalent Wazuh incident.

    The goal is to avoid restarting the full SOC workflow
    for repeated identical low-level Wazuh alerts.
    """

    created_after = datetime.utcnow() - timedelta(
        minutes=window_minutes
    )

    query = (
        db.query(Incident)
        .filter(
            Incident.source == "Wazuh",
            Incident.title == normalized.get("title"),
            Incident.created_at >= created_after,
        )
    )

    hostname = normalized.get("hostname")
    if hostname:
        query = query.filter(
            Incident.hostname == hostname
        )

    source_ip = normalized.get("source_ip")
    if source_ip:
        query = query.filter(
            Incident.source_ip == source_ip
        )

    username = normalized.get("username")
    if username:
        query = query.filter(
            Incident.username == username
        )

    return (
        query.order_by(
            Incident.id.desc()
        )
        .first()
    )


@router.post(
    "/alerts",
    status_code=status.HTTP_201_CREATED,
)
def receive_wazuh_alert(
    alert: dict[str, Any],
    db: Session = Depends(get_db),
):
    """
    Receive a Wazuh alert, normalize it, create a SOC incident,
    and start the multi-agent SOC workflow.
    """

    service = WazuhService()

    # --------------------------------------------------
    # 1. Normalize the Wazuh alert
    # --------------------------------------------------

    try:
        normalized = service.normalize_alert(alert)

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Unable to normalize Wazuh alert: "
                f"{str(exc)}"
            ),
        )

    # --------------------------------------------------
    # 2. Deduplication
    # --------------------------------------------------

    try:
        duplicate = find_recent_duplicate(
            db=db,
            normalized=normalized,
            window_minutes=2,
        )

    except Exception as exc:
        print(
            "\n========== WAZUH DEDUP ERROR =========="
        )
        print(
            f"Error type: {type(exc).__name__}"
        )
        print(
            f"Error message: {str(exc)}"
        )
        traceback.print_exc()
        print(
            "=======================================\n"
        )

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to check Wazuh incident "
                f"deduplication: {str(exc)}"
            ),
        )

    if duplicate:
        return {
            "status": "duplicate",
            "message": (
                "A recent equivalent Wazuh incident "
                "already exists. SOC workflow was "
                "not restarted."
            ),
            "wazuh": {
                "rule_id": normalized.get(
                    "wazuh_rule_id"
                ),
                "rule_level": normalized.get(
                    "wazuh_rule_level"
                ),
                "agent_id": normalized.get(
                    "wazuh_agent_id"
                ),
                "agent_name": normalized.get(
                    "wazuh_agent_name"
                ),
            },
            "incident": {
                "id": duplicate.id,
                "title": duplicate.title,
                "severity": duplicate.severity,
                "status": duplicate.status,
                "source": duplicate.source,
                "hostname": duplicate.hostname,
                "source_ip": duplicate.source_ip,
                "destination_ip": (
                    duplicate.destination_ip
                ),
                "username": duplicate.username,
            },
            "workflow": {
                "status": "not_started",
                "reason": "duplicate_incident",
            },
        }

    # --------------------------------------------------
    # 3. Create incident + start SOC workflow
    # --------------------------------------------------

    try:
        incident = service.create_incident_from_alert(
            db=db,
            alert=alert,
        )

        workflow_result = run_soc_workflow(
            db=db,
            incident=incident,
            request=None,
        )

    except Exception as exc:
        print(
            "\n========== WAZUH WORKFLOW ERROR =========="
        )
        print(
            f"Error type: {type(exc).__name__}"
        )
        print(
            f"Error message: {str(exc)}"
        )
        traceback.print_exc()
        print(
            "==========================================\n"
        )

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to process Wazuh alert: "
                f"{str(exc)}"
            ),
        )

    # --------------------------------------------------
    # 4. API response
    # --------------------------------------------------

    return {
        "status": "processed",
        "message": (
            "Wazuh alert converted to incident "
            "and SOC workflow started successfully."
        ),
        "wazuh": {
            "rule_id": normalized.get(
                "wazuh_rule_id"
            ),
            "rule_level": normalized.get(
                "wazuh_rule_level"
            ),
            "agent_id": normalized.get(
                "wazuh_agent_id"
            ),
            "agent_name": normalized.get(
                "wazuh_agent_name"
            ),
            "agent_ip": normalized.get(
                "wazuh_agent_ip"
            ),
            "mitre_ids": normalized.get(
                "mitre_ids"
            ),
            "mitre_techniques": normalized.get(
                "mitre_techniques"
            ),
            "mitre_tactics": normalized.get(
                "mitre_tactics"
            ),
        },
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "source": incident.source,
            "hostname": incident.hostname,
            "source_ip": incident.source_ip,
            "destination_ip": (
                incident.destination_ip
            ),
            "username": incident.username,
        },
        "workflow": workflow_result,
    }