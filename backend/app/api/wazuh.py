from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session

from app.api.agents import run_soc_workflow
from app.database.session import get_db
from app.services.wazuh_service import WazuhService


router = APIRouter(
    prefix="/wazuh",
    tags=["Wazuh"],
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
    Receive a Wazuh alert, convert it into a SOC incident,
    and automatically start the SOC analysis workflow.
    """

    service = WazuhService()

    try:
        # ---------------------------------------------
        # 1. Normalize the real Wazuh alert
        # ---------------------------------------------

        normalized = service.normalize_alert(alert)

        # ---------------------------------------------
        # 2. Create the SOC incident
        # ---------------------------------------------

        incident = service.create_incident_from_alert(
            db=db,
            alert=alert,
        )

        # ---------------------------------------------
        # 3. Start the SOC workflow
        # ---------------------------------------------

        workflow_result = run_soc_workflow(
            db=db,
            incident=incident,
            request=None,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Unable to process Wazuh alert: "
                f"{str(exc)}"
            ),
        )

    # ---------------------------------------------
    # 4. API response
    # ---------------------------------------------

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
            "destination_ip": incident.destination_ip,
            "username": incident.username,
        },
        "workflow": workflow_result,
    }