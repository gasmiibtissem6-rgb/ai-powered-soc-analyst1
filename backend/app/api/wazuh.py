from typing import Any
from app.api.agents import run_soc_workflow
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session

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

    service = WazuhService()

    try:
        normalized = service.normalize_alert(
            alert
        )

        incident = service.create_incident_from_alert(
            db=db,
            alert=alert,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to process Wazuh alert: "
                f"{str(exc)}"
            ),
        )
    workflow_result = run_soc_workflow(
    db=db,
    incident=incident,
    request=None,
)

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