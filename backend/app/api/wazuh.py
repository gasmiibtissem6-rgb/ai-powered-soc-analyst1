from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.agents import run_soc_workflow
from app.core.ingestion_security import verify_ingestion_api_key
from app.database.session import get_db
from app.models.incident import Incident
from app.services.correlation_service import CorrelationService
from app.services.wazuh_service import WazuhService

from app.schemas.alert import AlertCreate
from app.services.alert_service import AlertService
from app.utils.datetime_utils import utc_now
router = APIRouter(
    prefix="/wazuh",
    tags=["Wazuh"],
)


# =========================================================
# FIND RECENT DUPLICATE
# =========================================================

def find_recent_duplicate(
    db: Session,
    normalized: dict[str, Any],
    window_minutes: int = 2,
):
    """
    Look for a recently created equivalent Wazuh incident.

    This prevents restarting the complete SOC workflow
    for repeated equivalent Wazuh alerts.
    """

    created_after = utc_now() - timedelta(
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


# =========================================================
# RECEIVE WAZUH ALERT
# =========================================================

@router.post(
    "/alerts",
    status_code=status.HTTP_201_CREATED,
)
def receive_wazuh_alert(
    alert: dict[str, Any],
    db: Session = Depends(get_db),
    _: None = Depends(verify_ingestion_api_key),
):
    """
    Receive a Wazuh alert.

    Steps:
    1. Normalize the Wazuh alert.
    2. Check for a recent duplicate.
    3. Create the SOC incident.
    4. Correlate it with incidents from other sources.
    5. Run the SOC workflow only for the primary incident.
    6. Keep the incident even if the AI workflow fails.
    """

    service = WazuhService()

    # =====================================================
    # 1. NORMALIZE WAZUH ALERT
    # =====================================================

    try:
        normalized = service.normalize_alert(
            alert
        )

    except Exception:
        print(
            "\n========== WAZUH NORMALIZATION ERROR =========="
        )
        print(
            "Unable to normalize Wazuh alert"
        )
        print(
            "===============================================\n"
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to normalize Wazuh alert",
        )

    # =====================================================
    # 2. DEDUPLICATION
    # =====================================================

    try:
        duplicate = find_recent_duplicate(
            db=db,
            normalized=normalized,
            window_minutes=2,
        )

    except Exception:
        print(
            "\n========== WAZUH DEDUP ERROR =========="
        )
        print(
            "Unable to check Wazuh incident deduplication"
        )
        print(
            "=======================================\n"
        )

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to check Wazuh incident deduplication"
            ),
        )

    # -----------------------------------------------------
    # Duplicate found
    # -----------------------------------------------------

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
                "correlation_id": (
                    duplicate.correlation_id
                ),
                "workflow_status": (
                    duplicate.workflow_status
                ),
                "workflow_error": (
                    duplicate.workflow_error
                ),
            },
            "workflow": {
                "status": "not_started",
                "reason": "duplicate_incident",
            },
        }

    # =====================================================
    # 3. CREATE INCIDENT + CORRELATION
    # =====================================================

    try:
        incident = service.create_incident_from_alert(
            db=db,
            alert=alert,
        )
        AlertService.create_alert(
            db=db,
            alert_data=AlertCreate(
                title=incident.title,
                description=incident.description,
                severity=incident.severity,
                source=incident.source,
            ),
        )
        CorrelationService.correlate_incident(
            db=db,
            incident=incident,
            window_minutes=5,
        )

    except Exception:
        print(
            "\n========== WAZUH INCIDENT ERROR =========="
        )
        print(
            "Unable to create/correlate incident from Wazuh alert"
        )
        print(
            "==========================================\n"
        )

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to create/correlate incident from "
                "Wazuh alert"
            ),
        )

    # =====================================================
    # 4. CHECK CORRELATION WORKFLOW CONTROL
    # =====================================================

    try:
        should_run = (
            CorrelationService.should_run_workflow(
                db=db,
                incident=incident,
            )
        )

    except Exception:
        print(
            "\n========== WAZUH CORRELATION ERROR =========="
        )
        print(
            "Unable to determine correlation workflow state"
        )
        print(
            "============================================\n"
        )

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to determine correlation workflow state"
            ),
        )

    # -----------------------------------------------------
    # Secondary correlated incident
    # -----------------------------------------------------

    if not should_run:
        try:
            CorrelationService.mark_as_correlated(
                db=db,
                incident=incident,
            )

        except Exception:
            print(
                "\n========== WAZUH CORRELATION STATUS ERROR =========="
            )
            print(
                "Unable to mark incident as correlated"
            )
            print(
                "===================================================\n"
            )

            raise HTTPException(
                status_code=(
                    status.HTTP_500_INTERNAL_SERVER_ERROR
                ),
                detail=(
                    "Unable to mark incident as correlated"
                ),
            )

        return {
            "status": "correlated",
            "message": (
                "Incident correlated with an existing "
                "multi-source incident. SOC workflow was "
                "not executed again."
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
                "correlation_id": (
                    incident.correlation_id
                ),
                "workflow_status": (
                    incident.workflow_status
                ),
                "workflow_error": (
                    incident.workflow_error
                ),
            },
            "workflow": {
                "status": "not_started",
                "reason": (
                    "secondary_correlated_incident"
                ),
            },
        }

    # =====================================================
    # 5. START SOC MULTI-AGENT WORKFLOW
    # =====================================================

    try:
        workflow_result = run_soc_workflow(
            db=db,
            incident=incident,
            request=None,
        )

    except Exception:
        print(
            "\n========== WAZUH WORKFLOW ERROR =========="
        )
        print(
            "SOC workflow could not be completed"
        )
        print(
            "==========================================\n"
        )

        # IMPORTANT:
        # The Wazuh alert has already been converted
        # into an incident.
        #
        # A failure of LLM / LangGraph must NOT
        # make Wazuh believe that alert ingestion failed.
        #
        # The API therefore keeps HTTP 201.

        return {
            "status": "processed_with_workflow_error",
            "message": (
                "Wazuh alert was converted to an "
                "incident successfully, but the SOC "
                "workflow could not be completed."
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
                "correlation_id": (
                    incident.correlation_id
                ),
                "workflow_status": (
                    incident.workflow_status
                ),
                "workflow_error": (
                    incident.workflow_error
                ),
            },
            "workflow": {
                "status": "error",
                "message": (
                    "SOC workflow could not be completed"
                ),
            },
        }

    # =====================================================
    # 6. SUCCESSFUL RESPONSE
    # =====================================================

    return {
        "status": "processed",
        "message": (
            "Wazuh alert converted to incident, "
            "correlated, and SOC workflow started "
            "successfully."
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
            "correlation_id": (
                incident.correlation_id
            ),
            "workflow_status": (
                incident.workflow_status
            ),
            "workflow_error": (
                incident.workflow_error
            ),
        },
        "workflow": workflow_result,
    }
