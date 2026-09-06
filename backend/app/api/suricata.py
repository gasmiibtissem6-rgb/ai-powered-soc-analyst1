import traceback
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.agents import run_soc_workflow
from app.core.ingestion_security import verify_ingestion_api_key
from app.database.session import get_db
from app.models.incident import Incident
from app.services.correlation_service import CorrelationService
from app.services.suricata_service import SuricataService


router = APIRouter(
    prefix="/suricata",
    tags=["Suricata"],
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
    Look for a recently created equivalent Suricata incident.

    This prevents restarting the complete SOC workflow
    for repeated equivalent network alerts.
    """

    created_after = datetime.utcnow() - timedelta(
        minutes=window_minutes
    )

    query = (
        db.query(Incident)
        .filter(
            Incident.source == "Suricata",
            Incident.title == normalized.get("title"),
            Incident.created_at >= created_after,
        )
    )

    source_ip = normalized.get("source_ip")

    if source_ip:
        query = query.filter(
            Incident.source_ip == source_ip
        )

    destination_ip = normalized.get(
        "destination_ip"
    )

    if destination_ip:
        query = query.filter(
            Incident.destination_ip == destination_ip
        )

    return (
        query.order_by(
            Incident.id.desc()
        )
        .first()
    )


# =========================================================
# RECEIVE SURICATA ALERT
# =========================================================

@router.post(
    "/alerts",
    status_code=status.HTTP_201_CREATED,
)
def receive_suricata_alert(
    alert: dict[str, Any],
    db: Session = Depends(get_db),
    _: None = Depends(verify_ingestion_api_key),
):
    """
    Receive a Suricata EVE JSON alert.

    Steps:
    1. Normalize the Suricata alert.
    2. Check for a recent duplicate.
    3. Create the SOC incident.
    4. Correlate it with incidents from other sources.
    5. Run the SOC workflow only for the primary incident.
    6. Keep the incident even if the AI workflow fails.
    """

    service = SuricataService()

    # =====================================================
    # 1. NORMALIZE SURICATA ALERT
    # =====================================================

    try:
        normalized = service.normalize_alert(
            alert
        )

    except Exception as exc:
        print(
            "\n========== SURICATA NORMALIZATION ERROR =========="
        )
        print(
            f"Error type: {type(exc).__name__}"
        )
        print(
            f"Error message: {str(exc)}"
        )
        traceback.print_exc()
        print(
            "==================================================\n"
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Unable to normalize Suricata alert: "
                f"{str(exc)}"
            ),
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

    except Exception as exc:
        print(
            "\n========== SURICATA DEDUP ERROR =========="
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
                "Unable to check Suricata incident "
                f"deduplication: {str(exc)}"
            ),
        )

    # -----------------------------------------------------
    # Duplicate found
    # -----------------------------------------------------

    if duplicate:
        return {
            "status": "duplicate",
            "message": (
                "A recent equivalent Suricata incident "
                "already exists. SOC workflow was "
                "not restarted."
            ),
            "suricata": normalized.get(
                "suricata",
                {},
            ),
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

        CorrelationService.correlate_incident(
            db=db,
            incident=incident,
            window_minutes=5,
        )

    except Exception as exc:
        print(
            "\n========== SURICATA INCIDENT ERROR =========="
        )
        print(
            f"Error type: {type(exc).__name__}"
        )
        print(
            f"Error message: {str(exc)}"
        )
        traceback.print_exc()
        print(
            "============================================\n"
        )

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to create/correlate incident from "
                f"Suricata alert: {str(exc)}"
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

    except Exception as exc:
        print(
            "\n========== SURICATA CORRELATION ERROR =========="
        )
        print(
            f"Error type: {type(exc).__name__}"
        )
        print(
            f"Error message: {str(exc)}"
        )
        traceback.print_exc()
        print(
            "===============================================\n"
        )

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to determine correlation "
                f"workflow state: {str(exc)}"
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

        except Exception as exc:
            print(
                "\n========== SURICATA CORRELATION STATUS ERROR =========="
            )
            print(
                f"Error type: {type(exc).__name__}"
            )
            print(
                f"Error message: {str(exc)}"
            )
            traceback.print_exc()
            print(
                "======================================================\n"
            )

            raise HTTPException(
                status_code=(
                    status.HTTP_500_INTERNAL_SERVER_ERROR
                ),
                detail=(
                    "Unable to mark incident as "
                    f"correlated: {str(exc)}"
                ),
            )

        return {
            "status": "correlated",
            "message": (
                "Incident correlated with an existing "
                "multi-source incident. SOC workflow was "
                "not executed again."
            ),
            "suricata": normalized.get(
                "suricata",
                {},
            ),
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
    suricata_event=alert,
)

    except Exception as exc:
        print(
            "\n========== SURICATA WORKFLOW ERROR =========="
        )
        print(
            f"Error type: {type(exc).__name__}"
        )
        print(
            f"Error message: {str(exc)}"
        )
        traceback.print_exc()
        print(
            "============================================\n"
        )

        # IMPORTANT:
        # The Suricata alert has already been converted
        # into an incident.
        #
        # A failure of LLM / LangGraph must NOT
        # make Suricata ingestion fail.
        #
        # The API therefore keeps HTTP 201.

        return {
            "status": "processed_with_workflow_error",
            "message": (
                "Suricata alert was converted to an "
                "incident successfully, but the SOC "
                "workflow could not be completed."
            ),
            "suricata": normalized.get(
                "suricata",
                {},
            ),
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
                "error_type": type(exc).__name__,
                "message": str(exc),
            },
        }

    # =====================================================
    # 6. SUCCESSFUL RESPONSE
    # =====================================================

    return {
        "status": "processed",
        "message": (
            "Suricata alert converted to incident, "
            "correlated, and SOC workflow started "
            "successfully."
        ),
        "suricata": normalized.get(
            "suricata",
            {},
        ),
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