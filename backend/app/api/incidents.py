from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.incident import Incident
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
)
from app.services.incident_service import IncidentService


router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)


# =========================================================
# GET ALL INCIDENTS
# =========================================================

@router.get(
    "",
    response_model=List[IncidentResponse],
)
def get_incidents(
    workflow_status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    return IncidentService.get_incidents(
        db=db,
        workflow_status=workflow_status,
    )


# =========================================================
# CREATE INCIDENT
# =========================================================

@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_incident(
    incident_data: IncidentCreate,
    db: Session = Depends(get_db),
):
    return IncidentService.create_incident(
        db,
        incident_data,
    )


# =========================================================
# GET INCIDENTS BY CORRELATION ID
# =========================================================

@router.get(
    "/correlation/{correlation_id}",
)
def get_correlated_incidents(
    correlation_id: str,
    db: Session = Depends(get_db),
):
    """
    Return all incidents belonging to the same
    multi-source correlation group.
    """

    incidents = (
        db.query(Incident)
        .filter(
            Incident.correlation_id == correlation_id
        )
        .order_by(
            Incident.created_at.asc()
        )
        .all()
    )

    if not incidents:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Correlation group not found",
        )

    sources = sorted(
        {
            incident.source
            for incident in incidents
            if incident.source
        }
    )

    source_ips = sorted(
        {
            incident.source_ip
            for incident in incidents
            if incident.source_ip
        }
    )

    destination_ips = sorted(
        {
            incident.destination_ip
            for incident in incidents
            if incident.destination_ip
        }
    )

    severities = [
        incident.severity
        for incident in incidents
        if incident.severity
    ]

    severity_order = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    highest_severity = max(
        severities,
        key=lambda value: severity_order.get(
            value.lower(),
            0,
        ),
        default="unknown",
    )

    return {
        "correlation_id": correlation_id,
        "incident_count": len(incidents),
        "sources": sources,
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "highest_severity": highest_severity,
        "first_seen": incidents[0].created_at,
        "last_seen": incidents[-1].created_at,
        "incidents": [
            {
                "id": incident.id,
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity,
                "status": incident.status,
                "source": incident.source,
                "hostname": incident.hostname,
                "source_ip": incident.source_ip,
                "destination_ip": (
                    incident.destination_ip
                ),
                "username": incident.username,
                "assigned_to": incident.assigned_to,
                "workflow_status": (
                    incident.workflow_status
                ),
                "workflow_error": (
                    incident.workflow_error
                ),
                "correlation_id": (
                    incident.correlation_id
                ),
                "created_at": incident.created_at,
            }
            for incident in incidents
        ],
    }


# =========================================================
# GET ONE INCIDENT
# =========================================================

@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = IncidentService.get_incident(
        db,
        incident_id,
    )

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return incident


# =========================================================
# UPDATE INCIDENT
# =========================================================

@router.put(
    "/{incident_id}",
    response_model=IncidentResponse,
)
def update_incident(
    incident_id: int,
    incident_data: IncidentUpdate,
    db: Session = Depends(get_db),
):
    incident = IncidentService.update_incident(
        db,
        incident_id,
        incident_data,
    )

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return incident


# =========================================================
# DELETE INCIDENT
# =========================================================

@router.delete(
    "/{incident_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_incident(
    incident_id: int,
    db: Session = Depends(get_db),
):
    deleted = IncidentService.delete_incident(
        db,
        incident_id,
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )