from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.incident import Incident
from app.services.threat_intelligence_service import (
    ThreatIntelligenceService,
)


router = APIRouter(
    prefix="/threat-intelligence",
    tags=["Threat Intelligence"],
)


service = ThreatIntelligenceService()


# =========================================================
# REQUEST SCHEMA
# =========================================================

class TextAnalysisRequest(BaseModel):
    text: str


# =========================================================
# CHECK ONE IP
# =========================================================

@router.get("/ip/{ip_address}")
def check_ip(
    ip_address: str,
):
    try:
        return service.check_ip(
            ip_address
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# ANALYZE TEXT
# =========================================================

@router.post("/analyze")
def analyze_text(
    request: TextAnalysisRequest,
):
    try:
        return service.analyze_text(
            request.text
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# ANALYZE INCIDENT
# =========================================================

@router.get("/incident/{incident_id}")
def analyze_incident_threat_intelligence(
    incident_id: int,
    db: Session = Depends(get_db),
):

    # -----------------------------------------------------
    # 1. Load incident
    # -----------------------------------------------------

    incident = (
        db.query(Incident)
        .filter(
            Incident.id == incident_id
        )
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    results = []
    analyzed_ips = set()

    # -----------------------------------------------------
    # 2. Analyze source_ip directly
    # -----------------------------------------------------

    if incident.source_ip:
        try:
            result = service.check_ip(
                incident.source_ip
            )

            results.append(
                result
            )

            analyzed_ips.add(
                incident.source_ip
            )

        except Exception as exc:
            results.append(
                {
                    "ip_address": incident.source_ip,
                    "error": str(exc),
                }
            )

    # -----------------------------------------------------
    # 3. Analyze IPs found in text
    # -----------------------------------------------------

    text = (
        f"{incident.title or ''} "
        f"{incident.description or ''}"
    )

    extracted_ips = service.extract_ips(
        text
    )

    for ip_address in extracted_ips:

        if ip_address in analyzed_ips:
            continue

        try:
            result = service.check_ip(
                ip_address
            )

            results.append(
                result
            )

            analyzed_ips.add(
                ip_address
            )

        except Exception as exc:
            results.append(
                {
                    "ip_address": ip_address,
                    "error": str(exc),
                }
            )

    # -----------------------------------------------------
    # 4. Response
    # -----------------------------------------------------

    return {
        "incident_id": incident.id,
        "source": incident.source,
        "source_ip": incident.source_ip,
        "threat_intelligence": results,
    }