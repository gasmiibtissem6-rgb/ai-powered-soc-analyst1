from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.threat_intelligence_service import ThreatIntelligenceService
from fastapi import Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.incident import Incident

router = APIRouter(
    prefix="/threat-intelligence",
    tags=["Threat Intelligence"]
)

service = ThreatIntelligenceService()


class TextAnalysisRequest(BaseModel):
    text: str


@router.get("/ip/{ip_address}")
def check_ip(ip_address: str):
    try:
        return service.check_ip(ip_address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze")
def analyze_text(request: TextAnalysisRequest):
    return service.analyze_text(request.text)

@router.get("/incident/{incident_id}")
def analyze_incident_threat_intelligence(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    text = f"{incident.title} {incident.description}"

    results = service.analyze_text(text)

    return {
    "threat_intelligence": result,
    "agent_trace": [
        "Threat Intelligence"
    ],
}