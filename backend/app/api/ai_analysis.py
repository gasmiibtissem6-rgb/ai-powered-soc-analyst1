from typing import List
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session
from app.core.config import settings
from app.database.session import get_db

from app.models.incident import Incident
from app.models.ai_analysis import AIAnalysis

from app.schemas.ai_analysis import (
    AIAnalysisCreate,
    AIAnalysisUpdate,
    AIAnalysisResponse,
)

from app.services.ai_analysis_service import AIAnalysisService
from app.services.llm_service import LLMService
from app.services.mitre_service import MitreService
from app.agents.soc_graph import threat_intelligence_agent
from app.core.security import require_admin, require_analyst
from app.models.user import User

router = APIRouter(
    prefix="/ai-analysis",
    tags=["AI Analysis"],
)


# =========================================================
# GET ALL AI ANALYSES
# =========================================================

@router.get(
    "",
    response_model=List[AIAnalysisResponse],
)
def get_analyses(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    return AIAnalysisService.get_analyses(db)


# =========================================================
# GET ANALYSES BY INCIDENT
# =========================================================

@router.get(
    "/incident/{incident_id}",
    response_model=List[AIAnalysisResponse],
)
def get_analyses_by_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):

    incident = (
        db.query(Incident)
        .filter(
            Incident.id == incident_id
        )
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    analyses = (
        db.query(AIAnalysis)
        .filter(
            AIAnalysis.incident_id == incident_id
        )
        .order_by(
            AIAnalysis.id.desc()
        )
        .all()
    )

    return analyses


# =========================================================
# GET ONE AI ANALYSIS
# =========================================================

@router.get(
    "/{analysis_id}",
    response_model=AIAnalysisResponse,
)
def get_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):

    analysis = AIAnalysisService.get_analysis(
        db,
        analysis_id,
    )

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AI analysis not found",
        )

    return analysis


# =========================================================
# CREATE AI ANALYSIS MANUALLY
# =========================================================

@router.post(
    "",
    response_model=AIAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_analysis(
    analysis_data: AIAnalysisCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):

    analysis = AIAnalysisService.create_analysis(
        db,
        analysis_data,
    )

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return analysis


# =========================================================
# UPDATE AI ANALYSIS
# =========================================================

@router.put(
    "/{analysis_id}",
    response_model=AIAnalysisResponse,
)
def update_analysis(
    analysis_id: int,
    analysis_data: AIAnalysisUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):

    analysis = AIAnalysisService.update_analysis(
        db,
        analysis_id,
        analysis_data,
    )

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AI analysis not found",
        )

    return analysis


# =========================================================
# DELETE AI ANALYSIS
# =========================================================

@router.delete(
    "/{analysis_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):

    deleted = AIAnalysisService.delete_analysis(
        db,
        analysis_id,
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AI analysis not found",
        )

    return None


# =========================================================
# GENERATE AI ANALYSIS
# Threat Intelligence + Kimi + MITRE ATT&CK
# =========================================================

@router.post("/generate/{incident_id}")
def generate_ai_analysis(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):

    # -----------------------------------------------------
    # 1. Récupérer l'incident
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
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    # -----------------------------------------------------
    # 2. THREAT INTELLIGENCE
    # -----------------------------------------------------

        # -----------------------------------------------------
    # 2. THREAT INTELLIGENCE
    # -----------------------------------------------------

    incident_state = {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "source": incident.source,
            "hostname": incident.hostname,
            "source_ip": incident.source_ip,
            "destination_ip": incident.destination_ip,
        },
        "correlated_incidents": [],
    }

    try:

        threat_result = (
            threat_intelligence_agent(
                incident_state
            )
        )

        threat_intelligence = (
            threat_result.get(
                "threat_intelligence",
                [],
            )
        )

    except Exception:

        threat_intelligence = [
            {
                "status": "error",
                "error": "Threat Intelligence analysis failed",
            }
        ]

    # -----------------------------------------------------
    # 3. ANALYSE IA AVEC KIMI
    # -----------------------------------------------------

    llm = LLMService()

    try:

        result = llm.analyze_incident(
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            source=incident.source,
            threat_intelligence=threat_intelligence,
        )

    except Exception:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="LLM analysis failed",
        )

    # -----------------------------------------------------
    # 4. VALIDATION MITRE ATT&CK
    # -----------------------------------------------------

    mitre_service = MitreService()

    mitre_value = result.get(
        "mitre_technique",
        "",
    )

    mitre_id = (
        mitre_value
        .split(" ")[0]
        .strip()
    )

    if mitre_id:

        try:

            mitre_validation = (
                mitre_service.validate_technique(
                    mitre_id
                )
            )

        except Exception:

            mitre_validation = {
                "technique_id": mitre_id,
                "name": None,
                "description": None,
                "valid": False,
                "error": "MITRE technique validation failed",
            }

    else:

        mitre_validation = {
            "technique_id": None,
            "name": None,
            "description": None,
            "valid": False,
        }

    # -----------------------------------------------------
    # 5. SAUVEGARDER L'ANALYSE IA
    # -----------------------------------------------------

    analysis = AIAnalysis(
        incident_id=incident.id,

        summary=result["summary"],

        risk_level=result["risk_level"],

        explanation=result.get(
            "explanation"
        ),

        recommendation=result.get(
            "recommendation"
        ),

        mitre_technique=mitre_validation.get(
            "technique_id"
        ),

        mitre_name=mitre_validation.get(
            "name"
        ),

        mitre_valid=mitre_validation.get(
            "valid",
            False,
        ),

        model_used=settings.LLM_MODEL,
    )

    try:

        db.add(analysis)
        db.commit()
        db.refresh(analysis)

    except Exception:

        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to save AI analysis",
        )

    # -----------------------------------------------------
    # 6. RETOUR COMPLET
    # -----------------------------------------------------

    return {

        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "source": incident.source,
        },

        "threat_intelligence": (
            threat_intelligence
        ),

        "analysis": {
            "id": analysis.id,
            "incident_id": analysis.incident_id,
            "summary": analysis.summary,
            "risk_level": analysis.risk_level,
            "explanation": analysis.explanation,
            "recommendation": analysis.recommendation,
            "mitre_technique": analysis.mitre_technique,
            "mitre_name": analysis.mitre_name,
            "mitre_valid": analysis.mitre_valid,
            "model_used": analysis.model_used,
        },

        "mitre_validation": (
            mitre_validation
        ),
    }