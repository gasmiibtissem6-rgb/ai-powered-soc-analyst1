from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

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
from app.services.threat_intelligence_service import (
    ThreatIntelligenceService,
)


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
):
    return AIAnalysisService.get_analyses(db)


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
# Threat Intelligence + Qwen + MITRE ATT&CK
# =========================================================

@router.post("/generate/{incident_id}")
def generate_ai_analysis(
    incident_id: int,
    db: Session = Depends(get_db),
):

    # -----------------------------------------------------
    # 1. Récupérer l'incident depuis la base de données
    # -----------------------------------------------------

    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id)
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    # -----------------------------------------------------
    # 2. THREAT INTELLIGENCE
    # Extraire les IP et les vérifier avec AbuseIPDB
    # -----------------------------------------------------

    threat_service = ThreatIntelligenceService()

    incident_text = (
        f"{incident.title} "
        f"{incident.description}"
    )

    try:
        threat_intelligence = threat_service.analyze_text(
            incident_text
        )

    except Exception as exc:
        threat_intelligence = [
            {
                "error": f"Threat Intelligence failed: {str(exc)}"
            }
        ]

    # -----------------------------------------------------
    # 3. ANALYSE IA AVEC QWEN
    # -----------------------------------------------------

    llm = LLMService()

    try:
        result = llm.analyze_incident(
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            source=incident.source,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM analysis failed: {str(exc)}",
        )

    # -----------------------------------------------------
    # 4. VALIDATION MITRE ATT&CK
    # -----------------------------------------------------

    mitre_service = MitreService()

    mitre_value = result.get(
        "mitre_technique",
        "",
    )

    # Exemple :
    # "T1110 - Brute Force"
    # devient :
    # "T1110"

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

        except Exception as exc:
            mitre_validation = {
                "technique_id": mitre_id,
                "name": None,
                "description": None,
                "valid": False,
                "error": str(exc),
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
        explanation=result.get("explanation"),
        recommendation=result.get("recommendation"),
        mitre_technique=result.get(
            "mitre_technique"
        ),
        model_used="qwen/qwen3.6-27b",
    )

    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    # -----------------------------------------------------
    # 6. RETOURNER LE RÉSULTAT COMPLET
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

        "threat_intelligence": threat_intelligence,

        "analysis": {
            "id": analysis.id,
            "incident_id": analysis.incident_id,
            "summary": analysis.summary,
            "risk_level": analysis.risk_level,
            "explanation": analysis.explanation,
            "recommendation": analysis.recommendation,
            "mitre_technique": analysis.mitre_technique,
            "model_used": analysis.model_used,
        },

        "mitre_validation": mitre_validation,
    }