from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.ai_analysis import (
    AIAnalysisCreate,
    AIAnalysisUpdate,
    AIAnalysisResponse,
)
from app.services.ai_analysis_service import AIAnalysisService
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.incident import Incident
from app.models.ai_analysis import AIAnalysis
from app.services.llm_service import LLMService

router = APIRouter(
    prefix="/ai-analysis",
    tags=["AI Analysis"],
)


@router.get(
    "",
    response_model=List[AIAnalysisResponse],
)
def get_analyses(
    db: Session = Depends(get_db),
):
    return AIAnalysisService.get_analyses(db)


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

@router.post("/generate/{incident_id}")
def generate_ai_analysis(
    incident_id: int,
    db: Session = Depends(get_db),
):
    # 1. Récupérer l'incident
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

    # 2. Envoyer l'incident au LLM
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

    # 3. Sauvegarder le résultat
    analysis = AIAnalysis(
        incident_id=incident.id,
        summary=result["summary"],
        risk_level=result["risk_level"],
        explanation=result["explanation"],
        recommendation=result["recommendation"],
        mitre_technique=result.get("mitre_technique"),
        model_used="qwen/qwen3.6-27b",
    )

    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    return analysis