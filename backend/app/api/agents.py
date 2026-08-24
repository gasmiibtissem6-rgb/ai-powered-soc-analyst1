from typing import Optional
from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from langgraph.types import Command
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.agents.soc_graph import soc_graph
from app.core.config import settings
from app.database.session import get_db
from app.models.ai_analysis import AIAnalysis
from app.models.incident import Incident
from app.models.report import SOCReport


router = APIRouter(
    prefix="/agents",
    tags=["SOC Agents"],
)


# =========================================================
# HUMAN DECISION SCHEMA
# =========================================================

class HumanDecision(BaseModel):
    approved: bool
    comment: Optional[str] = None


# =========================================================
# SAVE AI ANALYSIS
# =========================================================

def save_ai_analysis(
    db: Session,
    result: dict,
    thread_id: str,
) -> AIAnalysis:

    # -----------------------------------------------------
    # 1. Eviter les doublons
    # -----------------------------------------------------

    existing_analysis = (
        db.query(AIAnalysis)
        .filter(
            AIAnalysis.thread_id == thread_id
        )
        .first()
    )

    if existing_analysis:
        return existing_analysis

    # -----------------------------------------------------
    # 2. Extraire les données du workflow
    # -----------------------------------------------------

    incident = (
        result.get("incident")
        or {}
    )

    triage = (
        result.get("triage")
        or {}
    )

    investigation = (
        result.get("investigation")
        or {}
    )

    mitre_validation = (
        result.get("mitre_validation")
        or {}
    )

    human_review = (
        result.get("human_review")
        or {}
    )

    response = (
        result.get("response")
        or {}
    )

    report = (
        result.get("report")
        or {}
    )

    rag_context = (
        result.get("rag_context")
        or []
    )

    agent_trace = (
        result.get("agent_trace")
        or []
    )

    # -----------------------------------------------------
    # 3. Sources RAG
    # -----------------------------------------------------

    rag_sources = [
        item.get("source")
        for item in rag_context
        if (
            isinstance(item, dict)
            and item.get("source")
        )
    ]

    # -----------------------------------------------------
    # 4. Risk level
    # -----------------------------------------------------

    risk_level = investigation.get(
        "risk_level"
    )

    if not risk_level:
        risk_level = triage.get(
            "severity",
            "unknown",
        )

    # -----------------------------------------------------
    # 5. Human review
    # -----------------------------------------------------

    human_approval_required = (
        human_review.get(
            "required",
            False,
        )
    )

    human_approved = (
        human_review.get(
            "approved"
        )
    )

    human_review_status = (
        human_review.get(
            "status"
        )
    )

    human_comment = (
        human_review.get(
            "comment"
        )
    )

    # -----------------------------------------------------
    # 6. Response status
    # -----------------------------------------------------

    response_status = response.get(
        "status"
    )

    if not response_status:
        response_status = report.get(
            "response_status",
            "not_executed",
        )

    # -----------------------------------------------------
    # 7. Construire AIAnalysis
    # -----------------------------------------------------

    db_analysis = AIAnalysis(
        incident_id=incident.get(
            "id"
        ),

        summary=investigation.get(
            "summary",
            "No summary available",
        ),

        risk_level=risk_level,

        explanation=investigation.get(
            "explanation"
        ),

        recommendation=investigation.get(
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

        # JSONB : on sauvegarde directement la liste
        rag_sources=rag_sources,

        human_approval_required=(
            human_approval_required
        ),

        human_approved=(
            human_approved
        ),

        human_review_status=(
            human_review_status
        ),

        human_comment=(
            human_comment
        ),

        response_status=(
            response_status
        ),

        thread_id=thread_id,

        # JSONB : on sauvegarde directement la liste
        agent_trace=agent_trace,

        model_used=settings.LLM_MODEL,
    )

    # -----------------------------------------------------
    # 8. Sauvegarder
    # -----------------------------------------------------

    try:
        db.add(db_analysis)
        db.commit()
        db.refresh(db_analysis)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to save AI analysis: "
                f"{str(exc)}"
            ),
        )

    return db_analysis


# =========================================================
# SAVE SOC REPORT
# =========================================================

def save_soc_report(
    db: Session,
    result: dict,
    thread_id: str,
    ai_analysis_id: int,
) -> SOCReport:

    # -----------------------------------------------------
    # 1. Eviter les doublons
    # -----------------------------------------------------

    existing_report = (
        db.query(SOCReport)
        .filter(
            SOCReport.thread_id == thread_id
        )
        .first()
    )

    if existing_report:
        return existing_report

    # -----------------------------------------------------
    # 2. Extraire les données
    # -----------------------------------------------------

    incident = (
        result.get("incident")
        or {}
    )

    investigation = (
        result.get("investigation")
        or {}
    )

    mitre_validation = (
        result.get("mitre_validation")
        or {}
    )

    human_review = (
        result.get("human_review")
        or {}
    )

    response = (
        result.get("response")
        or {}
    )

    report = (
        result.get("report")
        or {}
    )

    rag_context = (
        result.get("rag_context")
        or []
    )

    agent_trace = (
        result.get("agent_trace")
        or []
    )

    # -----------------------------------------------------
    # 3. Sources RAG
    # -----------------------------------------------------

    rag_sources = [
        item.get("source")
        for item in rag_context
        if (
            isinstance(item, dict)
            and item.get("source")
        )
    ]

    # -----------------------------------------------------
    # 4. Construire SOCReport
    # -----------------------------------------------------

    db_report = SOCReport(
        incident_id=incident.get(
            "id"
        ),

        ai_analysis_id=ai_analysis_id,

        thread_id=thread_id,

        title=report.get(
            "title",
            incident.get(
                "title",
                "SOC Incident Report",
            ),
        ),

        summary=report.get(
            "summary",
            investigation.get(
                "summary",
                "No summary available",
            ),
        ),

        risk_level=report.get(
            "risk_level",
            investigation.get(
                "risk_level",
                "unknown",
            ),
        ),

        mitre_technique=report.get(
            "mitre_technique",
            mitre_validation.get(
                "technique_id"
            ),
        ),

        mitre_name=report.get(
            "mitre_name",
            mitre_validation.get(
                "name"
            ),
        ),

        recommendation=report.get(
            "recommendation",
            investigation.get(
                "recommendation"
            ),
        ),

        response_status=report.get(
            "response_status",
            response.get(
                "status",
                "not_executed",
            ),
        ),

        human_review_status=report.get(
            "human_review_status",
            human_review.get(
                "status"
            ),
        ),

        human_comment=report.get(
            "human_comment",
            human_review.get(
                "comment"
            ),
        ),

        # JSONB
        rag_sources=rag_sources,

        # JSONB
        agent_trace=agent_trace,
    )

    # -----------------------------------------------------
    # 5. Sauvegarder
    # -----------------------------------------------------

    try:
        db.add(db_report)
        db.commit()
        db.refresh(db_report)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to save SOC report: "
                f"{str(exc)}"
            ),
        )

    return db_report


# =========================================================
# START SOC WORKFLOW
# =========================================================

@router.post("/analyze/{incident_id}")
def analyze_incident_with_agents(
    incident_id: int,
    db: Session = Depends(get_db),
):

    # -----------------------------------------------------
    # 1. Charger l'incident
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
    # 2. Créer un thread LangGraph
    # -----------------------------------------------------

    thread_id = str(
        uuid4()
    )

    config = {
        "configurable": {
            "thread_id": thread_id,
        }
    }

    # -----------------------------------------------------
    # 3. Etat initial
    # -----------------------------------------------------

    initial_state = {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "source": incident.source,
        }
    }

    # -----------------------------------------------------
    # 4. Lancer LangGraph
    # -----------------------------------------------------

    try:
        result = soc_graph.invoke(
            initial_state,
            config=config,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "SOC agents workflow failed: "
                f"{str(exc)}"
            ),
        )

    # -----------------------------------------------------
    # 5. Vérifier interruption
    # -----------------------------------------------------

    interrupts = result.get(
        "__interrupt__",
        [],
    )

    # =====================================================
    # HUMAN APPROVAL REQUIRED
    # =====================================================

    if interrupts:

        interrupt_values = [
            item.value
            for item in interrupts
        ]

        return {
            "status": "waiting_for_human",

            "thread_id": thread_id,

            "interrupt": interrupt_values,

            "incident": result.get(
                "incident"
            ),

            "triage": result.get(
                "triage"
            ),

            "threat_intelligence": result.get(
                "threat_intelligence"
            ),

            "rag_context": result.get(
                "rag_context",
                [],
            ),

            "investigation": result.get(
                "investigation"
            ),

            "mitre_validation": result.get(
                "mitre_validation"
            ),

            "agent_trace": result.get(
                "agent_trace",
                [],
            ),
        }

    # =====================================================
    # NO HUMAN APPROVAL REQUIRED
    # =====================================================

    db_analysis = save_ai_analysis(
        db=db,
        result=result,
        thread_id=thread_id,
    )

    db_report = save_soc_report(
        db=db,
        result=result,
        thread_id=thread_id,
        ai_analysis_id=db_analysis.id,
    )

    return {
        "status": "completed",

        "thread_id": thread_id,

        "ai_analysis_id": db_analysis.id,

        "soc_report_id": db_report.id,

        "incident": result.get(
            "incident"
        ),

        "triage": result.get(
            "triage"
        ),

        "threat_intelligence": result.get(
            "threat_intelligence"
        ),

        "rag_context": result.get(
            "rag_context",
            [],
        ),

        "investigation": result.get(
            "investigation"
        ),

        "mitre_validation": result.get(
            "mitre_validation"
        ),

        "human_review": result.get(
            "human_review"
        ),

        "response": result.get(
            "response"
        ),

        "report": result.get(
            "report"
        ),

        "agent_trace": result.get(
            "agent_trace",
            [],
        ),
    }


# =========================================================
# RESUME SOC WORKFLOW
# =========================================================

@router.post("/resume/{thread_id}")
def resume_soc_workflow(
    thread_id: str,
    decision: HumanDecision,
    db: Session = Depends(get_db),
):

    config = {
        "configurable": {
            "thread_id": thread_id,
        }
    }

    # -----------------------------------------------------
    # 1. Lire le checkpoint
    # -----------------------------------------------------

    try:
        snapshot = soc_graph.get_state(
            config
        )

    except Exception as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to read workflow state: "
                f"{str(exc)}"
            ),
        )

    # -----------------------------------------------------
    # 2. Vérifier que le workflow existe
    # -----------------------------------------------------

    if not snapshot.values:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Workflow not found. "
                "The checkpoint may have been lost. "
                "Run /agents/analyze/{incident_id} again."
            ),
        )

    # -----------------------------------------------------
    # 3. Vérifier l'incident
    # -----------------------------------------------------

    incident_state = snapshot.values.get(
        "incident"
    )

    if not incident_state:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Workflow state is incomplete: "
                "incident data is missing."
            ),
        )

    # -----------------------------------------------------
    # 4. Vérifier investigation
    # -----------------------------------------------------

    investigation_state = snapshot.values.get(
        "investigation"
    )

    if not investigation_state:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Workflow state is incomplete: "
                "investigation data is missing."
            ),
        )

    # -----------------------------------------------------
    # 5. Vérifier que le workflow attend une décision
    # -----------------------------------------------------

    if not snapshot.next:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This workflow is not waiting "
                "for human approval."
            ),
        )

    # -----------------------------------------------------
    # 6. Reprendre LangGraph
    # -----------------------------------------------------

    try:
        result = soc_graph.invoke(
            Command(
                resume={
                    "approved": (
                        decision.approved
                    ),
                    "comment": (
                        decision.comment
                    ),
                }
            ),
            config=config,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "Unable to resume workflow: "
                f"{str(exc)}"
            ),
        )

    # -----------------------------------------------------
    # 7. Vérifier nouvelle interruption
    # -----------------------------------------------------

    remaining_interrupts = result.get(
        "__interrupt__",
        [],
    )

    if remaining_interrupts:

        return {
            "status": "waiting_for_human",

            "thread_id": thread_id,

            "interrupt": [
                item.value
                for item in remaining_interrupts
            ],

            "incident": result.get(
                "incident"
            ),

            "triage": result.get(
                "triage"
            ),

            "threat_intelligence": result.get(
                "threat_intelligence"
            ),

            "rag_context": result.get(
                "rag_context",
                [],
            ),

            "investigation": result.get(
                "investigation"
            ),

            "mitre_validation": result.get(
                "mitre_validation"
            ),

            "agent_trace": result.get(
                "agent_trace",
                [],
            ),
        }

    # -----------------------------------------------------
    # 8. Sauvegarder AI Analysis
    # -----------------------------------------------------

    db_analysis = save_ai_analysis(
        db=db,
        result=result,
        thread_id=thread_id,
    )

    # -----------------------------------------------------
    # 9. Sauvegarder SOC Report
    # -----------------------------------------------------

    db_report = save_soc_report(
        db=db,
        result=result,
        thread_id=thread_id,
        ai_analysis_id=db_analysis.id,
    )

    # -----------------------------------------------------
    # 10. Résultat final
    # -----------------------------------------------------

    return {
        "status": "completed",

        "thread_id": thread_id,

        "ai_analysis_id": db_analysis.id,

        "soc_report_id": db_report.id,

        "incident": result.get(
            "incident"
        ),

        "triage": result.get(
            "triage"
        ),

        "threat_intelligence": result.get(
            "threat_intelligence"
        ),

        "rag_context": result.get(
            "rag_context",
            [],
        ),

        "investigation": result.get(
            "investigation"
        ),

        "mitre_validation": result.get(
            "mitre_validation"
        ),

        "human_review": result.get(
            "human_review"
        ),

        "response": result.get(
            "response"
        ),

        "report": result.get(
            "report"
        ),

        "agent_trace": result.get(
            "agent_trace",
            [],
        ),
    }